import json
import re
from pathlib import Path

from flask import (Blueprint, Response, abort, current_app, flash, jsonify, redirect, render_template, request,
                   send_file, url_for)
from flask_login import current_user, login_required

from .collectors import PROVIDERS, CollectorError, aws_live, demo_inventory, validate_snapshot
from .collectors.iac import parse_any
from .extensions import db
from .models import (FINDING_STATUSES, ROLES, SEVERITIES, Alert, ApiToken, AuditLog, Finding, Integration,
                     Remediation, Report, ScanRun, User, utcnow)
from .rules import RULES, get_rule
from .security import PASSWORD_RULES, decrypt, encrypt, password_problems, requires, valid_email
from .services import (attack_graph, audit, copilot, coverage_notes, dashboard_data, org_check_stats,
                     org_compliance, reports)
from .services.compliance import FRAMEWORKS, control_labels
from .services.remediation import RemediationError, apply_fix, fix_script, open_github_pr
from .services import iam_service
from .services.scanner import posture_score, scan_all, scan_integration

bp = Blueprint("views", __name__)
ALLOWED_UPLOADS = (".tf", ".yaml", ".yml", ".json", ".py", ".js", ".ts", ".env", ".txt", ".cfg", ".ini", ".toml",
                   ".properties", ".sh", ".ps1", ".xml", ".java", ".go", ".rb", ".php", ".cs", ".conf")


def org_id():
    return current_user.org_id


def _integ(iid):
    i = Integration.query.filter_by(id=iid, org_id=org_id()).first()
    if not i:
        abort(404)
    return i


def _safe_local(target):
    """Only allow redirects to paths on this app (form 'next' values are user-controlled)."""
    if target and isinstance(target, str) and target.startswith("/") and not target.startswith("//"):
        return target
    return None


def _finding(fid):
    f = Finding.query.filter_by(id=fid, org_id=org_id()).first()
    if not f:
        abort(404)
    return f


@bp.app_context_processor
def inject():
    product = {"checks": len(RULES), "frameworks": len(FRAMEWORKS), "providers": len([k for k in PROVIDERS if k != "code"])}
    if current_user.is_authenticated:
        unread = Alert.query.filter_by(org_id=current_user.org_id, read=False).count()
        return {"unread_alerts": unread, "SEVERITIES": SEVERITIES, "PRODUCT": product}
    return {"PRODUCT": product}


DEMO_EMAIL = "demo@shieldiq.local"
DEMO_PASSWORD = "ShieldIQ@2026"


def _demo_mode():
    """Demo credentials / demo content are only ever shown when the operator explicitly opted in
    (SHIELDIQ_SEED_DEMO=1). A deployment that merely has a demo account in its database shows nothing."""
    return bool(current_app.config.get("SEED_DEMO"))


SAMPLE_PATH = {  # shown only when the demo workspace is absent or has no open paths (e.g. after every fix was applied)
    "id": "PATH-001", "integration": "AWS acme-production (demo)", "provider": "aws", "hops": 4, "risk_score": 91,
    "severity": "critical", "title": "Security group launch-wizard-1 \u2192 S3 bucket acme-customer-exports",
    "nodes": [
        {"type": "ingress", "label": "Internet (0.0.0.0/0)", "sensitive": False, "findings": []},
        {"type": "network", "label": "Security group launch-wizard-1", "sensitive": False,
         "findings": [{"id": 15, "severity": "critical", "title": "Security group allows SSH/RDP from the internet"}]},
        {"type": "compute", "label": "EC2 bastion-host", "sensitive": False, "findings": []},
        {"type": "identity", "label": "IAM role bastion-role", "sensitive": False, "findings": []},
        {"type": "datastore", "label": "S3 bucket acme-customer-exports", "sensitive": True, "findings": []},
    ],
    "edges": [{"label": "SSH/RDP open"}, {"label": "inbound access"}, {"label": "IMDSv1 credential theft"}, {"label": "full admin"}],
    "choke_point": {"label": "Security group launch-wizard-1",
                    "finding": {"id": 15, "severity": "critical", "title": "Security group allows SSH/RDP from the internet", "rule_id": "AWS-EC2-001"}},
}


def _landing_story(demo_user):
    """Real numbers for the scroll story: the 64 checks (and which ones fail in the demo workspace),
    open findings by severity, and the demo's framework scores. Empty-but-valid when there is no demo."""
    from .services import active_findings, org_compliance
    from .services.scanner import posture_score
    sev_order = ["critical", "high", "medium", "low"]
    failing, sev, comp, score = {}, {k: 0 for k in sev_order}, {}, None
    if demo_user:
        try:
            for f in active_findings(demo_user.org_id):
                sev[f.severity] = sev.get(f.severity, 0) + 1
                failing[f.rule_id] = f.severity
            comp = {k: v["score"] for k, v in org_compliance(demo_user.org_id).items()}
            score = posture_score(demo_user.org_id)
        except Exception:
            current_app.logger.exception("landing story")
    provider_order = [k for k in PROVIDERS]
    rules = sorted(RULES.values(), key=lambda r: (provider_order.index(r.provider) if r.provider in provider_order else 99, r.id))
    cells = [{"id": r.id, "provider": r.provider, "severity": r.severity, "fail": failing.get(r.id)} for r in rules]
    return {"cells": cells, "severity": sev, "open": sum(sev.values()), "failing_rules": len(failing),
            "compliance": comp, "score": score}


def _score_if_fixed(org_id, path):
    """The demo's real posture score now, and what the same formula gives once the findings on
    this attack path are resolved (what the hero animation's score roll shows)."""
    from .models import SEVERITY_WEIGHT
    total = 0
    for integ in Integration.query.filter_by(org_id=org_id).all():
        for rid, st in (integ.check_stats or {}).items():
            rule = get_rule(rid)
            if rule:
                total += st.get("total", 0) * SEVERITY_WEIGHT[rule.severity]
    if not total:
        return {}
    active = Finding.query.filter(Finding.org_id == org_id, Finding.status.in_(["open", "in_progress"])).all()
    failed = sum(SEVERITY_WEIGHT[f.severity] for f in active)
    on_path = {fx["id"] for n in path.get("nodes", []) for fx in (n.get("findings") or [])}
    freed = sum(SEVERITY_WEIGHT[f.severity] for f in active if f.id in on_path)
    before = max(0, round(100 * (total - failed) / total))
    after = max(0, round(100 * (total - failed + freed) / total))
    return {"score_before": before, "score_after": after, "path_findings": len(on_path)}


def _landing_artefacts(demo_user):
    """A real attack path and the finding at its choke point, read from the demo workspace."""
    from .services import attack_graph
    from .services.copilot import analyze_finding
    out = {"path": SAMPLE_PATH, "path_breaks": 3, "path_count": None, "live": False, "finding": None, "analysis": None,
           "story": _landing_story(demo_user)}
    if not demo_user:
        return out
    try:
        g = attack_graph.build(demo_user.org_id)
        paths = [p for p in g["paths"] if p.get("choke_point")]
        if paths:
            p = paths[0]
            breaks = next((c["paths"] for c in g["choke_points"] if c["node"]["label"] == p["choke_point"]["label"]), 1)
            out.update(path=p, path_breaks=breaks, path_count=len(g["paths"]), live=True)
            out.update(_score_if_fixed(demo_user.org_id, p))
            f = db.session.get(Finding, p["choke_point"]["finding"]["id"])
            if f:
                out.update(finding=f, analysis=analyze_finding(f))
    except Exception:  # the landing page must render even if the demo data is in an odd state
        current_app.logger.exception("landing artefacts")
    return out


def _landing_context():
    from .rules.code import DETECTORS
    providers = [k for k in PROVIDERS if k != "code"]
    demo_user = User.query.filter_by(email=DEMO_EMAIL).first()
    demo_ok = _demo_mode() and bool(demo_user and demo_user.is_active)
    per_provider = {}
    for r in RULES.values():
        per_provider[r.provider] = per_provider.get(r.provider, 0) + 1
    return {
        "stats": {"checks": len(RULES), "frameworks": len(FRAMEWORKS), "providers": len(providers),
                  "detectors": len(DETECTORS)},
        "frameworks": FRAMEWORKS,
        "providers": {k: PROVIDERS[k] for k in providers},
        "rules_per_provider": per_provider,
        "art": _landing_artefacts(demo_user if demo_ok else None),
        "demo": {"email": DEMO_EMAIL, "password": DEMO_PASSWORD} if demo_ok else None,
    }


@bp.route("/")
def dashboard():
    """Logged-out visitors get the public landing page; signed-in users get their dashboard."""
    if not current_user.is_authenticated:
        return render_template("landing.html", **_landing_context())
    return render_template("dashboard.html", d=dashboard_data(org_id()), FRAMEWORKS=FRAMEWORKS)


@bp.route("/welcome")
def landing():
    """The product page, reachable while signed in too."""
    return render_template("landing.html", **_landing_context())


@bp.route("/guides")
def guides():
    """Public step-by-step setup guides (one per provider) plus what to do after connecting."""
    from .guides import AFTER, GUIDES
    providers = {k: PROVIDERS[k] for k in GUIDES}
    return render_template("guides.html", guides=GUIDES, after=AFTER, providers=providers,
                           demo={"email": DEMO_EMAIL, "password": DEMO_PASSWORD}
                           if _demo_mode() and (lambda u: bool(u and u.is_active))(
                               User.query.filter_by(email=DEMO_EMAIL).first()) else None)


@bp.route("/dashboard")
@login_required
def dashboard_alias():
    return redirect(url_for("views.dashboard"))


# ---------------------------------------------------------------- findings
@bp.route("/findings")
@login_required
def findings():
    q = Finding.query.filter_by(org_id=org_id())
    a = request.args
    status = a.get("status", "active")
    if status == "active":
        q = q.filter(Finding.status.in_(["open", "in_progress"]))
    elif status in FINDING_STATUSES:
        q = q.filter_by(status=status)
    if a.get("severity") in SEVERITIES:
        q = q.filter_by(severity=a["severity"])
    if a.get("provider") in PROVIDERS:
        q = q.filter_by(provider=a["provider"])
    if a.get("rule"):
        q = q.filter(Finding.rule_id.in_([r for r in a["rule"].split(",")[:60] if r in RULES]))
    if a.get("integration", "").isdigit():
        q = q.filter_by(integration_id=int(a["integration"]))
    if a.get("q"):
        like = f"%{a['q'][:100]}%"
        q = q.filter(db.or_(Finding.title.ilike(like), Finding.resource_id.ilike(like), Finding.rule_id.ilike(like),
                            Finding.detail.ilike(like)))
    rows = q.all()
    order = {s: i for i, s in enumerate(SEVERITIES)}
    rows.sort(key=lambda f: (order[f.severity], -f.id))
    return render_template("findings.html", findings=rows, args=a, status=status,
                           integrations=Integration.query.filter_by(org_id=org_id()).all(), STATUSES=FINDING_STATUSES)


@bp.route("/findings/<int:fid>")
@login_required
def finding_detail(fid):
    f = _finding(fid)
    analysis = copilot.analyze_finding(f)
    rems = Remediation.query.filter_by(finding_id=f.id).order_by(Remediation.id.desc()).all()
    iam_rems = [r for r in rems if r.mode == "iam_preview"]
    return render_template("finding_detail.html", f=f, a=analysis, rule=get_rule(f.rule_id),
                           rems=[r for r in rems if r.mode != "iam_preview"], iam_rems=iam_rems,
                           iam_capable=f.rule_id in iam_service.IAM_RULES, STATUSES=FINDING_STATUSES)


@bp.route("/findings/<int:fid>/status", methods=["POST"])
@login_required
@requires("triage")
def finding_status(fid):
    f = _finding(fid)
    status = request.form.get("status")
    note = (request.form.get("note") or "").strip()[:1000]
    if status not in FINDING_STATUSES:
        flash("Unknown status.", "error")
    elif status == "accepted" and len(note) < 5:
        flash("Accepting a risk needs a short justification.", "error")
    else:
        old = f.status
        f.status, f.status_note = status, note or f.status_note
        f.resolved_at = utcnow() if status == "resolved" else None
        audit.log(org_id(), current_user.email, "finding.status", f"finding #{f.id}", f"{old} -> {status}: {note}")
        db.session.commit()
        flash(f"Finding #{f.id} marked {status.replace('_', ' ')}.", "success")
    return redirect(_safe_local(request.form.get("next")) or url_for("views.finding_detail", fid=fid))


@bp.route("/findings/bulk", methods=["POST"])
@login_required
@requires("triage")
def findings_bulk():
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    status = request.form.get("status")
    if status not in ("open", "in_progress", "resolved") or not ids:
        flash("Select findings and a status.", "error")
        return redirect(url_for("views.findings"))
    rows = Finding.query.filter(Finding.org_id == org_id(), Finding.id.in_(ids)).all()
    for f in rows:
        f.status = status
        f.resolved_at = utcnow() if status == "resolved" else None
    audit.log(org_id(), current_user.email, "finding.bulk_status", f"{len(rows)} findings", status)
    db.session.commit()
    flash(f"{len(rows)} findings marked {status.replace('_', ' ')}.", "success")
    return redirect(url_for("views.findings"))


@bp.route("/findings/<int:fid>/autofix", methods=["POST"])
@login_required
@requires("remediate")
def finding_autofix(fid):
    f = _finding(fid)
    try:
        rem, run = apply_fix(f, current_user.email)
        flash(("Fixed and verified by re-scan. " if rem.status == "verified" else "Fix applied but the re-scan still fails. ")
              + f"Posture score is now {run.posture_score}.", "success" if rem.status == "verified" else "error")
    except RemediationError as exc:
        flash(str(exc), "error")
    return redirect(url_for("views.finding_detail", fid=fid))


@bp.route("/findings/<int:fid>/script.<kind>")
@login_required
def finding_script(fid, kind):
    f = _finding(fid)
    sh, tf = fix_script(f)
    if kind in ("iac", "tf") and tf:
        ext = get_rule(f.rule_id).iac_kind
        return Response(tf, mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename=shieldiq-fix-{f.id}.{ext}"})
    if kind == "sh":
        return Response(sh, mimetype="text/x-shellscript",
                        headers={"Content-Disposition": f"attachment; filename=shieldiq-fix-{f.id}.sh"})
    abort(404)


@bp.route("/findings/<int:fid>/pr", methods=["POST"])
@login_required
@requires("remediate")
def finding_pr(fid):
    f = _finding(fid)
    try:
        rem = open_github_pr(f, current_user.org, current_user.email)
        flash(f"Pull request opened: {rem.pr_url}", "success")
    except RemediationError as exc:
        flash(str(exc), "error")
    return redirect(url_for("views.finding_detail", fid=fid))


# ---------------------------------------------------------------- compliance & attack paths
@bp.route("/compliance")
@login_required
def compliance():
    comp = org_compliance(org_id())
    fw = request.args.get("fw", "SOC2")
    if fw not in comp:
        fw = "SOC2"
    rules_by_id = {rid: RULES[rid] for rid in org_check_stats(org_id())}
    return render_template("compliance.html", comp=comp, fw=fw, rules=rules_by_id)


@bp.route("/attack-paths")
@login_required
def attack_paths():
    return render_template("attack_paths.html", g=attack_graph.build(org_id()), iam_paths=_org_iam_paths())


def _org_iam_paths():
    """v2.3: evidence-based IAM privilege-escalation paths for every AWS integration."""
    out = []
    for integ in Integration.query.filter_by(org_id=org_id(), provider="aws").all():
        if not integ.snapshot:
            continue
        try:
            for p in iam_service.analysis(integ)["paths"]:
                out.append(dict(p, integration=integ.name, integration_id=integ.id))
        except Exception as exc:  # analysis problems must never break the page
            current_app.logger.warning("IAM path analysis failed for integration %s: %s", integ.id, exc)
    return out


# ---------------------------------------------------------------- IAM effective permissions (v2.3)
def _aws_integrations():
    return Integration.query.filter_by(org_id=org_id(), provider="aws").order_by(Integration.id).all()


@bp.route("/iam")
@login_required
def iam_page():
    items = [i for i in _aws_integrations() if i.snapshot]
    if not items:
        return render_template("iam.html", items=[], a=None, integ=None)
    sel = request.args.get("integration", type=int)
    integ = next((i for i in items if i.id == sel), items[0])
    return render_template("iam.html", items=items, integ=integ, a=iam_service.analysis(integ))


@bp.route("/iam/<int:iid>/principal/<kind>/<path:name>")
@login_required
def iam_principal(iid, kind, name):
    integ = _integ(iid)
    if integ.provider != "aws" or kind not in ("user", "role") or not integ.snapshot:
        abort(404)
    a = iam_service.analysis(integ)
    p = a["model"].get(kind, name)
    if p is None:
        abort(404)
    report = next(r for r in a["principals"] if r["arn"] == p.arn)
    decision = None
    action = (request.args.get("action") or "").strip()
    if action:
        ctx = {}
        for line in (request.args.get("context") or "").splitlines():
            if "=" in line:
                k, _, val = line.partition("=")
                if k.strip():
                    ctx[k.strip()] = val.strip()
        try:
            decision = iam_service.evaluate_request(integ, kind, name, action[:200],
                                                    (request.args.get("resource") or "*")[:500], ctx,
                                                    complete=request.args.get("complete") == "1").to_dict()
        except iam_service.IamWorkflowError as exc:
            flash(str(exc), "error")
    paths = [x for x in a["paths"] if x["start"]["arn"] == p.arn]
    return render_template("iam_principal.html", integ=integ, p=p, r=report, result=decision, paths=paths,
                           scp=a["scp"], args=request.args)


@bp.route("/findings/<int:fid>/iam-remediation/preview", methods=["POST"])
@login_required
@requires("remediate")
def iam_remediation_preview(fid):
    f = _finding(fid)
    try:
        iam_service.preview(f, current_user.email)
        flash("Remediation preview created (dry run - nothing was changed).", "success")
    except iam_service.IamWorkflowError as exc:
        flash(str(exc), "error")
    return redirect(url_for("views.finding_detail", fid=fid) + "#iam-remediation")


@bp.route("/findings/<int:fid>/iam-remediation/<int:rid>/<step>", methods=["POST"])
@login_required
@requires("remediate")
def iam_remediation_step(fid, rid, step):
    f = _finding(fid)
    try:
        if step == "approve":
            iam_service.approve(f, rid, current_user.email, request.form.get("confirm"))
            flash("Change approved. Nothing has been applied yet.", "success")
        elif step == "apply":
            rem = iam_service.apply(f, rid, current_user.email)
            flash(rem.output, "success" if rem.status == "verified" else "error")
        elif step == "verify":
            rem = iam_service.verify(f, rid, current_user.email)
            flash(rem.output, "success" if rem.status == "verified" else "error")
        else:
            abort(404)
    except iam_service.IamWorkflowError as exc:
        flash(str(exc), "error")
    return redirect(url_for("views.finding_detail", fid=fid) + "#iam-remediation")


# ---------------------------------------------------------------- integrations
@bp.route("/integrations")
@login_required
def integrations():
    items = Integration.query.filter_by(org_id=org_id()).order_by(Integration.id).all()
    counts = {i.id: Finding.query.filter(Finding.integration_id == i.id, Finding.status.in_(["open", "in_progress"])).count()
              for i in items}
    template_urls = {k: url_for("views.snapshot_template", provider=k) for k in PROVIDERS if k != "code"}
    return render_template("integrations.html", items=items, counts=counts, template_urls=template_urls,
                           aws_profiles=sorted(aws_live.allowed_profiles(current_app.config)))


@bp.route("/integrations/new", methods=["POST"])
@login_required
@requires("integrate")
def integration_new():
    f = request.form
    provider, mode = f.get("provider"), f.get("mode", "demo")
    name = (f.get("name") or "").strip()[:120]
    if provider not in PROVIDERS or provider == "code":
        flash("Choose a provider.", "error")
        return redirect(url_for("views.integrations"))
    integ = Integration(org_id=org_id(), provider=provider, name=name or f"{PROVIDERS[provider]['short']} ({mode})", mode=mode,
                        config={})
    try:
        if mode == "demo":
            integ.snapshot = demo_inventory(provider)
        elif mode == "snapshot":
            up = request.files.get("snapshot")
            if not up or not up.filename:
                raise CollectorError("Choose a JSON snapshot file")
            try:
                data = json.loads(up.read().decode("utf-8", "replace"))
            except ValueError as exc:
                raise CollectorError(f"Invalid JSON: {exc}")
            integ.snapshot = validate_snapshot(provider, data)
        elif mode == "live" and provider == "aws":
            ak, sk = (f.get("access_key_id") or "").strip(), (f.get("secret_access_key") or "").strip()
            profile = (f.get("profile") or "").strip()
            allowed = aws_live.allowed_profiles(current_app.config)
            if ak and sk:
                profile = ""  # an explicit key always wins; never store a profile beside it
            elif profile:
                # Only profiles the operator explicitly allowed: otherwise any tenant could scan with the
                # server's own ~/.aws credentials (or probe which profiles exist).
                if profile not in allowed:
                    raise CollectorError("That AWS CLI profile is not allowed on this server. Use an access key for a "
                                         "read-only SecurityAudit user.")
            else:
                raise CollectorError("Enter an access key + secret (read-only SecurityAudit user)"
                                     + (" or one of the allowed AWS CLI profiles" if allowed else ""))
            integ.secret_enc = encrypt({"access_key_id": ak, "secret_access_key": sk, "profile": profile})
            region = (f.get("region") or "us-east-1").strip()[:30]
            regions = [r.strip() for r in (f.get("regions") or "").split(",") if r.strip()]
            bad = [r for r in [region] + regions if not re.fullmatch(r"^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d{1,2}$", r)]
            if bad:
                raise CollectorError(f"Not an AWS region name: {bad[0][:30]}")
            integ.config = {"region": region}
            if regions:
                integ.config["regions"] = regions[:40]  # blank = every enabled region (DescribeRegions)
        elif mode == "live" and provider == "github":
            target = (f.get("target") or "").strip()
            if not target:
                raise CollectorError("Enter a GitHub owner or owner/repo")
            integ.config = {"target": target[:200]}
            if f.get("token"):
                integ.secret_enc = encrypt({"token": f.get("token").strip()})
        else:
            raise CollectorError(f"Live mode is not available for {PROVIDERS[provider]['label']}; use demo or snapshot")
    except CollectorError as exc:
        flash(str(exc), "error")
        return redirect(url_for("views.integrations"))
    db.session.add(integ)
    audit.log(org_id(), current_user.email, "integration.create", integ.name, f"{provider}/{mode}")
    db.session.commit()
    run = scan_integration(integ, current_user.email, alert_on_failure=False)
    if run.status in ("completed", "partial"):
        if run.status == "partial":
            flash(f"Connected {integ.name} with partial coverage: {run.checks_run} checks evaluated, "
                  f"{run.checks_failed} failing. {run.error}", "info")
        else:
            flash(f"Connected {integ.name}: {run.checks_run} checks, {run.checks_failed} failing.", "success")
    else:
        # don't keep a source we could not read; the failed run stays in scan history for the record
        ScanRun.query.filter_by(integration_id=integ.id).update({"integration_id": None})
        audit.log(org_id(), current_user.email, "integration.delete", integ.name, "first scan failed")
        db.session.delete(integ)
        db.session.commit()
        flash(f"Could not connect {integ.name}: {run.error}. Nothing was saved; check the details and try again.", "error")
    return redirect(url_for("views.integrations"))


@bp.route("/integrations/<int:iid>/scan", methods=["POST"])
@login_required
@requires("scan")
def integration_scan(iid):
    integ = _integ(iid)
    run = scan_integration(integ, current_user.email)
    if run.status in ("completed", "partial"):
        msg = (f"Scanned {integ.name}: {run.checks_run} checks, {run.new_findings} new, "
               f"{run.resolved_findings} resolved. Posture score {run.posture_score}.")
        if run.status == "partial":
            flash(f"{msg} {run.error}", "info")
        else:
            flash(msg, "success")
    else:
        flash(f"Scan failed: {run.error}", "error")
    return redirect(_safe_local(request.form.get("next")) or url_for("views.integrations"))


@bp.route("/scan-all", methods=["POST"])
@login_required
@requires("scan")
def scan_everything():
    runs = scan_all(org_id(), current_user.email)
    ok = [r for r in runs if r.status in ("completed", "partial")]
    partial = [r for r in runs if r.status == "partial"]
    flash(f"Scanned {len(ok)}/{len(runs)} sources"
          f"{' (' + str(len(partial)) + ' with partial coverage)' if partial else ''}. "
          f"Posture score {posture_score(org_id())}.",
          "success" if len(ok) == len(runs) and not partial else ("info" if len(ok) == len(runs) else "error"))
    return redirect(_safe_local(request.form.get("next")) or url_for("views.dashboard"))


@bp.route("/integrations/<int:iid>/delete", methods=["POST"])
@login_required
@requires("integrate")
def integration_delete(iid):
    integ = _integ(iid)
    fids = [f.id for f in Finding.query.filter_by(integration_id=integ.id).all()]
    if fids:
        Remediation.query.filter(Remediation.finding_id.in_(fids)).delete(synchronize_session=False)
        Alert.query.filter(Alert.finding_id.in_(fids)).update({"finding_id": None}, synchronize_session=False)
    Finding.query.filter_by(integration_id=integ.id).delete()
    ScanRun.query.filter_by(integration_id=integ.id).update({"integration_id": None})
    audit.log(org_id(), current_user.email, "integration.delete", integ.name)
    db.session.delete(integ)
    db.session.commit()
    flash(f"Removed {integ.name} and its findings.", "success")
    return redirect(url_for("views.integrations"))


@bp.route("/integrations/<int:iid>/inventory.json")
@login_required
def integration_inventory(iid):
    integ = _integ(iid)
    return Response(json.dumps(integ.snapshot or {}, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=shieldiq-{integ.provider}-{integ.id}.json"})


@bp.route("/integrations/template/<provider>.json")
@login_required
def snapshot_template(provider):
    if provider not in PROVIDERS or provider == "code":
        abort(404)
    return Response(json.dumps(demo_inventory(provider), indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=shieldiq-{provider}-snapshot-template.json"})


# ---------------------------------------------------------------- scanners (uploads)
@bp.route("/scanners", methods=["GET", "POST"])
@login_required
def scanners():
    result = None
    if request.method == "POST":
        if not current_user.can("scan"):
            abort(403)
        kind = request.form.get("kind")
        up = request.files.get("file")
        text = request.form.get("content") or ""
        filename = (request.form.get("filename") or "").strip()[:120]
        if up and up.filename:
            filename = Path(up.filename).name[:120]
            text = up.read().decode("utf-8-sig", "replace")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        if not text.strip():
            flash("Upload a file or paste some content.", "error")
            return redirect(url_for("views.scanners"))
        if filename and not filename.lower().endswith(ALLOWED_UPLOADS):
            flash("Unsupported file type.", "error")
            return redirect(url_for("views.scanners"))
        try:
            if kind == "secrets":
                filename = filename or "pasted.txt"
                provider, inv = "code", {"files": [{"path": filename, "content": text}]}
            elif kind == "iac":
                filename = filename or ("pasted.tf" if "resource" in text and "{" in text else "pasted.yaml")
                provider, inv = parse_any(filename, text)
            else:
                raise CollectorError("Choose a scanner")
        except CollectorError as exc:
            flash(str(exc), "error")
            return redirect(url_for("views.scanners"))
        label = {"aws": "Terraform", "kubernetes": "Manifests", "code": "Code"}[provider]
        integ = Integration(org_id=org_id(), provider=provider, name=f"{label}: {filename}", mode="upload",
                            snapshot=inv, config={"filename": filename})
        db.session.add(integ)
        audit.log(org_id(), current_user.email, "scanner.upload", filename, provider)
        db.session.commit()
        run = scan_integration(integ, current_user.email)
        result = {"integ": integ, "run": run,
                  "findings": Finding.query.filter(Finding.integration_id == integ.id,
                                                   Finding.status.in_(["open", "in_progress"])).all()}
    uploads = Integration.query.filter_by(org_id=org_id(), mode="upload").order_by(Integration.id.desc()).all()
    return render_template("scanners.html", result=result, uploads=uploads)


@bp.route("/scanners/sample/<name>")
@login_required
def scanner_sample(name):
    from .collectors import SAMPLE_DIR
    from .seed import sample_leaky_code
    if name == "settings.py":
        return Response(sample_leaky_code(), mimetype="text/plain",
                        headers={"Content-Disposition": "attachment; filename=settings.py"})
    if name not in ("main.tf", "deployment.yaml"):
        abort(404)
    return send_file(SAMPLE_DIR / "uploads" / name, as_attachment=True)


# ---------------------------------------------------------------- copilot
@bp.route("/copilot")
@login_required
def copilot_page():
    return render_template("copilot.html", llm=bool(current_app.config.get("LLM_API_KEY")))


# ---------------------------------------------------------------- reports
@bp.route("/reports")
@login_required
def reports_page():
    items = Report.query.filter_by(org_id=org_id()).order_by(Report.id.desc()).all()
    return render_template("reports.html", items=items, FRAMEWORKS=FRAMEWORKS)


@bp.route("/reports/generate", methods=["POST"])
@login_required
@requires("report")
def report_generate():
    fw = request.form.get("framework") or None
    if fw and fw not in FRAMEWORKS:
        fw = None
    comp = org_compliance(org_id())
    all_f = Finding.query.filter_by(org_id=org_id()).all()
    score = posture_score(org_id())
    rep = Report(org_id=org_id(), title=f"{FRAMEWORKS[fw]['name'] + ' ' if fw else ''}Security posture report",
                 framework=fw, created_by=current_user.email, filename="pending", posture_score=score,
                 finding_count=sum(1 for f in all_f if f.status in ("open", "in_progress")))
    db.session.add(rep)
    db.session.flush()
    fname = f"shieldiq-report-{org_id()}-{rep.id}.pdf"
    reports.build_pdf(Path(current_app.config["REPORTS_DIR"]) / fname, current_user.org.name, score, all_f, comp,
                      attack_graph.build(org_id()), fw, current_user.full_name,
                      coverage=coverage_notes(org_id()))
    rep.filename = fname
    audit.log(org_id(), current_user.email, "report.generate", rep.title)
    db.session.commit()
    flash("Report generated.", "success")
    return redirect(url_for("views.reports_page"))


@bp.route("/reports/<int:rid>/download")
@login_required
def report_download(rid):
    rep = Report.query.filter_by(id=rid, org_id=org_id()).first_or_404()
    path = Path(current_app.config["REPORTS_DIR"]) / rep.filename
    if not path.exists():
        abort(404)
    return send_file(path, as_attachment=request.args.get("inline") != "1", download_name=rep.filename,
                     mimetype="application/pdf")


@bp.route("/reports/<int:rid>/delete", methods=["POST"])
@login_required
@requires("report")
def report_delete(rid):
    rep = Report.query.filter_by(id=rid, org_id=org_id()).first_or_404()
    path = Path(current_app.config["REPORTS_DIR"]) / rep.filename
    if path.exists():
        path.unlink()
    db.session.delete(rep)
    audit.log(org_id(), current_user.email, "report.delete", rep.title)
    db.session.commit()
    flash("Report deleted.", "success")
    return redirect(url_for("views.reports_page"))


@bp.route("/export/findings.<fmt>")
@login_required
def export_findings(fmt):
    rows = Finding.query.filter_by(org_id=org_id()).order_by(Finding.id).all()
    if fmt == "csv":
        return Response(reports.findings_csv(rows), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=shieldiq-findings.csv"})
    if fmt == "json":
        return Response(reports.findings_json(rows, posture_score(org_id()), org_compliance(org_id()),
                                              attack_graph.build(org_id()),
                                              coverage=coverage_notes(org_id())), mimetype="application/json",
                        headers={"Content-Disposition": "attachment; filename=shieldiq-findings.json"})
    abort(404)


# ---------------------------------------------------------------- alerts & audit
@bp.route("/alerts")
@login_required
def alerts():
    kind = request.args.get("kind")
    q = Alert.query.filter_by(org_id=org_id())
    if kind:
        q = q.filter_by(kind=kind)
    return render_template("alerts.html", items=q.order_by(Alert.id.desc()).limit(200).all(), kind=kind)


@bp.route("/alerts/read", methods=["POST"])
@login_required
def alerts_read():
    aid = request.form.get("id")
    q = Alert.query.filter_by(org_id=org_id())
    if aid and aid.isdigit():
        q = q.filter_by(id=int(aid))
    q.update({"read": True})
    db.session.commit()
    return redirect(_safe_local(request.form.get("next")) or url_for("views.alerts"))


@bp.route("/audit")
@login_required
@requires("admin")
def audit_log():
    q = AuditLog.query.filter_by(org_id=org_id())
    if request.args.get("q"):
        like = f"%{request.args['q'][:100]}%"
        q = q.filter(db.or_(AuditLog.action.ilike(like), AuditLog.user_email.ilike(like), AuditLog.target.ilike(like)))
    return render_template("audit.html", items=q.order_by(AuditLog.id.desc()).limit(300).all())


# ---------------------------------------------------------------- settings & users
@bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    new_token = None
    org = current_user.org
    if request.method == "POST":
        action = request.form.get("action")
        f = request.form
        if action == "profile":
            name = (f.get("full_name") or "").strip()[:120]
            if len(name) < 2:
                flash("Enter your name.", "error")
            else:
                current_user.full_name = name
                current_user.theme = f.get("theme") if f.get("theme") in ("dark", "light") else current_user.theme
                flash("Profile saved.", "success")
        elif action == "password":
            if not current_user.check_password(f.get("current") or ""):
                flash("Current password is wrong.", "error")
            elif password_problems(f.get("new") or ""):
                flash("New password needs " + ", ".join(password_problems(f.get("new"))) + ".", "error")
            elif f.get("new") != f.get("confirm"):
                flash("Passwords do not match.", "error")
            else:
                current_user.set_password(f["new"])
                audit.log(org.id, current_user.email, "user.password_change", current_user.email)
                flash("Password changed.", "success")
        elif action == "token":
            name = (f.get("token_name") or "API token").strip()[:80]
            tok, new_token = ApiToken.issue(current_user, name)
            audit.log(org.id, current_user.email, "api_token.create", name)
            flash("Token created. Copy it now; it will not be shown again.", "success")
        elif action == "revoke":
            tok = ApiToken.query.filter_by(id=int(f.get("token_id", 0) or 0), user_id=current_user.id).first()
            if tok:
                db.session.delete(tok)
                audit.log(org.id, current_user.email, "api_token.revoke", tok.name)
                flash("Token revoked.", "success")
        elif action == "org":
            if not current_user.can("admin"):
                abort(403)
            name = (f.get("org_name") or "").strip()[:120]
            if len(name) >= 2:
                org.name = name
            if f.get("alert_min_severity") in SEVERITIES:
                org.alert_min_severity = f["alert_min_severity"]
            try:
                org.alert_score_drop = max(1, min(50, int(f.get("alert_score_drop") or 5)))
            except ValueError:
                pass
            email = (f.get("alert_email") or "").strip()
            if email and not valid_email(email):
                flash("Alert email is not valid.", "error")
            else:
                org.alert_email = email or None
            hook = (f.get("slack_webhook") or "").strip()
            if hook:
                if not hook.startswith("https://hooks.slack.com/"):
                    flash("Slack webhook must start with https://hooks.slack.com/", "error")
                else:
                    org.slack_webhook_enc = encrypt(hook)
            if f.get("clear_webhook"):
                org.slack_webhook_enc = None
            repo = (f.get("github_repo") or "").strip()
            org.github_repo = repo[:200] or None
            if f.get("github_token"):
                org.github_token_enc = encrypt(f["github_token"].strip())
            if f.get("clear_github_token"):
                org.github_token_enc = None
            audit.log(org.id, current_user.email, "org.settings", org.name)
            flash("Organization settings saved.", "success")
        db.session.commit()
    tokens = ApiToken.query.filter_by(user_id=current_user.id).all()
    return render_template("settings.html", org=org, tokens=tokens, new_token=new_token, rules=PASSWORD_RULES,
                           has_webhook=bool(org.slack_webhook_enc), has_gh_token=bool(org.github_token_enc),
                           llm=bool(current_app.config.get("LLM_API_KEY")))


@bp.route("/settings/theme", methods=["POST"])
@login_required
def set_theme():
    """Remember the theme picked with the top-bar toggle (CSRF-protected like every form)."""
    theme = request.form.get("theme") or (request.get_json(silent=True) or {}).get("theme")
    if theme not in ("dark", "light"):
        return jsonify(error="theme must be dark or light"), 400
    current_user.theme = theme
    db.session.commit()
    return jsonify(ok=True, theme=theme)


@bp.route("/users", methods=["GET", "POST"])
@login_required
@requires("admin")
def users():
    if request.method == "POST":
        f = request.form
        action = f.get("action")
        if action == "create":
            email = (f.get("email") or "").strip().lower()
            name = (f.get("full_name") or "").strip()[:120]
            role = f.get("role") if f.get("role") in ROLES else "viewer"
            pw = f.get("password") or ""
            if len(email) > 255 or not valid_email(email) or len(name) < 2:
                flash("Enter a name and a valid email (255 characters or fewer).", "error")
            elif User.query.filter_by(email=email).first():
                flash("That email is already registered.", "error")
            elif password_problems(pw):
                flash("Temporary password needs " + ", ".join(password_problems(pw)) + ".", "error")
            else:
                u = User(org_id=org_id(), email=email, full_name=name, role=role)
                u.set_password(pw)
                db.session.add(u)
                audit.log(org_id(), current_user.email, "user.create", email, role)
                flash(f"Added {email} as {role}.", "success")
        elif action in ("role", "toggle"):
            u = User.query.filter_by(id=int(f.get("user_id", 0) or 0), org_id=org_id()).first_or_404()
            if u.id == current_user.id:
                flash("You cannot change your own role or disable yourself.", "error")
            elif action == "role" and f.get("role") in ROLES:
                u.role = f["role"]
                audit.log(org_id(), current_user.email, "user.role", u.email, u.role)
                flash(f"{u.email} is now {u.role}.", "success")
            elif action == "toggle":
                u.is_active_user = not u.is_active_user
                audit.log(org_id(), current_user.email, "user.toggle", u.email, "active" if u.is_active_user else "disabled")
                flash(f"{u.email} {'enabled' if u.is_active_user else 'disabled'}.", "success")
        db.session.commit()
        return redirect(url_for("views.users"))
    return render_template("users.html", items=User.query.filter_by(org_id=org_id()).order_by(User.id).all(),
                           ROLES=ROLES, rules=PASSWORD_RULES)


@bp.route("/rules")
@login_required
def rules_catalog():
    prov = request.args.get("provider")
    if prov not in PROVIDERS:
        prov = None
    items = [r for r in RULES.values() if not prov or r.provider == prov]
    return render_template("rules.html", items=items, selected=prov, control_labels=control_labels)


@bp.route("/api-docs")
@login_required
def api_docs():
    return render_template("api_docs.html")
