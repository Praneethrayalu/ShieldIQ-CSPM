"""REST API (JSON) at /api/v1.

Auth: `Authorization: Bearer siq_...` (API token from Settings) or the browser session. Browser-session
requests that change data must send the X-CSRFToken header (the UI does this automatically)."""
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request
from flask_login import current_user
from flask_wtf.csrf import validate_csrf
from wtforms.validators import ValidationError

from .collectors import CollectorError
from .collectors.iac import parse_any
from .extensions import db
from .models import FINDING_STATUSES, SEVERITIES, ApiToken, Finding, Integration, utcnow
from .rules import RULES
from .services import attack_graph, audit, copilot, dashboard_data, iam_service, org_compliance
from .services.remediation import RemediationError, apply_fix
from .services.scanner import posture_score, scan_integration

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def api_auth(action="view"):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = None
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                tok = ApiToken.query.filter_by(token_hash=ApiToken.hash(auth[7:].strip())).first()
                if not tok or not tok.user.is_active:
                    return jsonify(error="Invalid or revoked API token"), 401
                tok.last_used_at = utcnow()
                db.session.commit()
                user = tok.user
            elif current_user.is_authenticated:
                user = current_user._get_current_object()
                if request.method not in ("GET", "HEAD", "OPTIONS") and current_app.config.get("WTF_CSRF_ENABLED", True):
                    try:
                        validate_csrf(request.headers.get("X-CSRFToken"))
                    except ValidationError:
                        return jsonify(error="Missing or invalid CSRF token"), 400
            else:
                return jsonify(error="Authentication required"), 401
            if not user.can(action):
                return jsonify(error=f"Your role ({user.role}) cannot perform '{action}'"), 403
            g.api_user = user
            return fn(*a, **kw)
        return wrapper
    return deco


def _org():
    return g.api_user.org_id


@bp.get("/summary")
@api_auth()
def summary():
    d = dashboard_data(_org())
    return jsonify(posture_score=d["score"], open_findings=d["open"], severity=d["severity"], checks=d["checks"],
                   checks_failed=d["checks_failed"], attack_paths=len(d["graph"]["paths"]),
                   compliance={k: v["score"] for k, v in d["compliance"].items()}, trend=d["trend"])


@bp.get("/findings")
@api_auth()
def findings():
    q = Finding.query.filter_by(org_id=_org())
    status = request.args.get("status")
    if status in FINDING_STATUSES:
        q = q.filter_by(status=status)
    elif status != "all":
        q = q.filter(Finding.status.in_(["open", "in_progress"]))
    if request.args.get("severity") in SEVERITIES:
        q = q.filter_by(severity=request.args["severity"])
    if request.args.get("provider"):
        q = q.filter_by(provider=request.args["provider"][:20])
    try:
        limit = max(1, min(500, int(request.args.get("limit", 100))))
    except ValueError:
        limit = 100
    return jsonify(findings=[f.to_dict() for f in q.order_by(Finding.id.desc()).limit(limit).all()])


@bp.get("/findings/<int:fid>")
@api_auth()
def finding(fid):
    f = Finding.query.filter_by(id=fid, org_id=_org()).first()
    if not f:
        return jsonify(error="Not found"), 404
    return jsonify(finding=f.to_dict(), analysis=copilot.analyze_finding(f))


@bp.patch("/findings/<int:fid>")
@api_auth("triage")
def finding_update(fid):
    f = Finding.query.filter_by(id=fid, org_id=_org()).first()
    if not f:
        return jsonify(error="Not found"), 404
    data = request.get_json(silent=True) or {}
    status, note = data.get("status"), str(data.get("note") or "")[:1000]
    if status not in FINDING_STATUSES:
        return jsonify(error=f"status must be one of {FINDING_STATUSES}"), 400
    if status == "accepted" and len(note) < 5:
        return jsonify(error="Accepting a risk needs a note (justification)"), 400
    f.status, f.status_note = status, note or f.status_note
    f.resolved_at = utcnow() if status == "resolved" else None
    audit.log(_org(), g.api_user.email, "finding.status", f"finding #{f.id}", f"api: {status}")
    db.session.commit()
    return jsonify(finding=f.to_dict())


@bp.post("/findings/<int:fid>/autofix")
@api_auth("remediate")
def finding_autofix(fid):
    f = Finding.query.filter_by(id=fid, org_id=_org()).first()
    if not f:
        return jsonify(error="Not found"), 404
    try:
        rem, run = apply_fix(f, g.api_user.email)
    except RemediationError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(status=rem.status, steps=rem.steps, posture_score=run.posture_score)


@bp.get("/integrations")
@api_auth()
def integrations():
    return jsonify(integrations=[{"id": i.id, "provider": i.provider, "name": i.name, "mode": i.mode, "status": i.status,
                                  "last_scan_at": i.last_scan_at.isoformat() + "Z" if i.last_scan_at else None,
                                  "last_error": i.last_error}
                                 for i in Integration.query.filter_by(org_id=_org()).all()])


@bp.post("/integrations/<int:iid>/scan")
@api_auth("scan")
def scan(iid):
    integ = Integration.query.filter_by(id=iid, org_id=_org()).first()
    if not integ:
        return jsonify(error="Not found"), 404
    run = scan_integration(integ, g.api_user.email)
    body = {"status": run.status, "checks_run": run.checks_run, "checks_failed": run.checks_failed,
            "new_findings": run.new_findings, "resolved_findings": run.resolved_findings,
            "posture_score": run.posture_score, "error": run.error,
            "coverage": (integ.snapshot or {}).get("_coverage") if integ.mode == "live" else None}
    # partial coverage is a successful scan with fewer evaluated checks, not a failure
    return jsonify(body), (200 if run.status in ("completed", "partial") else 502)


@bp.post("/scan/iac")
@api_auth("scan")
def scan_iac():
    """Scan a Terraform/Kubernetes file without storing it: JSON {"filename": "main.tf", "content": "..."}."""
    data = request.get_json(silent=True) or {}
    content, filename = str(data.get("content") or ""), str(data.get("filename") or "main.tf")[:120]
    if not content.strip() or len(content) > 2_000_000:
        return jsonify(error="content is required (max 2 MB)"), 400
    try:
        provider, inv = parse_any(filename, content)
    except CollectorError as exc:
        return jsonify(error=str(exc)), 400
    from .rules import evaluate
    out = [{"rule_id": ev.rule.id, "severity": ev.rule.severity, "title": ev.rule.title, "resource": r.resource_id,
            "detail": r.detail} for ev in evaluate(provider, inv) for r in ev.failed]
    return jsonify(provider=provider, findings=out, passed=len(out) == 0)


@bp.post("/scan/secrets")
@api_auth("scan")
def scan_secrets():
    data = request.get_json(silent=True) or {}
    content, filename = str(data.get("content") or ""), str(data.get("filename") or "input.txt")[:120]
    if not content.strip() or len(content) > 2_000_000:
        return jsonify(error="content is required (max 2 MB)"), 400
    from .rules.code import scan_text
    hits = scan_text(filename, content)
    return jsonify(secrets=hits, passed=not hits)


@bp.get("/compliance")
@api_auth()
def compliance():
    comp = org_compliance(_org())
    return jsonify({k: {kk: v[kk] for kk in ("name", "version", "score", "checks", "failed", "controls_passed",
                                              "controls_assessed", "controls")} for k, v in comp.items()})


@bp.get("/attack-paths")
@api_auth()
def attack_paths():
    return jsonify(attack_graph.build(_org()))


# ---------------------------------------------------------------- IAM effective permissions (v2.3)
def _aws_integ(iid):
    i = Integration.query.filter_by(id=iid, org_id=_org(), provider="aws").first()
    return i if i is not None and i.snapshot else None


def _principal_json(r):
    return {k: r[k] for k in ("arn", "name", "kind", "state", "admin", "escalations", "unknown_capabilities",
                              "sources", "groups", "boundary", "identity_complete", "service_linked")}


@bp.get("/iam/<int:iid>")
@api_auth()
def iam_summary(iid):
    integ = _aws_integ(iid)
    if integ is None:
        return jsonify(error="Not found (no AWS inventory)"), 404
    a = iam_service.analysis(integ)
    return jsonify(integration_id=iid, mode=integ.mode, model_origin=a["origin"], counts=a["counts"],
                   completeness=a["completeness"], scp=a["scp"], principals=[_principal_json(r) for r in a["principals"]],
                   attack_paths=a["paths"], verified_by_scanner=integ.mode == "live")


@bp.get("/iam/<int:iid>/attack-paths")
@api_auth()
def iam_paths(iid):
    integ = _aws_integ(iid)
    if integ is None:
        return jsonify(error="Not found (no AWS inventory)"), 404
    return jsonify(attack_paths=iam_service.analysis(integ)["paths"])


@bp.post("/iam/<int:iid>/evaluate")
@api_auth()
def iam_evaluate(iid):
    integ = _aws_integ(iid)
    if integ is None:
        return jsonify(error="Not found (no AWS inventory)"), 404
    d = request.get_json(silent=True) or {}
    kind, name, action = str(d.get("kind") or "user"), str(d.get("name") or ""), str(d.get("action") or "")
    if kind not in ("user", "role") or not name or not action:
        return jsonify(error="kind (user|role), name and action are required"), 400
    ctx = d.get("context") if isinstance(d.get("context"), dict) else {}
    try:
        dec = iam_service.evaluate_request(integ, kind, name, action[:200], str(d.get("resource") or "*")[:500],
                                           ctx, complete=bool(d.get("context_complete")))
    except iam_service.IamWorkflowError as exc:
        return jsonify(error=str(exc)), 404
    return jsonify(dec.to_dict())


@bp.post("/findings/<int:fid>/iam-remediation")
@api_auth("remediate")
def iam_rem_preview(fid):
    f = Finding.query.filter_by(id=fid, org_id=_org()).first()
    if not f:
        return jsonify(error="Not found"), 404
    try:
        rem = iam_service.preview(f, g.api_user.email)
    except iam_service.IamWorkflowError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(id=rem.id, status=rem.status, preview=rem.steps, dry_run=True)


@bp.post("/findings/<int:fid>/iam-remediation/<int:rid>/<step>")
@api_auth("remediate")
def iam_rem_step(fid, rid, step):
    f = Finding.query.filter_by(id=fid, org_id=_org()).first()
    if not f:
        return jsonify(error="Not found"), 404
    d = request.get_json(silent=True) or {}
    try:
        if step == "approve":
            rem = iam_service.approve(f, rid, g.api_user.email, d.get("confirm"))
        elif step == "apply":
            rem = iam_service.apply(f, rid, g.api_user.email)
        elif step == "verify":
            rem = iam_service.verify(f, rid, g.api_user.email)
        else:
            return jsonify(error="unknown step"), 404
    except iam_service.IamWorkflowError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(id=rem.id, status=rem.status, output=rem.output, verification=(rem.steps or {}).get("verification"))


@bp.get("/rules")
@api_auth()
def rules():
    return jsonify(rules=[{"id": r.id, "provider": r.provider, "service": r.service, "title": r.title,
                           "severity": r.severity, "auto_fix": bool(r.fix)} for r in RULES.values()])


@bp.post("/copilot/chat")
@api_auth()
def copilot_chat():
    data = request.get_json(silent=True) or {}
    q = str(data.get("message") or "")[:4000]
    if not q.strip():
        return jsonify(error="message is required"), 400
    hist = data.get("history") if isinstance(data.get("history"), list) else []
    res = copilot.chat(q, _org(), org_compliance(_org()), posture_score(_org()), hist)
    return jsonify(res)


@bp.get("/search")
@api_auth()
def search():
    """Used by the command palette."""
    q = (request.args.get("q") or "").strip()[:80]
    if len(q) < 2:
        return jsonify(results=[])
    like = f"%{q}%"
    rows = Finding.query.filter(Finding.org_id == _org(), db.or_(Finding.title.ilike(like), Finding.resource_id.ilike(like),
                                                                 Finding.rule_id.ilike(like))).limit(8).all()
    return jsonify(results=[{"id": f.id, "title": f.title, "resource": f.resource_id, "severity": f.severity,
                             "status": f.status} for f in rows])
