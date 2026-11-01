"""Scan orchestration: collect -> evaluate -> sync findings -> score -> alerts -> audit."""
import hashlib
from datetime import timedelta
from collections import Counter

from sqlalchemy.exc import IntegrityError

from ..collectors import CollectorError, aws_live, demo_inventory, github_live
from ..extensions import db
from ..models import SEVERITY_WEIGHT, Finding, Integration, Organization, ScanRun, utcnow
from ..rules import evaluate, get_rule
from ..security import decrypt
from . import audit
from .alerts import raise_alert, severity_at_least


def fingerprint(integration_id, rule_id, resource_id):
    return hashlib.sha256(f"{integration_id}|{rule_id}|{resource_id}".encode()).hexdigest()


def collect_inventory(integ: Integration) -> dict:
    if integ.mode in ("demo", "snapshot", "upload"):
        if integ.snapshot is None and integ.mode == "demo":
            integ.snapshot = demo_inventory(integ.provider)
        if integ.snapshot is None:
            raise CollectorError("No inventory stored for this integration")
        return integ.snapshot
    if integ.mode == "live":
        secret = decrypt(integ.secret_enc, as_json=True) or {}
        if integ.provider == "aws":
            from flask import current_app
            cfg = integ.config or {}
            creds = {**secret, "region": cfg.get("region"), "regions": cfg.get("regions")}
            if not creds.get("access_key_id"):
                # re-checked at every scan: a profile stored before it was disallowed stops working
                prof = creds.get("profile")
                if not prof or prof not in aws_live.allowed_profiles(current_app.config):
                    raise CollectorError("This integration has no access key and its AWS CLI profile is not allowed "
                                         "on this server (SHIELDIQ_ALLOWED_AWS_PROFILES). Reconnect with a read-only "
                                         "access key.")
                return aws_live.collect(creds, session=aws_live._session(
                    creds, profiles=aws_live.allowed_profiles(current_app.config)))
            return aws_live.collect(creds)
        if integ.provider == "github":
            from flask import current_app
            token = secret.get("token") or current_app.config.get("GITHUB_TOKEN") or None
            return github_live.collect((integ.config or {}).get("target", ""), token=token)
    raise CollectorError(f"Live scanning is not available for {integ.provider}; use demo or snapshot mode")


def posture_score(org_id):
    """Severity-weighted pass rate across every check of every source (0-100)."""
    total = 0
    for integ in Integration.query.filter_by(org_id=org_id).all():
        for rid, st in (integ.check_stats or {}).items():
            rule = get_rule(rid)
            if rule:
                total += st.get("total", 0) * SEVERITY_WEIGHT[rule.severity]
    if not total:
        return None
    failed = sum(SEVERITY_WEIGHT[f.severity] for f in
                 Finding.query.filter(Finding.org_id == org_id, Finding.status.in_(["open", "in_progress"])).all())
    return max(0, round(100 * (total - failed) / total))


def scan_integration(integ: Integration, user_email="system", deliver_alerts=True, alert_on_failure=True) -> ScanRun:
    """Scan one integration. alert_on_failure=False is used for the first scan of a brand-new connection: if it
    fails, the connection is not kept, so there is nothing to raise an alert about."""
    org = db.session.get(Organization, integ.org_id)
    stale_before = utcnow() - timedelta(minutes=15)
    running = ScanRun.query.filter_by(integration_id=integ.id, status="running").all()
    if any(r.started_at and r.started_at >= stale_before for r in running):
        # Another scan of this source is still in flight; refuse instead of racing it.
        run = ScanRun(org_id=org.id, integration_id=integ.id, source=integ.provider, triggered_by=user_email,
                      status="failed", error="A scan of this source is already running; try again shortly.",
                      finished_at=utcnow())
        db.session.add(run)
        db.session.commit()
        return run
    for r in running:  # leftovers from an interrupted process; the unique index counts them too
        r.status = "failed"
        r.finished_at = utcnow()
        r.error = (r.error or "") + " [interrupted: marked failed before a new scan]"
    previous = ScanRun.query.filter(ScanRun.org_id == org.id,
                                    ScanRun.status.in_(["completed", "partial"])).order_by(ScanRun.id.desc()).first()
    run = ScanRun(org_id=org.id, integration_id=integ.id, source=integ.provider, triggered_by=user_email)
    db.session.add(run)
    try:
        db.session.flush()
    except IntegrityError:
        # Lost a true race: another transaction registered a running scan for this source first
        # (unique partial index uq_scanrun_running). Report instead of racing it.
        db.session.rollback()
        run = ScanRun(org_id=org.id, integration_id=integ.id, source=integ.provider, triggered_by=user_email,
                      status="failed", error="A scan of this source is already running; try again shortly.",
                      finished_at=utcnow())
        db.session.add(run)
        db.session.commit()
        return run
    try:
        inv = collect_inventory(integ)
    except CollectorError as exc:
        run.status, run.error, run.finished_at = "failed", str(exc), utcnow()
        integ.status, integ.last_error = "error", str(exc)
        if alert_on_failure:
            raise_alert(org, "scan_failed", f"Scan failed: {integ.name}", str(exc), "medium", deliver=deliver_alerts)
        audit.log(org.id, user_email, "scan.failed", integ.name, str(exc))
        db.session.commit()
        return run

    if integ.mode == "live":
        integ.snapshot = inv
    # Coverage: a live read can fail (access denied, throttled, service error). The collector records those
    # failures in a sanitized form and leaves the affected data unknown (never passed, never failed), so a
    # scan that evaluated fewer checks than it attempted is reported as "partial", not "completed".
    errs = []
    for e in (inv.get("_errors") or []):
        if isinstance(e, dict):
            errs.append(e)
        else:  # snapshots stored by v2.1.2 carried "service:Call: ExceptionClass" strings
            call, _, cls = str(e).partition(": ")
            errs.append({"call": call, "code": cls or None, "status": None, "kind": "error"})
    evaluations = evaluate(integ.provider, inv)
    stats, failing, evaluated, rule_errors, unknown_results = {}, {}, {}, {}, {}
    for ev in evaluations:
        if ev.error:
            rule_errors[ev.rule.id] = ev.error
            stats[ev.rule.id] = {"total": 0, "failed": 0, "error": ev.error}
            continue
        stats[ev.rule.id] = {"total": len(ev.decided), "failed": len(ev.failed)}
        if ev.unknown:  # v2.3: Unknown / Incomplete is its own state - not counted as passed, never resolves
            stats[ev.rule.id]["unknown"] = len(ev.unknown)
            unknown_results[ev.rule.id] = {res.resource_id: res.detail for res in ev.unknown}
        evaluated[ev.rule.id] = {res.resource_id for res in ev.decided}
        for res in ev.failed:
            failing[fingerprint(integ.id, ev.rule.id, res.resource_id)] = (ev.rule, res)
    integ.check_stats = stats

    now = utcnow()
    existing = {f.fingerprint: f for f in Finding.query.filter_by(org_id=org.id, integration_id=integ.id).all()}
    new, resolved = [], 0
    for fp, (rule, res) in failing.items():
        f = existing.get(fp)
        if f is None:
            f = Finding(org_id=org.id, integration_id=integ.id, source=integ.mode, rule_id=rule.id,
                        provider=rule.provider, service=rule.service, resource_id=res.resource_id, title=rule.title,
                        detail=res.detail, severity=rule.severity, fingerprint=fp, evidence=res.evidence,
                        first_seen=now, last_seen=now)
            db.session.add(f)
            new.append(f)
        else:
            f.last_seen, f.detail, f.evidence = now, res.detail, res.evidence
            if f.status == "resolved":  # regression
                f.status, f.resolved_at, f.status_note = "open", None, "Re-opened: the issue came back in a later scan"
                new.append(f)
    unverified = 0
    for fp, f in existing.items():
        if fp not in failing and f.status in ("open", "in_progress", "accepted"):
            # Only resolve what this scan actually proved fixed:
            #  - the rule crashed            -> nothing was evaluated: keep the finding, mark it unverified
            #  - the resource was evaluated  -> it passed this time: resolve
            #  - the resource was not seen   -> resolve as "no longer present" ONLY if the whole scan read every
            #                                   source completely (no read errors, no rule errors); otherwise the
            #                                   absence may just be data we could not read: keep it, unverified
            if f.rule_id in rule_errors:
                f.status_note = "Unverified: this check failed to run in the latest scan (rule error)"
                unverified += 1
                continue
            if f.resource_id in unknown_results.get(f.rule_id, {}):
                f.status_note = ("Unverified: the latest scan could not decide this check (unknown / incomplete "
                                 "data): " + str(unknown_results[f.rule_id][f.resource_id])[:300])
                unverified += 1
                continue
            if f.resource_id in evaluated.get(f.rule_id, set()):
                f.status, f.resolved_at = "resolved", now
                f.status_note = "Auto-resolved: passed in the latest scan"
                resolved += 1
                continue
            if errs or rule_errors or f.rule_id not in evaluated:
                f.status_note = "Unverified: the latest scan could not evaluate this check (partial coverage)"
                unverified += 1
                continue
            f.status, f.resolved_at = "resolved", now
            f.status_note = "Auto-resolved: resource no longer present in a complete scan"
            resolved += 1
    db.session.flush()

    sev = Counter(rule.severity for rule, _ in failing.values())
    run.checks_run = sum(s["total"] for s in stats.values())
    run.checks_failed = sum(s["failed"] for s in stats.values())
    run.new_findings, run.resolved_findings = len(new), resolved
    run.critical, run.high, run.medium, run.low = (sev.get(k, 0) for k in ("critical", "high", "medium", "low"))
    run.posture_score = posture_score(org.id)
    coverage_note = None
    if errs:
        denied = sum(1 for e in errs if e.get("kind") == "denied")
        shown = "; ".join(f"{e.get('call')} ({e.get('code')})" for e in errs[:5])
        coverage_note = (f"Partial coverage: {len(errs)} read(s) could not be completed "
                         f"({denied} access-denied): {shown}{'; ...' if len(errs) > 5 else ''}. "
                         f"Affected checks were not evaluated; results and score cover evaluated checks only.")
    if rule_errors:
        shown = "; ".join(f"{rid} ({msg[:80]})" for rid, msg in list(rule_errors.items())[:5])
        coverage_note = ((coverage_note + " ") if coverage_note else "") + (
            f"Rule errors: {len(rule_errors)} check(s) crashed and were not evaluated: {shown}"
            f"{'; ...' if len(rule_errors) > 5 else ''}. Their existing findings were left open (unverified).")
    if coverage_note:
        run.status = "partial"
        run.error = coverage_note
    else:
        run.status = "completed"
        if run.checks_run == 0:
            run.error = "No checks were evaluated: the source returned no readable resources."
    run.finished_at = utcnow()
    integ.status, integ.last_error, integ.last_scan_at = "connected", coverage_note, run.finished_at

    # alerts
    notable = [f for f in new if severity_at_least(f.severity, org.alert_min_severity)]
    for f in notable[:10]:
        raise_alert(org, "new_finding", f"{f.severity.title()}: {f.title}", f"{f.resource_id} ({integ.name})\n{f.detail}",
                    f.severity, finding_id=f.id, deliver=deliver_alerts)
    if len(notable) > 10:
        raise_alert(org, "new_finding", f"{len(notable) - 10} more new findings in {integ.name}", "", "high",
                    deliver=deliver_alerts)
    if previous and previous.posture_score is not None and run.posture_score is not None and \
            previous.posture_score - run.posture_score >= (org.alert_score_drop or 5):
        raise_alert(org, "score_drop", f"Posture score dropped {previous.posture_score} -> {run.posture_score}",
                    f"After scanning {integ.name}", "high", deliver=deliver_alerts)
    audit.log(org.id, user_email, "scan.completed", integ.name,
              f"{run.checks_run} checks, {run.checks_failed} failed, {len(new)} new, {resolved} resolved"
              + (f", {unverified} unverified" if unverified else "")
              + (f" [{run.status}]" if run.status != "completed" else ""))
    try:
        db.session.commit()
    except IntegrityError:
        # A concurrent scan of the same source won the race; discard this duplicate run cleanly.
        db.session.rollback()
        run = ScanRun(org_id=org.id, integration_id=integ.id, source=integ.provider, triggered_by=user_email,
                      status="failed", error="Another scan of this source was running; try again.",
                      finished_at=utcnow())
        db.session.add(run)
        db.session.commit()
    return run


def scan_all(org_id, user_email="system"):
    runs = []
    for integ in Integration.query.filter_by(org_id=org_id).all():
        runs.append(scan_integration(integ, user_email))
    return runs
