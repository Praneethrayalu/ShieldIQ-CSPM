"""Service layer helpers shared by views and the API."""
from collections import Counter, defaultdict

from ..models import Alert, Finding, Integration, ScanRun
from . import attack_graph, compliance
from .scanner import posture_score


def org_check_stats(org_id):
    merged = defaultdict(lambda: {"total": 0, "failed": 0})
    for integ in Integration.query.filter_by(org_id=org_id).all():
        for rid, st in (integ.check_stats or {}).items():
            merged[rid]["total"] += st.get("total", 0)
            merged[rid]["failed"] += st.get("failed", 0)
    return dict(merged)


def active_findings(org_id):
    return Finding.query.filter(Finding.org_id == org_id, Finding.status.in_(["open", "in_progress"])).all()


def org_compliance(org_id):
    return compliance.compute(org_check_stats(org_id), active_findings(org_id))


def coverage_notes(org_id):
    """Sources whose latest scan had partial coverage: [{"name", "note"}]. Used to make sure the
    dashboard, PDF reports and exports never present an evaluated-only score as complete."""
    notes = []
    for integ in Integration.query.filter_by(org_id=org_id).all():
        last = (ScanRun.query.filter(ScanRun.integration_id == integ.id,
                                     ScanRun.status.in_(["completed", "partial"]))
                .order_by(ScanRun.id.desc()).first())
        if last and last.status == "partial" and last.error:
            notes.append({"name": integ.name, "note": last.error})
    return notes


def dashboard_data(org_id):
    active = active_findings(org_id)
    stats = org_check_stats(org_id)
    comp = compliance.compute(stats, active)
    graph = attack_graph.build(org_id)
    runs = ScanRun.query.filter(ScanRun.org_id == org_id,
                                ScanRun.status.in_(["completed", "partial"])).order_by(ScanRun.id.desc()).limit(20).all()[::-1]
    sev = Counter(f.severity for f in active)
    by_provider = Counter(f.provider for f in active)
    all_f = Finding.query.filter_by(org_id=org_id).all()
    integrations = Integration.query.filter_by(org_id=org_id).all()
    return {
        "score": posture_score(org_id),
        "coverage": coverage_notes(org_id),
        "severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low")},
        "open": len(active),
        "resolved": sum(1 for f in all_f if f.status == "resolved"),
        "accepted": sum(1 for f in all_f if f.status == "accepted"),
        "checks": sum(s["total"] for s in stats.values()),
        "checks_failed": sum(s["failed"] for s in stats.values()),
        "by_provider": dict(by_provider.most_common()),
        "compliance": comp,
        "heatmap": compliance.heatmap(stats, active),
        "graph": graph,
        "trend": [{"label": f"#{r.id}", "time": r.finished_at.strftime("%d %b %H:%M"), "score": r.posture_score,
                   "new": r.new_findings, "resolved": r.resolved_findings,
                   "source": r.integration.name if r.integration_id and r.integration else r.source} for r in runs],
        "top": sorted(active, key=lambda f: (["critical", "high", "medium", "low"].index(f.severity), -f.id))[:6],
        "alerts": Alert.query.filter_by(org_id=org_id).order_by(Alert.id.desc()).limit(5).all(),
        "integrations": integrations,
        "last_scan": runs[-1] if runs else None,
    }
