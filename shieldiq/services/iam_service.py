"""IAM analysis + remediation workflow for the UI, API and Copilot (v2.3).

Read side: `analysis(integ)` builds the authorization model from the integration's stored inventory and returns
principals (with permission sources and Secure / Finding / Unknown state), evidence-based attack paths and the
collection-completeness indicator.

Remediation workflow (one `Remediation` row per preview, mode "iam_preview"):
  preview  -> status "preview"   (proposed change, before/after diff, impact, validation; nothing applied)
  approve  -> status "approved"  (explicit: an analyst/admin types the principal name; recorded in the audit log)
  apply    -> stored inventories (demo / snapshot / upload) only: write the proposal, re-scan, then status
              "verified" (finding resolved) or "not_resolved". Live AWS: refused - ShieldIQ holds read-only
              credentials; the approved policy + CLI instructions are handed to the operator.
  verify   -> re-scan the integration and report resolved / not resolved (used after a manual live change).
"""
import copy

from ..extensions import db
from ..iam.analysis import Analyzer
from ..iam.evaluator import evaluate
from ..iam.model import build_model
from ..iam.policy import RequestContext
from ..iam.remediation import apply_to_inventory, propose
from ..models import Remediation, utcnow
from . import audit

IAM_RULES = ("AWS-IAM-005", "AWS-IAM-007")


class IamWorkflowError(Exception):
    pass


def analysis(integ, context=None):
    inv = integ.snapshot or {}
    model = build_model(inv)
    an = Analyzer(model, context)
    principals = [an.principal_report(p) for p in model.principals.values()]
    paths = an.paths()
    buckets = [b.get("name") for b in inv.get("s3_buckets") or [] if b.get("name")]
    counts = {"Secure": 0, "Finding": 0, "Unknown": 0}
    for p in principals:
        counts[p["state"]] = counts.get(p["state"], 0) + 1
    return {"integration": integ, "model": model, "analyzer": an, "principals": principals, "paths": paths,
            "data_access": an.data_access(buckets[:20]), "counts": counts,
            "completeness": completeness_rows(inv, model), "scp": model.scp, "origin": model.origin}


def completeness_rows(inv, model=None):
    rows = list(inv.get("_sources") or [])
    if rows:
        return rows
    model = model or build_model(inv)
    return [{"source": k, "label": k.replace("_", " "), "status": v.get("status"), "detail": v.get("detail"),
             "errors": [e for e in model.errors if k in str(e.get("api", ""))][:10]}
            for k, v in (model.sources or {}).items()]


def find_principal(model, resource_id):
    p = model.principals.get(resource_id)
    if p is not None:
        return p
    kind = "role" if ":role/" in resource_id else "user"
    return model.get(kind, resource_id.split("/")[-1])


def evaluate_request(integ, kind, name, action, resource="*", context_values=None, complete=False):
    model = build_model(integ.snapshot or {})
    p = model.get(kind, name)
    if p is None:
        raise IamWorkflowError("principal not found")
    ctx = RequestContext(context_values or {}, complete=complete)
    return evaluate(model, p, action.strip(), (resource or "*").strip(), ctx)


# ------------------------------------------------------------------ remediation workflow
def preview(finding, user_email):
    if finding.rule_id not in IAM_RULES:
        raise IamWorkflowError("IAM remediation previews exist for AWS-IAM-005 and AWS-IAM-007 findings")
    integ = finding.integration
    if integ is None or not integ.snapshot:
        raise IamWorkflowError("No stored inventory for this finding's integration: re-scan first")
    inv = integ.snapshot
    model = build_model(inv)
    p = find_principal(model, finding.resource_id)
    if p is None:
        raise IamWorkflowError("The principal is no longer in the collected IAM data: re-scan")
    prev = propose(inv, p.arn, finding.rule_id, finding.evidence or {})
    prev["mode"] = "inventory" if integ.mode in ("demo", "snapshot", "upload") else "manual"
    prev["dry_run"] = True
    rem = Remediation(org_id=finding.org_id, finding_id=finding.id, mode="iam_preview",
                      status="preview" if prev.get("ok") else "manual_only", steps=prev,
                      executed_by=user_email,
                      output="Preview only - nothing was changed." if prev.get("ok") else prev.get("error"))
    db.session.add(rem)
    audit.log(finding.org_id, user_email, "remediation.iam_preview", f"finding #{finding.id}",
              f"{finding.rule_id} on {finding.resource_id}: {'ok' if prev.get('ok') else prev.get('error')}")
    db.session.commit()
    return rem


def _get(rem_id, finding):
    rem = Remediation.query.filter_by(id=rem_id, finding_id=finding.id, org_id=finding.org_id,
                                      mode="iam_preview").first()
    if rem is None:
        raise IamWorkflowError("Remediation preview not found")
    return rem


def approve(finding, rem_id, user_email, confirm_text):
    rem = _get(rem_id, finding)
    steps = dict(rem.steps or {})
    if rem.status != "preview":
        raise IamWorkflowError(f"Only a fresh preview can be approved (status is {rem.status})")
    if not steps.get("ok"):
        raise IamWorkflowError("This preview has no applicable change")
    if not steps.get("validation", {}).get("ok"):
        raise IamWorkflowError("The proposed policy failed validation; it cannot be approved")
    if (confirm_text or "").strip() != steps.get("principal_name"):
        raise IamWorkflowError("Type the principal name exactly to approve this change")
    steps["approval"] = {"by": user_email, "at": utcnow().isoformat() + "Z"}
    rem.steps = steps
    rem.status = "approved"
    audit.log(finding.org_id, user_email, "remediation.iam_approved", f"finding #{finding.id}",
              f"approved change to {', '.join(c['policy'] for c in steps['changes'])}")
    db.session.commit()
    return rem


def apply(finding, rem_id, user_email):
    from .scanner import scan_integration
    rem = _get(rem_id, finding)
    if rem.status != "approved":
        raise IamWorkflowError("Approve the preview first (explicit approval is required before any change)")
    integ = finding.integration
    steps = dict(rem.steps or {})
    if integ.mode not in ("demo", "snapshot", "upload"):
        raise IamWorkflowError("Live AWS account: ShieldIQ uses read-only credentials and never changes AWS. Apply the "
                               "approved policy with the CLI instructions shown, then click Verify (re-scan).")
    inv = copy.deepcopy(integ.snapshot)
    n = apply_to_inventory(inv, steps["principal"], steps["changes"])
    if not n:
        raise IamWorkflowError("The policy to change was not found in the stored inventory (re-scan and preview again)")
    integ.snapshot = inv
    db.session.flush()
    return _rescan(finding, rem, steps, user_email, f"applied {n} policy document(s) to the stored {integ.mode} inventory")


def verify(finding, rem_id, user_email):
    rem = _get(rem_id, finding)
    if rem.status not in ("approved", "verified", "not_resolved"):
        raise IamWorkflowError("Verify follows an approved change")
    return _rescan(finding, rem, dict(rem.steps or {}), user_email, "verification re-scan")


def _rescan(finding, rem, steps, user_email, what):
    from .scanner import scan_integration
    run = scan_integration(finding.integration, user_email, deliver_alerts=False)
    db.session.refresh(finding)
    resolved = finding.status == "resolved"
    steps["verification"] = {"at": utcnow().isoformat() + "Z", "what": what, "scan_status": run.status,
                             "finding_status": finding.status, "resolved": resolved,
                             "note": finding.status_note}
    rem.steps = steps
    rem.status = "verified" if resolved else "not_resolved"
    rem.output = ("Resolved: the re-scan no longer reports this finding." if resolved else
                  f"Not resolved: the finding is still {finding.status} after the re-scan ({run.status}).")
    audit.log(finding.org_id, user_email, "remediation.iam_verify", f"finding #{finding.id}", rem.output)
    db.session.commit()
    return rem
