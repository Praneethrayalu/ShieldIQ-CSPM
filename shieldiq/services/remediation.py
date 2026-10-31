"""Remediation: verified auto-fix for demo/snapshot/upload inventories, fix scripts, and real GitHub PRs.

Auto-fix never touches a live cloud account. For live accounts ShieldIQ generates the exact
CLI/Terraform fix so a human runs it through their normal change process, then re-scans to verify.
"""
import base64
import copy
import re

import requests
from flask import current_app

from ..extensions import db
from ..models import Remediation, utcnow
from ..rules import get_rule
from ..rules.engine import comment_safe
from ..security import decrypt
from . import audit
from .alerts import raise_alert
from .scanner import scan_integration


class RemediationError(Exception):
    pass


def apply_fix(finding, user_email):
    """Apply the rule's fix to the stored inventory, re-scan, and verify the finding is resolved."""
    integ = finding.integration
    rule = get_rule(finding.rule_id)
    steps = []
    if integ is None or integ.mode not in ("demo", "snapshot", "upload"):
        raise RemediationError("Auto-fix only runs on demo, snapshot or uploaded inventories. "
                               "For live accounts use the generated script / Terraform, then re-scan.")
    if not rule or not rule.fix:
        raise RemediationError("No automatic fix exists for this rule")
    inv = copy.deepcopy(integ.snapshot)
    steps.append({"step": "Load current inventory", "status": "ok", "at": utcnow().isoformat() + "Z"})
    if not rule.fix(inv, finding.resource_id):
        raise RemediationError("Resource not found in the inventory (it may have been removed)")
    steps.append({"step": f"Apply fix: {rule.steps[0] if rule.steps else rule.title}", "status": "ok",
                  "at": utcnow().isoformat() + "Z"})
    integ.snapshot = inv
    db.session.flush()
    run = scan_integration(integ, user_email, deliver_alerts=False)
    db.session.refresh(finding)
    verified = finding.status == "resolved"
    steps.append({"step": f"Re-scan {integ.name} ({run.checks_run} checks)", "status": "ok" if run.status in ("completed", "partial") else "failed",
                  "at": utcnow().isoformat() + "Z"})
    steps.append({"step": "Verify finding resolved", "status": "verified" if verified else "still failing",
                  "at": utcnow().isoformat() + "Z"})
    rem = Remediation(org_id=finding.org_id, finding_id=finding.id, mode="auto_fix",
                      status="verified" if verified else "failed", steps=steps, executed_by=user_email,
                      output=f"Posture score after fix: {run.posture_score}")
    db.session.add(rem)
    audit.log(finding.org_id, user_email, "remediation.auto_fix", f"finding #{finding.id}",
              f"{rule.id} on {finding.resource_id}: {'verified' if verified else 'not verified'}")
    raise_alert(integ_org(finding), "remediation", f"Fixed: {rule.title}", f"{finding.resource_id} verified by re-scan",
                "low", finding_id=finding.id, deliver=False)
    db.session.commit()
    return rem, run


def integ_org(finding):
    from ..models import Organization
    return db.session.get(Organization, finding.org_id)


def fix_script(finding):
    """Generated fix script + IaC snippet. Every scanned/uploaded value interpolated into them is quoted
    (shlex.quote for the shell script, string-escaped for Terraform) and comment lines are flattened, so a
    hostile resource name (e.g. `x;touch PWNED;#` or one containing a newline) cannot inject commands."""
    rule = get_rule(finding.rule_id)
    rid = finding.resource_id
    safe_rid = comment_safe(rid)
    sh = ["#!/usr/bin/env bash", f"# ShieldIQ fix for finding #{finding.id}: {comment_safe(rule.title)}",
          f"# Resource: {safe_rid}",
          "# Review before running. Requires the provider CLI and permissions to change this resource.",
          "set -euo pipefail", "", rule.render(rule.cli, rid, quote="shell"), "",
          "echo 'Done. Re-scan in ShieldIQ to verify.'", ""]
    tf = f"# ShieldIQ fix for finding #{finding.id}: {comment_safe(rule.title)}\n# Resource: {safe_rid}\n" \
         f"{rule.render(rule.terraform, rid, quote=rule.iac_quote).lstrip()}\n" if rule.terraform else None
    return "\n".join(sh), tf



def open_github_pr(finding, org, user_email, repo=None, token=None, base="main", session=None):
    """Create a branch, commit the Terraform fix under shieldiq-fixes/, and open a pull request."""
    rule = get_rule(finding.rule_id)
    repo = (repo or org.github_repo or "").strip()
    token = token or decrypt(org.github_token_enc) or current_app.config.get("GITHUB_TOKEN")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo or ""):
        raise RemediationError("Set the remediation repository (owner/repo) in Settings first")
    if not token:
        raise RemediationError("A GitHub token with 'contents' and 'pull requests' write access is needed (Settings)")
    _, tf = fix_script(finding)
    content = tf or f"# {comment_safe(rule.title)}\n# {comment_safe(finding.resource_id)}\n\n" + \
        rule.render(rule.cli, finding.resource_id, quote="shell")
    s = session or requests.Session()
    h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "User-Agent": "ShieldIQ"}
    api = f"https://api.github.com/repos/{repo}"

    def call(method, url, **kw):
        r = s.request(method, url, headers=h, timeout=15, **kw)
        if r.status_code >= 400:
            raise RemediationError(f"GitHub API {r.status_code} on {url.replace(api, '') or '/'}: "
                                   f"{(r.json() or {}).get('message', '') if r.content else ''}")
        return r.json()

    base_sha = call("GET", f"{api}/git/ref/heads/{base}")["object"]["sha"]
    branch = f"shieldiq/fix-{rule.id.lower()}-{finding.id}"
    call("POST", f"{api}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": base_sha})
    path = f"shieldiq-fixes/{rule.id.lower()}-{finding.id}.{rule.iac_kind if tf else 'sh'}"
    call("PUT", f"{api}/contents/{path}", json={"message": f"fix(security): {rule.title}", "branch": branch,
                                                "content": base64.b64encode(content.encode()).decode()})
    body = (f"Automated remediation proposed by ShieldIQ for finding #{finding.id}.\n\n**{rule.title}** ({finding.severity})\n"
            f"Resource: `{finding.resource_id}`\n\n{rule.root_cause}\n\n**Steps**\n" +
            "\n".join(f"- {s_}" for s_ in rule.steps) + "\n\nPlease review and run `terraform plan` before merging.")
    pr = call("POST", f"{api}/pulls", json={"title": f"fix(security): {rule.title}", "head": branch, "base": base, "body": body})
    rem = Remediation(org_id=org.id, finding_id=finding.id, mode="github_pr", status="pr_opened",
                      pr_url=pr.get("html_url"), executed_by=user_email,
                      steps=[{"step": f"Branch {branch}", "status": "ok"}, {"step": f"Commit {path}", "status": "ok"},
                             {"step": f"PR #{pr.get('number')}", "status": "ok"}])
    db.session.add(rem)
    finding.status = "in_progress"
    finding.status_note = f"Fix PR opened: {pr.get('html_url')}"
    audit.log(org.id, user_email, "remediation.github_pr", f"finding #{finding.id}", pr.get("html_url"))
    db.session.commit()
    return rem
