"""Slack workspace rules."""
from .engine import CheckResult, fixer, find, rule

BROAD_SCOPES = {"admin", "channels:history", "groups:history", "im:history", "files:read", "users:read.email"}


def _ws(inv):
    return f"slack://{inv.get('workspace', {}).get('name', 'workspace')}"


@rule("SLK-001", "slack", "Workspace", "Two-factor authentication is not required", "high",
      "Require 2FA for every workspace member.",
      ["mfa"],
      "Workspace authentication settings do not enforce 2FA.",
      "Compromised passwords give access to internal conversations, files and shared credentials.",
      ["Admin > Settings & permissions > Authentication > Require two-factor authentication.",
       "Better: enforce SSO with your identity provider's MFA."],
      cli="# Workspace settings > Authentication > Two-factor authentication: Required", asset="identity")
def slk_2fa(inv):
    ws = inv.get("workspace")
    if ws:
        yield CheckResult(_ws(inv), bool(ws.get("two_factor_required")),
                          "Required" if ws.get("two_factor_required") else "Optional")


@fixer("SLK-001")
def _f1(inv, rid):
    inv.setdefault("workspace", {})["two_factor_required"] = True
    return True


@rule("SLK-002", "slack", "Workspace", "Public file links are enabled", "medium",
      "Disable public file sharing links.",
      ["public_data"],
      "Members can create public links to files that work without signing in.",
      "Internal documents can be shared to the whole internet with one click.",
      ["Disable 'Public file sharing' in workspace permissions."],
      cli="# Workspace settings > Permissions > Public file sharing: Disabled", asset="datastore")
def slk_public_files(inv):
    ws = inv.get("workspace")
    if ws and "public_file_sharing" in ws:
        yield CheckResult(_ws(inv), not ws["public_file_sharing"], "Enabled" if ws["public_file_sharing"] else "Disabled")


@fixer("SLK-002")
def _f2(inv, rid):
    inv.setdefault("workspace", {})["public_file_sharing"] = False
    return True


@rule("SLK-003", "slack", "Workspace", "Session duration exceeds 7 days", "low",
      "Force re-authentication at least every 7 days.",
      ["credentials"],
      "Session duration is set longer than 168 hours.",
      "Stolen session cookies stay valid for a long time.",
      ["Set session duration to 7 days or less."],
      cli="# Workspace settings > Authentication > Session duration")
def slk_session(inv):
    ws = inv.get("workspace")
    if ws and "session_duration_hours" in ws:
        h = ws["session_duration_hours"]
        yield CheckResult(_ws(inv), h <= 168, f"Session duration {h} hours")


@fixer("SLK-003")
def _f3(inv, rid):
    inv.setdefault("workspace", {})["session_duration_hours"] = 168
    return True


@rule("SLK-004", "slack", "Workspace", "External shared channels need no admin approval", "medium",
      "Require admin approval before Slack Connect channels are created.",
      ["access"],
      "Members can connect channels with external organizations without approval.",
      "Sensitive channels can be shared with outside organizations unnoticed.",
      ["Require admin approval for Slack Connect invitations."],
      cli="# Workspace settings > Slack Connect > Require approval")
def slk_ext(inv):
    ws = inv.get("workspace")
    if ws and "external_channel_approval" in ws:
        yield CheckResult(_ws(inv), bool(ws["external_channel_approval"]),
                          "Approval required" if ws["external_channel_approval"] else "No approval")


@fixer("SLK-004")
def _f4(inv, rid):
    inv.setdefault("workspace", {})["external_channel_approval"] = True
    return True


@rule("SLK-005", "slack", "Apps", "Installed app holds broad data-access scopes", "medium",
      "Review apps with history/file/admin scopes.",
      ["access"],
      "A third-party app was granted scopes that read message history, files or admin APIs.",
      "A compromised or malicious app vendor can exfiltrate the workspace's conversations.",
      ["Review the app's need for each scope; remove the app or reinstall with fewer scopes.",
       "Enable app approval so members cannot install apps freely."],
      cli="# Workspace settings > Manage apps > {resource} > Remove / Reconfigure")
def slk_apps(inv):
    for a in inv.get("apps", []):
        broad = sorted(set(a.get("scopes", [])) & BROAD_SCOPES)
        yield CheckResult(f"slack-app://{a['name']}", not broad,
                          f"Broad scopes: {', '.join(broad)}" if broad else "Minimal scopes")


@fixer("SLK-005")
def _f5(inv, rid):
    a = find(inv.get("apps"), "name", rid.split("//")[-1])
    if not a:
        return False
    a["scopes"] = [s for s in a.get("scopes", []) if s not in BROAD_SCOPES]
    return True
