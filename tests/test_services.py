"""Copilot, compliance, collectors (mocked network), crypto/config regression tests."""
import requests
from cryptography.fernet import Fernet

from shieldiq.collectors import aws_live, github_live
from shieldiq.models import Finding
from shieldiq.rules import evaluate
from shieldiq.services import copilot, org_compliance
from shieldiq.services.scanner import posture_score


# ---------------------------------------------------------------- copilot
def test_copilot_offline_intents(demo):
    comp, score = org_compliance(demo.id), posture_score(demo.id)
    first = copilot.chat("What should I fix first?", demo.id, comp, score)
    assert first["engine"] == "offline" and "#" in first["answer"]
    assert "PATH-" in copilot.chat("show me attack paths", demo.id, comp, score)["answer"]
    assert "PCI DSS" in copilot.chat("how do we look for pci?", demo.id, comp, score)["answer"]
    f = Finding.query.first()
    assert f.title in copilot.chat(f"explain finding #{f.id}", demo.id, comp, score)["answer"]
    assert "Posture score" in copilot.chat("give me a summary", demo.id, comp, score)["answer"]


def test_copilot_analysis_has_everything(demo):
    f = Finding.query.filter_by(rule_id="AWS-EC2-001").first()
    a = copilot.analyze_finding(f)
    assert a["root_cause"] and a["impact"] and a["steps"] and a["cli"]
    assert a["attack_paths"]["paths"] >= 1 and "attack path" in a["blast_radius"]
    assert any("SOC 2" in c for c in a["compliance"])
    assert a["auto_fix_available"]


def test_copilot_llm_falls_back_gracefully(app, demo, monkeypatch):
    app.config["LLM_API_KEY"] = "sk-test"

    def boom(*a, **k):
        raise requests.ConnectionError("no network")
    monkeypatch.setattr(requests, "post", boom)
    res = copilot.chat("What should I fix first?", demo.id, org_compliance(demo.id), posture_score(demo.id))
    assert res["engine"] == "offline" and "LLM unavailable" in res["note"]


def test_copilot_llm_used_when_available(app, demo, monkeypatch):
    app.config["LLM_API_KEY"] = "sk-test"
    seen = {}

    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": "Fix the open SSH group first."}}]}

    def fake_post(url, headers=None, json=None, timeout=None):
        seen["system"] = json["messages"][0]["content"]
        return R()
    monkeypatch.setattr(requests, "post", fake_post)
    res = copilot.chat("priorities?", demo.id, org_compliance(demo.id), posture_score(demo.id))
    assert res["answer"] == "Fix the open SSH group first." and res["engine"].startswith("llm:")
    assert "Open findings" in seen["system"]  # grounded in the org's own data


# ---------------------------------------------------------------- compliance
def test_compliance_scores(demo):
    comp = org_compliance(demo.id)
    assert set(comp) == {"CIS", "SOC2", "ISO27001", "PCI", "GDPR", "NIST", "HIPAA"}
    for fw in comp.values():
        assert fw["score"] is None or 0 <= fw["score"] <= 100
        assert fw["controls_assessed"] <= fw["controls_total"]


# ---------------------------------------------------------------- config / crypto (regression of the original crash)
def test_generated_encryption_key_is_valid(app):
    Fernet(app.config["ENCRYPTION_KEY"].encode())  # original app crashed here on startup
    from shieldiq.security import decrypt, encrypt
    tok = encrypt({"a": 1})
    assert decrypt(tok, as_json=True) == {"a": 1}
    assert decrypt("garbage") is None


def test_invalid_env_key_gives_clear_error(tmp_path, monkeypatch):
    import pytest
    from shieldiq import create_app
    from shieldiq.config import TestConfig
    monkeypatch.setenv("SHIELDIQ_ENCRYPTION_KEY", "not-a-valid-key")
    with pytest.raises(ValueError):
        create_app(TestConfig, INSTANCE_DIR=str(tmp_path))


# ---------------------------------------------------------------- GitHub live collector (mocked HTTP)
class GHResp:
    def __init__(self, status, data=None, text=""):
        self.status_code, self._d, self.text, self.headers = status, data, text, {}

    def json(self):
        return self._d


class GHSession:
    headers = {}

    def get(self, url, timeout=None, params=None):
        api = "https://api.github.com"
        routes = {
            f"{api}/users/octo": GHResp(200, {"type": "User"}),
            f"{api}/repos/octo/app": GHResp(200, {"name": "app", "default_branch": "main", "private": False}),
            f"{api}/repos/octo/app/branches/main": GHResp(200, {"protected": False}),
            f"{api}/repos/octo/app/git/trees/main": GHResp(200, {"tree": [
                {"path": "config/settings.py", "type": "blob", "size": 100},
                {"path": "README.md", "type": "blob", "size": 10},
                {"path": "node_modules/x.js", "type": "blob", "size": 10}]}),
            "https://raw.githubusercontent.com/octo/app/main/config/settings.py":
                GHResp(200, text="KEY = 'AKIA" + "ZT4M2N8QW5R7Y6PX'\n"),
            "https://raw.githubusercontent.com/octo/app/main/README.md": GHResp(200, text="# hello"),
        }
        return routes.get(url, GHResp(404))


def test_github_live_collector(monkeypatch):
    monkeypatch.setattr(github_live, "_session", lambda token=None: GHSession())
    inv = github_live.collect("octo/app")
    repo = inv["repos"][0]
    assert repo["branch_protection"] == {"enabled": False}
    assert repo["has_security_policy"] is False and repo["dependabot"] is False
    assert repo["secrets_found"] and repo["secrets_found"][0]["path"] == "config/settings.py"
    assert repo["files_scanned"] == 2  # node_modules skipped
    failed = {ev.rule.id for ev in evaluate("github", inv) for _ in ev.failed}
    assert {"GH-REPO-001", "GH-REPO-004", "GH-REPO-005", "GH-REPO-006"} <= failed
    assert "GH-ORG-001" not in failed  # 2FA setting is not visible for personal accounts, so not guessed


def test_github_target_validation():
    import pytest
    from shieldiq.collectors import CollectorError
    for bad in ["", "a/b/c", "bad name", "../etc"]:
        with pytest.raises(CollectorError):
            github_live.collect(bad)


# ---------------------------------------------------------------- AWS live collector (fake boto3 session)
class FakeClient:
    def __init__(self, name):
        self.name = name

    def __getattr__(self, op):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        data = {
            "get_caller_identity": {"Account": "999999999999"},
            "get_account_summary": {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}},
            "get_account_password_policy": {"PasswordPolicy": {"MinimumPasswordLength": 8}},
            "list_users": {"Users": [{"UserName": "bob"}]},
            "get_login_profile": {"LoginProfile": {}},
            "list_mfa_devices": {"MFADevices": []},
            "list_access_keys": {"AccessKeyMetadata": [{"AccessKeyId": "AKIAABCDEFGHIJKLMNOP", "Status": "Active",
                                                        "CreateDate": now - timedelta(days=200)}]},
            "list_attached_user_policies": {"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]},
            "list_roles": {"Roles": []},
            "list_buckets": {"Buckets": [{"Name": "data"}]},
            "get_bucket_acl": {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]},
            "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": False}},
            "get_bucket_versioning": {},
            "describe_security_groups": {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "ssh", "IpPermissions": [
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]},
            "describe_volumes": {"Volumes": []},
            "describe_instances": {"Reservations": []},
            "describe_db_instances": {"DBInstances": []},
            "describe_trails": {"trailList": []},
            "list_keys": {"Keys": []},
            "list_detectors": {"DetectorIds": []},
        }
        if op in ("get_public_access_block", "get_bucket_encryption"):
            def raise_(**kw):
                raise RuntimeError("NoSuchConfiguration")
            return raise_
        return lambda **kw: data[op]


class FakeSession:
    region_name = "ap-south-1"

    def client(self, name):
        return FakeClient(name)


def test_aws_live_collector_maps_api_to_inventory():
    inv = aws_live.collect({}, session=FakeSession())
    assert inv["account_id"] == "999999999999"
    assert inv["iam_users"][0]["access_keys"][0]["age_days"] >= 199
    assert inv["s3_buckets"][0]["acl_public"] is True
    # failed reads are recorded as sanitized structured entries, never as raw exception text
    pab_err = next(e for e in inv["_errors"] if e["call"] == "s3:GetPublicAccessBlock")
    assert pab_err["code"] == "RuntimeError" and pab_err["kind"] == "error"
    # the failed PAB read marks the field unknown, so AWS-S3-001 skips instead of guessing
    assert "public_access_block" in inv["s3_buckets"][0]["_unknown"]
    failed = {ev.rule.id for ev in evaluate("aws", inv) for _ in ev.failed}
    assert {"AWS-IAM-001", "AWS-IAM-003", "AWS-IAM-004", "AWS-IAM-005", "AWS-S3-002",
            "AWS-EC2-001", "AWS-LOG-001", "AWS-MON-001"} <= failed
    assert "AWS-S3-001" not in failed  # unknown PAB state is not reported as non-compliant


# ---------------------------------------------------------------- alert delivery (mocked Slack webhook)
def test_slack_alert_delivery(app, demo, monkeypatch):
    from shieldiq.extensions import db
    from shieldiq.models import Organization
    from shieldiq.security import encrypt
    from shieldiq.services.alerts import raise_alert
    org = db.session.get(Organization, demo.id)
    org.slack_webhook_enc = encrypt("https://hooks.slack.com/services/T/B/X")
    sent = {}

    class R:
        status_code = 200

    def fake_post(url, json=None, timeout=None):
        sent["url"], sent["text"] = url, json["text"]
        return R()
    monkeypatch.setattr(requests, "post", fake_post)
    a = raise_alert(org, "new_finding", "Public bucket", severity="critical")
    assert a.delivered == {"slack": "sent"} and "Public bucket" in sent["text"]

    def down(*a, **k):
        raise requests.ConnectionError()
    monkeypatch.setattr(requests, "post", down)
    a = raise_alert(org, "new_finding", "Another", severity="high")
    assert a.delivered["slack"].startswith("error")  # failure is recorded, never raised
