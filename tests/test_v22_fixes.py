"""v2.2 regression tests for the detection-validation audit fixes.

Every AWS response here is synthetic (no network, no credentials). botocore's Stubber is used where a real
boto3 client matters (pagination); elsewhere a small duck-typed fake session stands in for boto3.
"""
import io
import json
import os
import shlex
import subprocess
import sys
import textwrap

import pytest

from shieldiq.collectors import aws_live
from shieldiq.rules import RULES, evaluate
from shieldiq.rules.iam_policy import analyze


# ---------------------------------------------------------------- fake AWS
class AwsErr(Exception):
    def __init__(self, code, status=403):
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "synthetic"}, "ResponseMetadata": {"HTTPStatusCode": status}}


class FakeClient:
    """Duck-typed boto3 client. Unlisted operations are AccessDenied. `pages` makes an operation paginated:
    {method: (input_token, output_token, result_key, [page1, page2, ...])}."""

    def __init__(self, svc, beh, calls, region):
        self.svc, self.beh, self.calls, self.region = svc, beh, calls, region

    def can_paginate(self, method):
        return method in self.beh.get("_pages", {})

    def get_paginator(self, method):
        in_tok, out_tok, _key, pages = self.beh["_pages"][method]
        outer = self

        class P:
            def paginate(self_, **kw):
                token = None
                while True:
                    outer.calls.append((outer.svc, method, outer.region, dict(kw, **({in_tok: token} if token else {}))))
                    page = pages[[p.get("_id") for p in pages].index(token or "first")]
                    yield page
                    token = page.get(out_tok)
                    if not token:
                        return
        return P()

    def __getattr__(self, method):
        def call(**kw):
            self.calls.append((self.svc, method, self.region, kw))
            v = self.beh.get(method, AwsErr("AccessDenied"))
            if callable(v) and not isinstance(v, Exception):
                v = v(region=self.region, **kw) if getattr(v, "wants_region", False) else v(**kw)
            if isinstance(v, Exception):
                raise v
            return v
        return call


class FakeSession:
    region_name = "us-east-1"

    def __init__(self, beh):
        self.beh, self.calls = beh, []

    def client(self, svc, region_name=None):
        return FakeClient(svc, self.beh.get(svc, {}), self.calls, region_name or self.region_name)


def regional(fn):
    fn.wants_region = True
    return fn


ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
READ_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:Get*", "s3:List*"], "Resource": "*"}]}


def base():
    return {
        "sts": {"get_caller_identity": {"Account": "123456789012"}},
        "iam": {"get_account_summary": {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
                "get_account_password_policy": {"PasswordPolicy": {"MinimumPasswordLength": 14, "PasswordReusePrevention": 24}},
                "list_users": {"Users": []}, "list_roles": {"Roles": []},
                "list_user_policies": {"PolicyNames": []}, "list_groups_for_user": {"Groups": []},
                "list_attached_user_policies": {"AttachedPolicies": []},
                "list_attached_group_policies": {"AttachedPolicies": []}, "list_group_policies": {"PolicyNames": []},
                "list_attached_role_policies": {"AttachedPolicies": []}, "list_role_policies": {"PolicyNames": []},
                "get_login_profile": AwsErr("NoSuchEntity", 404), "list_mfa_devices": {"MFADevices": []},
                "list_access_keys": {"AccessKeyMetadata": []},
                "get_policy": lambda PolicyArn: {"Policy": {"Arn": PolicyArn, "DefaultVersionId": "v1"}},
                "get_policy_version": lambda PolicyArn, VersionId: {"PolicyVersion": {"Document": READ_DOC}}},
        "s3": {"list_buckets": {"Buckets": []}},
        "s3control": {"get_public_access_block": AwsErr("NoSuchPublicAccessBlockConfiguration", 404)},
        "ec2": {"describe_regions": {"Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]},
                "describe_security_groups": {"SecurityGroups": []}, "describe_volumes": {"Volumes": []},
                "describe_instances": {"Reservations": []}},
        "rds": {"describe_db_instances": {"DBInstances": []}},
        "cloudtrail": {"describe_trails": {"trailList": []}},
        "kms": {"list_keys": {"Keys": []}},
        "guardduty": {"list_detectors": {"DetectorIds": ["d1"]}, "get_detector": {"Status": "ENABLED"}},
    }


def with_user(b, name="ops", attached=(), inline=None, groups=None):
    b["iam"]["list_users"] = {"Users": [{"UserName": name}]}
    b["iam"]["list_attached_user_policies"] = {"AttachedPolicies": [
        {"PolicyName": p.split("/")[-1], "PolicyArn": p if p.startswith("arn:") else f"arn:aws:iam::aws:policy/{p}"}
        for p in attached]}
    if inline:
        b["iam"]["list_user_policies"] = {"PolicyNames": list(inline)}
        b["iam"]["get_user_policy"] = lambda UserName, PolicyName: {"PolicyDocument": inline[PolicyName]}
    if groups:
        b["iam"]["list_groups_for_user"] = {"Groups": [{"GroupName": g} for g in groups]}
    return b


def results(inv, rule_id):
    ev = next(e for e in evaluate("aws", inv) if e.rule.id == rule_id)
    assert ev.error is None, ev.error
    return ev.results


def verdict(inv, rule_id):
    res = results(inv, rule_id)
    if not res:
        return "SKIP"
    return "FAIL" if any(not r.passed for r in res) else "PASS"


def collect(b, **creds):
    s = FakeSession(b)
    return aws_live.collect(creds, session=s), s


# ================================================================ 1. IAM policy documents
def test_analyze_admin_and_scoped():
    assert analyze([{"name": "a", "document": ADMIN_DOC}])["admin"]
    assert analyze([{"name": "a", "document": {"Statement": {"Effect": "Allow", "Action": ["*:*"], "Resource": ["*"]}}}])["admin"]
    r = analyze([{"name": "r", "document": READ_DOC}])
    assert not r["admin"] and not r["escalation"]


def test_analyze_escalation_paths():
    doc = lambda acts: [{"name": "p", "document": {"Statement": [{"Effect": "Allow", "Action": acts, "Resource": "*"}]}}]
    for action in ("iam:CreatePolicyVersion", "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:UpdateAssumeRolePolicy",
                   "iam:AddUserToGroup", "iam:SetDefaultPolicyVersion"):
        assert [e["path"] for e in analyze(doc([action]))["escalation"]] == [action], action
    assert {e["path"] for e in analyze(doc(["iam:PassRole", "ec2:RunInstances"]))["escalation"]} == {"iam:PassRole + ec2:RunInstances"}
    assert {e["path"] for e in analyze(doc(["iam:PassRole", "lambda:CreateFunction"]))["escalation"]} == {"iam:PassRole + lambda:CreateFunction"}
    assert len(analyze(doc(["iam:*"]))["escalation"]) >= 10  # wildcards are expanded against the catalogue


def test_analyze_negatives_passrole_alone_deny_and_notaction():
    doc = lambda stmts: [{"name": "p", "document": {"Statement": stmts}}]
    assert not analyze(doc([{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]))["escalation"]
    denied = doc([{"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
                  {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}])
    assert not analyze(denied)["escalation"]
    power_user = doc([{"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"}])
    r = analyze(power_user)  # PowerUserAccess-style: not admin, no iam escalation
    assert not r["admin"] and not r["escalation"]


def test_inline_user_policy_admin_detected():
    inv, _ = collect(with_user(base(), inline={"god": ADMIN_DOC}))
    res = results(inv, "AWS-IAM-005")
    assert verdict(inv, "AWS-IAM-005") == "FAIL" and "god" in res[0].detail
    assert res[0].evidence["admin_via"][0]["source"] == "inline"


def test_customer_managed_policy_document_admin_detected():
    b = with_user(base(), attached=["arn:aws:iam::123456789012:policy/CompanyAdmins"])
    b["iam"]["get_policy_version"] = lambda PolicyArn, VersionId: {"PolicyVersion": {"Document": ADMIN_DOC}}
    inv, _ = collect(b)
    assert verdict(inv, "AWS-IAM-005") == "FAIL" and "CompanyAdmins" in results(inv, "AWS-IAM-005")[0].detail


def test_url_encoded_string_document_is_parsed():
    from urllib.parse import quote
    b = with_user(base(), inline={"god": quote(json.dumps(ADMIN_DOC))})
    inv, _ = collect(b)
    assert verdict(inv, "AWS-IAM-005") == "FAIL"


def test_group_membership_policies_detected():
    b = with_user(base(), groups=["Admins"])
    b["iam"]["list_attached_group_policies"] = {"AttachedPolicies": [
        {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}
    b["iam"]["get_policy_version"] = lambda PolicyArn, VersionId: {"PolicyVersion": {"Document": ADMIN_DOC}}
    inv, _ = collect(b)
    r = results(inv, "AWS-IAM-005")[0]
    assert not r.passed and r.evidence["groups"] == ["Admins"]
    assert r.evidence["admin_via"][0]["source"].startswith("group-managed:Admins")


def test_group_inline_escalation_detected():
    b = with_user(base(), groups=["Ops"])
    b["iam"]["list_group_policies"] = {"PolicyNames": ["ops-inline"]}
    b["iam"]["get_group_policy"] = lambda GroupName, PolicyName: {"PolicyDocument": {
        "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]}}
    inv, _ = collect(b)
    r = results(inv, "AWS-IAM-005")[0]
    assert not r.passed and "iam:PassRole + ec2:RunInstances" in r.detail


def test_role_inline_admin_detected_and_name_match_kept():
    b = base()
    b["iam"]["list_roles"] = {"Roles": [{"RoleName": "ci", "Path": "/"}, {"RoleName": "legacy", "Path": "/"}]}
    b["iam"]["list_role_policies"] = lambda RoleName: {"PolicyNames": ["all"] if RoleName == "ci" else []}
    b["iam"]["get_role_policy"] = lambda RoleName, PolicyName: {"PolicyDocument": ADMIN_DOC}
    b["iam"]["list_attached_role_policies"] = lambda RoleName: {"AttachedPolicies": [
        {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}] if RoleName == "legacy" else []}
    b["iam"]["get_policy_version"] = AwsErr("AccessDenied")  # document unreadable: the NAME match still fires
    inv, _ = collect(b)
    by = {r.resource_id.split("/")[-1]: r for r in results(inv, "AWS-IAM-005")}
    assert not by["ci"].passed and not by["legacy"].passed
    assert "AdministratorAccess" in by["legacy"].detail


def test_scoped_user_passes_only_when_every_policy_was_read():
    inv, _ = collect(with_user(base(), attached=["ReadOnlyAccess"]))
    assert verdict(inv, "AWS-IAM-005") == "PASS"
    assert results(inv, "AWS-IAM-005")[0].evidence["documents_evaluated"] == 1


@pytest.mark.parametrize("broken", ["list_user_policies", "list_groups_for_user", "get_policy_version",
                                    "list_attached_user_policies"])
def test_unreadable_policy_data_is_unknown_not_scoped(broken):
    b = with_user(base(), attached=["ReadOnlyAccess"])
    b["iam"][broken] = AwsErr("AccessDenied")
    inv, _ = collect(b)
    assert verdict(inv, "AWS-IAM-005") == "SKIP"
    assert any(e["code"] == "AccessDenied" for e in inv["_errors"])


def test_known_admin_still_reported_when_other_reads_fail():
    b = with_user(base(), inline={"god": ADMIN_DOC})
    b["iam"]["list_groups_for_user"] = AwsErr("AccessDenied")
    inv, _ = collect(b)
    assert verdict(inv, "AWS-IAM-005") == "FAIL"


def test_admin_fixer_removes_admin_documents():
    inv, _ = collect(with_user(base(), inline={"god": ADMIN_DOC}))
    rid = results(inv, "AWS-IAM-005")[0].resource_id
    assert RULES["AWS-IAM-005"].fix(inv, rid)
    assert verdict(inv, "AWS-IAM-005") == "PASS"


# ================================================================ 2. pagination + regions
def test_pages_uses_real_boto3_paginator_with_stubber():
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    iam = boto3.client("iam", region_name="us-east-1", aws_access_key_id="AKIDEXAMPLE", aws_secret_access_key="x")
    import datetime as dt
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    u = lambda n: {"UserName": n, "Path": "/", "UserId": "AIDA" + n.upper().ljust(16, "X"),
                   "Arn": f"arn:aws:iam::123456789012:user/{n}", "CreateDate": now}
    with Stubber(iam) as st:
        st.add_response("list_users", {"Users": [u("a"), u("b")], "IsTruncated": True, "Marker": "m2"}, {})
        st.add_response("list_users", {"Users": [u("c")], "IsTruncated": False}, {"Marker": "m2"})
        users = aws_live._pages(iam, "list_users", "Users")
        st.assert_no_pending_responses()
    assert [x["UserName"] for x in users] == ["a", "b", "c"]


def test_second_page_of_users_is_scanned():
    b = base()
    b["iam"]["_pages"] = {"list_users": ("Marker", "Marker", "Users", [
        {"_id": "first", "Users": [{"UserName": "u1"}], "Marker": "p2"},
        {"_id": "p2", "Users": [{"UserName": "u2-no-mfa"}]}])}
    b["iam"]["get_login_profile"] = {"LoginProfile": {}}
    b["iam"]["list_mfa_devices"] = lambda UserName: {"MFADevices": [] if UserName == "u2-no-mfa" else [{"SerialNumber": "x"}]}
    inv, s = collect(b)
    by = {r.resource_id.split("/")[-1]: r.passed for r in results(inv, "AWS-IAM-003")}
    assert by == {"u1": True, "u2-no-mfa": False}
    assert ("iam", "list_users", "us-east-1", {"Marker": "p2"}) in s.calls


def test_every_enabled_region_is_scanned():
    b = base()
    b["ec2"]["describe_regions"] = {"Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
                                                {"RegionName": "eu-west-1", "OptInStatus": "opt-in-not-required"},
                                                {"RegionName": "ap-east-1", "OptInStatus": "not-opted-in"}]}
    b["ec2"]["describe_security_groups"] = regional(lambda region, **kw: {"SecurityGroups": [
        {"GroupId": "sg-eu", "GroupName": "db", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]
        if region == "eu-west-1" else []})
    inv, s = collect(b)
    assert inv["regions"] == ["eu-west-1", "us-east-1"]  # the not-opted-in region is excluded
    r = results(inv, "AWS-EC2-001")[0]
    assert not r.passed and r.evidence["region"] == "eu-west-1" and "PostgreSQL (5432)" in r.detail
    assert {c[2] for c in s.calls if c[1] == "describe_db_instances"} == {"us-east-1", "eu-west-1"}
    assert {g["region"] for g in inv["guardduty"]} == {"us-east-1", "eu-west-1"}


def test_explicit_region_list_skips_discovery():
    inv, s = collect(base(), regions="eu-central-1, us-west-2")
    assert inv["regions"] == ["eu-central-1", "us-west-2"]
    assert not any(c[1] == "describe_regions" for c in s.calls)


def test_region_discovery_denied_falls_back_and_is_partial():
    b = base()
    b["ec2"]["describe_regions"] = AwsErr("UnauthorizedOperation")
    inv, _ = collect(b)
    assert inv["regions"] == ["us-east-1"]
    assert inv["_coverage"]["ec2"] == "partial"
    assert any(e["call"] == "ec2:DescribeRegions" for e in inv["_errors"])


# ================================================================ 3. resolve logic
def _live_integ(app):
    from shieldiq.extensions import db
    from shieldiq.models import Integration, Organization
    from shieldiq.security import encrypt
    org = Organization(name="t")
    db.session.add(org)
    db.session.commit()
    integ = Integration(org_id=org.id, provider="aws", name="live", mode="live",
                        secret_enc=encrypt({"access_key_id": "AKIDEXAMPLE", "secret_access_key": "x"}), config={})
    db.session.add(integ)
    db.session.commit()
    return integ


@pytest.fixture()
def live(app, monkeypatch):
    state = {}
    monkeypatch.setattr(aws_live, "_session", lambda creds, profiles=None: FakeSession(state["beh"]))
    from shieldiq.services import scanner
    integ = _live_integ(app)

    def scan(beh):
        state["beh"] = beh
        return scanner.scan_integration(integ, "t", deliver_alerts=False)
    scan.integ = integ
    return scan


def _sg_beh(port_open=True, include=True):
    b = base()
    perms = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
              "IpRanges": [{"CidrIp": "0.0.0.0/0" if port_open else "10.0.0.0/8"}]}]
    b["ec2"]["describe_security_groups"] = {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": perms}] if include else []}
    return b


def _finding(integ, rule="AWS-EC2-001"):
    from shieldiq.models import Finding
    return Finding.query.filter_by(integration_id=integ.id, rule_id=rule).first()


def test_crashing_rule_does_not_resolve_and_marks_scan_partial(live):
    live(_sg_beh(True))
    assert _finding(live.integ).status == "open"
    orig = RULES["AWS-EC2-001"].check

    def boom(inv):
        raise RuntimeError("simulated bug")
        yield  # pragma: no cover
    RULES["AWS-EC2-001"].check = boom
    try:
        run = live(_sg_beh(False))
    finally:
        RULES["AWS-EC2-001"].check = orig
    f = _finding(live.integ)
    assert f.status == "open" and "rule error" in f.status_note
    assert run.status == "partial" and "AWS-EC2-001" in run.error and run.resolved_findings == 0
    assert live.integ.check_stats["AWS-EC2-001"]["total"] == 0


def test_engine_reports_crash_without_fake_pass():
    orig = RULES["AWS-KMS-001"].check
    RULES["AWS-KMS-001"].check = lambda inv: 1 / 0
    try:
        ev = next(e for e in evaluate("aws", {}) if e.rule.id == "AWS-KMS-001")
    finally:
        RULES["AWS-KMS-001"].check = orig
    assert ev.results == [] and "ZeroDivisionError" in ev.error


def test_evaluated_and_passing_resource_is_resolved(live):
    live(_sg_beh(True))
    run = live(_sg_beh(False))
    f = _finding(live.integ)
    assert f.status == "resolved" and f.status_note == "Auto-resolved: passed in the latest scan"
    assert run.status == "completed"


def test_unseen_resource_in_partial_scan_is_not_resolved(live):
    live(_sg_beh(True))
    b = _sg_beh(True, include=False)
    b["kms"]["list_keys"] = AwsErr("AccessDenied")  # any read failure makes the scan partial
    run = live(b)
    f = _finding(live.integ)
    assert run.status == "partial" and f.status == "open" and f.status_note.startswith("Unverified")


def test_unseen_resource_in_complete_scan_is_resolved_as_gone(live):
    live(_sg_beh(True))
    run = live(_sg_beh(True, include=False))
    f = _finding(live.integ)
    assert run.status == "completed" and f.status == "resolved" and "no longer present" in f.status_note


def test_profile_only_integration_without_allowed_profile_is_refused(app, monkeypatch):
    from shieldiq.extensions import db
    from shieldiq.security import encrypt
    from shieldiq.services import scanner
    integ = _live_integ(app)
    integ.secret_enc = encrypt({"access_key_id": "", "secret_access_key": "", "profile": "default"})
    db.session.commit()
    called = []
    monkeypatch.setattr(aws_live, "collect", lambda *a, **k: called.append(1))
    run = scanner.scan_integration(integ, "t", deliver_alerts=False)
    assert run.status == "failed" and "not allowed" in run.error and not called


def test_no_credentials_never_uses_default_chain():
    with pytest.raises(aws_live.CollectorError):
        aws_live._session({"region": "us-east-1"})
    with pytest.raises(aws_live.CollectorError):
        aws_live._session({"profile": "default"}, profiles=set())


# ================================================================ 4. S3 / EC2 / GuardDuty / CloudTrail
def _bucket(b, pab=None, grants=(), policy_public=False):
    b["s3"]["list_buckets"] = {"Buckets": [{"Name": "bkt"}]}
    b["s3"]["get_public_access_block"] = ({"PublicAccessBlockConfiguration": pab} if pab is not None
                                          else AwsErr("NoSuchPublicAccessBlockConfiguration", 404))
    b["s3"]["get_bucket_acl"] = {"Grants": [{"Grantee": {"Type": "Group", "URI": f"http://acs.amazonaws.com/groups/global/{g}"},
                                             "Permission": "READ"} for g in grants]}
    b["s3"]["get_bucket_policy_status"] = {"PolicyStatus": {"IsPublic": policy_public}}
    b["s3"]["get_bucket_encryption"] = {"ServerSideEncryptionConfiguration": {"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
    b["s3"]["get_bucket_versioning"] = {"Status": "Enabled"}
    return b


ALL_ON = dict(BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=True, RestrictPublicBuckets=True)


def test_account_level_block_public_access_is_honoured():
    b = _bucket(base(), grants=["AllUsers"], policy_public=True)
    b["s3control"]["get_public_access_block"] = {"PublicAccessBlockConfiguration": ALL_ON}
    inv, _ = collect(b)
    assert verdict(inv, "AWS-S3-001") == "PASS" and verdict(inv, "AWS-S3-002") == "PASS"
    assert "neutralised" in results(inv, "AWS-S3-002")[0].detail


def test_bucket_without_any_block_public_access_fails():
    inv, _ = collect(_bucket(base(), grants=["AllUsers"]))
    assert verdict(inv, "AWS-S3-001") == "FAIL" and verdict(inv, "AWS-S3-002") == "FAIL"


def test_account_level_read_denied_is_unknown_for_s3_001():
    b = _bucket(base())
    b["s3control"]["get_public_access_block"] = AwsErr("AccessDenied")
    inv, _ = collect(b)
    assert verdict(inv, "AWS-S3-001") == "SKIP"
    assert inv["s3_account_public_access_block"] is None


def test_authenticated_users_grant_is_public():
    inv, _ = collect(_bucket(base(), grants=["AuthenticatedUsers"]))
    r = results(inv, "AWS-S3-002")[0]
    assert not r.passed and "AuthenticatedUsers" in r.detail


def test_restrict_public_buckets_neutralises_public_policy_only():
    b = _bucket(base(), pab=dict(ALL_ON, IgnorePublicAcls=False), grants=["AllUsers"], policy_public=True)
    inv, _ = collect(b)
    r = results(inv, "AWS-S3-002")[0]
    assert not r.passed and r.evidence["public_via"] == ["ACL"]


@pytest.mark.parametrize("port", [3306, 5432, 1433, 1521, 27017, 6379, 9200, 5601, 11211, 22, 3389])
def test_risky_ports_open_to_world_fail(port):
    inv = {"security_groups": [{"id": "sg", "ingress": [{"protocol": "tcp", "from": port, "to": port, "cidr": "0.0.0.0/0"}]}]}
    assert verdict(inv, "AWS-EC2-001") == "FAIL"


@pytest.mark.parametrize("rule,ok", [({"protocol": "-1", "from": 0, "to": 65535, "cidr": "0.0.0.0/0"}, False),
                                     ({"protocol": "tcp", "from": 6379, "to": 6379, "cidr": "::/0"}, False),
                                     ({"protocol": "tcp", "from": 443, "to": 443, "cidr": "0.0.0.0/0"}, True),
                                     ({"protocol": "tcp", "from": 5432, "to": 5432, "cidr": "10.0.0.0/8"}, True),
                                     ({"protocol": "icmp", "from": 22, "to": -1, "cidr": "0.0.0.0/0"}, True)])
def test_sg_port_cases(rule, ok):
    inv = {"security_groups": [{"id": "sg", "ingress": [rule]}]}
    assert verdict(inv, "AWS-EC2-001") == ("PASS" if ok else "FAIL")


def test_security_groups_read_denied_is_skipped():
    b = base()
    b["ec2"]["describe_security_groups"] = AwsErr("UnauthorizedOperation")
    inv, _ = collect(b)
    assert verdict(inv, "AWS-EC2-001") == "SKIP"


def _instances(*states):
    b = base()
    b["ec2"]["describe_instances"] = {"Reservations": [{"Instances": [
        {"InstanceId": f"i-{s}", "State": {"Name": s}, "MetadataOptions": {"HttpTokens": "optional"}} for s in states]}]}
    return b


def test_terminated_instances_skipped_stopped_still_checked():
    inv, _ = collect(_instances("terminated", "shutting-down", "stopped"))
    ids = [r.resource_id for r in results(inv, "AWS-EC2-003")]
    assert ids == ["i-stopped"]


def test_ebs_volume_missing_from_listing_is_unknown():
    b = _instances("running")
    b["ec2"]["describe_instances"]["Reservations"][0]["Instances"][0]["BlockDeviceMappings"] = [{"Ebs": {"VolumeId": "vol-x"}}]
    inv, _ = collect(b)
    assert inv["ec2_instances"][0]["ebs_encrypted"] is None and verdict(inv, "AWS-EC2-004") == "SKIP"


@pytest.mark.parametrize("status,expected", [("ENABLED", "PASS"), ("DISABLED", "FAIL")])
def test_guardduty_detector_status(status, expected):
    b = base()
    b["guardduty"]["get_detector"] = {"Status": status}
    inv, _ = collect(b)
    assert verdict(inv, "AWS-MON-001") == expected


def test_guardduty_status_unreadable_is_unknown():
    b = base()
    b["guardduty"]["get_detector"] = AwsErr("AccessDeniedException")
    inv, _ = collect(b)
    assert verdict(inv, "AWS-MON-001") == "SKIP"


def _trails(*specs, status=None):
    b = base()
    b["cloudtrail"]["describe_trails"] = {"trailList": [
        {"Name": n, "TrailARN": f"arn:aws:cloudtrail:us-east-1:123456789012:trail/{n}", "IsMultiRegionTrail": mr,
         "LogFileValidationEnabled": lv} for n, mr, lv, _ in specs]}
    logging = {f"arn:aws:cloudtrail:us-east-1:123456789012:trail/{n}": lg for n, _mr, _lv, lg in specs}
    b["cloudtrail"]["get_trail_status"] = status or (lambda Name: {"IsLogging": logging[Name]})
    return b


def test_cloudtrail_one_fully_compliant_trail_passes():
    inv, _ = collect(_trails(("org", True, True, True), ("old", False, False, False)))
    assert verdict(inv, "AWS-LOG-001") == "PASS"


def test_cloudtrail_properties_split_across_trails_fails():
    inv, _ = collect(_trails(("a", False, False, True), ("b", True, True, False)))
    assert verdict(inv, "AWS-LOG-001") == "FAIL"


def test_cloudtrail_candidate_status_unreadable_is_unknown():
    inv, _ = collect(_trails(("org", True, True, None), status=AwsErr("AccessDeniedException")))
    assert verdict(inv, "AWS-LOG-001") == "SKIP"


# ================================================================ 5. app
def test_demo_seeding_is_opt_in(monkeypatch):
    import importlib
    import shieldiq.config as cfg
    monkeypatch.delenv("SHIELDIQ_SEED_DEMO", raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: None)
    try:
        assert importlib.reload(cfg).Config.SEED_DEMO is False
        monkeypatch.setenv("SHIELDIQ_SEED_DEMO", "1")
        assert importlib.reload(cfg).Config.SEED_DEMO is True
    finally:
        monkeypatch.delenv("SHIELDIQ_SEED_DEMO", raising=False)
        importlib.reload(cfg)


def test_login_page_hides_demo_credentials_outside_demo_mode(app, client):
    from shieldiq.seed import seed_demo
    seed_demo(with_fixes=False)  # a demo account exists in the DB, but demo mode is OFF
    app.config["SEED_DEMO"] = False
    for url in ("/login", "/login?demo=1", "/"):
        html = client.get(url).get_data(as_text=True)
        assert "ShieldIQ@2026" not in html and "demo@shieldiq.local" not in html, url


def test_login_page_shows_demo_credentials_in_demo_mode(client, demo):
    assert "ShieldIQ@2026" in client.get("/login").get_data(as_text=True)


def test_disabled_users_existing_session_is_cut_off(app, demo):
    from shieldiq.extensions import db
    from shieldiq.models import User
    c = app.test_client()
    c.post("/login", data={"email": "viewer@shieldiq.local", "password": "ShieldIQ@2026"})
    assert c.get("/findings").status_code == 200
    u = User.query.filter_by(email="viewer@shieldiq.local").first()
    u.is_active_user = False
    db.session.commit()
    r = c.get("/findings")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert c.get("/api/v1/findings").status_code == 401


def test_user_loader_rejects_inactive_users(app, demo):
    # defence in depth: Flask-Login 0.6's UserMixin already treats inactive users as unauthenticated;
    # the loader now refuses them itself too, so a custom is_authenticated can never re-open the hole
    from shieldiq.extensions import db
    from shieldiq.models import User
    u = User.query.filter_by(email="viewer@shieldiq.local").first()
    assert app.login_manager._user_callback(str(u.id)) is u
    u.is_active_user = False
    db.session.commit()
    assert app.login_manager._user_callback(str(u.id)) is None
    assert app.login_manager._user_callback("not-a-number") is None


def test_active_users_session_keeps_working(admin):
    assert admin.get("/findings").status_code == 200
    assert admin.get("/findings").status_code == 200


def _snapshot_finding(admin, name, rule):
    from shieldiq.models import Finding
    snap = {"s3_buckets": [{"name": name, "public_access_block": {}, "acl_public": True, "policy_public": False,
                            "encryption": None, "versioning": False}]}
    admin.post("/integrations/new", data={"provider": "aws", "mode": "snapshot", "name": "evil",
                                          "snapshot": (io.BytesIO(json.dumps(snap).encode()), "s.json")},
               content_type="multipart/form-data")
    return Finding.query.filter(Finding.resource_id == f"arn:aws:s3:::{name}", Finding.rule_id == rule).first()


def test_fix_script_quotes_hostile_resource_names_and_does_not_execute_them(admin, tmp_path):
    f = _snapshot_finding(admin, "x;touch PWNED;#$(touch PWNED2)`touch PWNED3`", "AWS-S3-001")
    sh = admin.get(f"/findings/{f.id}/script.sh").get_data(as_text=True)
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    (fakebin / "aws").write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ARGS_OUT\"\n")
    (fakebin / "aws").chmod(0o755)
    (tmp_path / "fix.sh").write_text(sh)
    env = {**os.environ, "PATH": f"{fakebin}:{os.environ['PATH']}", "ARGS_OUT": str(tmp_path / "args.txt")}
    p = subprocess.run(["bash", str(tmp_path / "fix.sh")], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20)
    assert p.returncode == 0, p.stderr
    assert not any((tmp_path / n).exists() for n in ("PWNED", "PWNED2", "PWNED3"))
    args = (tmp_path / "args.txt").read_text().splitlines()
    # the bucket NAME (not the ARN) arrives as one intact argument
    assert args[args.index("--bucket") + 1] == "x;touch PWNED;#$(touch PWNED2)`touch PWNED3`"


def test_fix_script_comment_cannot_be_broken_by_newline(admin):
    f = _snapshot_finding(admin, "ok\nrm -rf /tmp/shieldiq-should-not", "AWS-S3-004")
    sh = admin.get(f"/findings/{f.id}/script.sh").get_data(as_text=True)
    assert not any(line.startswith("rm -rf") for line in sh.splitlines())


def test_s3_fix_commands_use_bucket_name_not_arn():
    rule = RULES["AWS-S3-003"]
    cli = rule.render(rule.cli, "arn:aws:s3:::my-bucket", quote="shell")
    assert "--bucket my-bucket" in cli and "arn:aws:s3" not in cli
    assert RULES["AWS-IAM-005"].render("{resource}", "arn:aws:iam::1:role/ci", quote="shell") == "ci"


def test_terraform_snippet_escapes_hostile_values():
    rule = RULES["AWS-S3-001"]
    tf = rule.render(rule.terraform, 'arn:aws:s3:::a"${file("/etc/passwd")}', quote="hcl")
    assert '${file' not in tf.replace("$${file", "") and '\\"' in tf


def test_findings_carry_evidence_origin_labels(admin):
    from shieldiq.models import Finding
    f = Finding.query.first()
    d = f.to_dict()["evidence_origin"]
    assert d == {"origin": "demo-data", "verified_by_scanner": False,
                 "label": "DEMO DATA - fictional sample inventory, not a real detection"}
    html = admin.get(f"/findings/{f.id}").get_data(as_text=True)
    assert "Not verified scanner evidence" in html and "DEMO DATA" in html
    assert "DEMO DATA" in admin.get("/findings").get_data(as_text=True)
    api = admin.get(f"/api/v1/findings/{f.id}").get_json()
    assert api["finding"]["evidence_origin"]["verified_by_scanner"] is False
    assert "not new scanner evidence" in api["analysis"]["disclaimer"]


def test_live_finding_is_labelled_verified(live):
    live(_sg_beh(True))
    assert _finding(live.integ).to_dict()["evidence_origin"]["verified_by_scanner"] is True


def test_copilot_llm_answer_is_labelled_unverified(admin, app, monkeypatch):
    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": "CRITICAL: your bucket is being exfiltrated right now"}}]}
    app.config["LLM_API_KEY"] = "test-key"
    monkeypatch.setattr("shieldiq.services.copilot.requests.post", lambda *a, **k: R())
    from shieldiq.models import Finding
    before = Finding.query.count()
    d = admin.post("/api/v1/copilot/chat", json={"message": "anything critical?"}).get_json()
    assert d["ai_generated"] is True and d["verified_evidence"] is False and "not scanner evidence" in d["disclaimer"]
    assert Finding.query.count() == before  # the AI cannot create findings
    off = admin.post("/api/v1/copilot/chat", json={"message": "summary"})
    assert off.get_json()["verified_evidence"] is False


def test_aws_profile_field_rejects_unlisted_profiles(admin, app):
    from shieldiq.models import Integration
    app.config["ALLOWED_AWS_PROFILES"] = []
    r = admin.post("/integrations/new", data={"provider": "aws", "mode": "live", "profile": "default"}, follow_redirects=True)
    assert "not allowed" in r.get_data(as_text=True)
    assert Integration.query.filter_by(mode="live").count() == 0
    html = admin.get("/integrations").get_data(as_text=True)
    assert 'name="profile"' not in html  # no free-text profile field unless the operator allowed some


def test_aws_profile_field_accepts_operator_allowed_profile(admin, app, monkeypatch):
    from shieldiq.models import Integration
    app.config["ALLOWED_AWS_PROFILES"] = ["tenant-a"]
    seen = {}
    monkeypatch.setattr(aws_live, "collect", lambda creds, session=None: seen.setdefault("creds", creds) and {
        "account_id": "1", "_errors": []})
    monkeypatch.setattr(aws_live, "_session", lambda creds, profiles=None: object())
    admin.post("/integrations/new", data={"provider": "aws", "mode": "live", "profile": "tenant-a", "regions": "eu-west-1"})
    integ = Integration.query.filter_by(mode="live").first()
    assert integ is not None and seen["creds"]["profile"] == "tenant-a" and seen["creds"]["regions"] == ["eu-west-1"]
    assert '<option value="tenant-a">' in admin.get("/integrations").get_data(as_text=True)


def test_invalid_region_name_rejected(admin):
    from shieldiq.models import Integration
    r = admin.post("/integrations/new", data={"provider": "aws", "mode": "live", "access_key_id": "AKID",
                                              "secret_access_key": "x", "regions": "eu-west-1,../../etc"},
                   follow_redirects=True)
    assert "Not an AWS region name" in r.get_data(as_text=True)
    assert Integration.query.filter_by(mode="live").count() == 0
