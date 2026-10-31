"""v2.1.3 regression tests: live-read failures are reported as unknown / partial coverage.

A denied or errored read must never be reclassified as a pass, a fail, or an empty result.
All fixtures below are synthetic (no real accounts, credentials or inventory data). The fake
error messages deliberately embed an ARN to prove the collector never stores message text.
"""
from shieldiq.collectors import aws_live
from shieldiq.rules import evaluate


class AwsErr(Exception):
    """Stand-in for botocore.exceptions.ClientError (botocore is an optional dependency)."""
    def __init__(self, code, status=403):
        super().__init__(f"{code}: synthetic message arn:aws:iam::123456789012:user/should-never-be-stored")
        self.response = {"Error": {"Code": code,
                                   "Message": "arn:aws:iam::123456789012:user/should-never-be-stored"},
                         "ResponseMetadata": {"HTTPStatusCode": status}}


class FakeClient:
    def __init__(self, behavior):
        self.behavior = behavior

    def __getattr__(self, op):
        def call(**kw):
            v = self.behavior.get(op, AwsErr("AccessDeniedException"))
            if isinstance(v, Exception):
                raise v
            return v(**kw) if callable(v) else v
        return call


class FakeSession:
    region_name = "us-east-1"

    def __init__(self, behaviors):
        self.behaviors = behaviors

    def client(self, name, region_name=None):  # boto3's Session.client signature (v2.2 scans every region)
        return FakeClient(self.behaviors.get(name, {}))


STS_OK = {"get_caller_identity": {"Account": "123456789012"}}  # documentation-style synthetic account id


def base_behaviors():
    """A minimal, fully readable account that should scan with complete coverage."""
    return {
        "sts": STS_OK,
        "iam": {"get_account_summary": {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
                "get_account_password_policy": {"PasswordPolicy": {"MinimumPasswordLength": 14,
                                                                   "PasswordReusePrevention": 24}},
                "list_users": {"Users": []}, "list_roles": {"Roles": []}},
        "s3": {"list_buckets": {"Buckets": []}},
        "ec2": {"describe_security_groups": {"SecurityGroups": []}, "describe_volumes": {"Volumes": []},
                "describe_instances": {"Reservations": []},
                # v2.2: regions are discovered (DescribeRegions); this account has one enabled region
                "describe_regions": {"Regions": [{"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"}]}},
        # v2.2: account-level S3 Block Public Access is read; "not configured" is a legitimate state
        "s3control": {"get_public_access_block": AwsErr("NoSuchPublicAccessBlockConfiguration", 404)},
        "rds": {"describe_db_instances": {"DBInstances": []}},
        "cloudtrail": {"describe_trails": {"trailList": []}},
        "kms": {"list_keys": {"Keys": []}},
        "guardduty": {"list_detectors": {"DetectorIds": ["synthetic-detector"]},
                      "get_detector": {"Status": "ENABLED"}},  # v2.2: detector status is read
    }


def failed_ids(inv):
    return {ev.rule.id for ev in evaluate("aws", inv) for _ in ev.failed}


def evaluated_total(inv):
    return sum(len(ev.results) for ev in evaluate("aws", inv))


# ---------------------------------------------------------------- collector semantics
def test_clean_account_has_full_coverage():
    inv = aws_live.collect({}, session=FakeSession(base_behaviors()))
    assert inv["_errors"] == []
    assert set(inv["_coverage"].values()) == {"ok"}
    # an account genuinely without CloudTrail is a real finding, not an error
    assert "AWS-LOG-001" in failed_ids(inv)
    assert "AWS-IAM-001" not in failed_ids(inv)  # root MFA enabled


def test_denied_reads_are_unknown_never_passed_or_failed():
    inv = aws_live.collect({}, session=FakeSession({"sts": STS_OK}))
    assert inv["_errors"], "denied calls must be recorded"
    assert all(e["kind"] == "denied" and e["code"] == "AccessDeniedException" and e["status"] == 403
               for e in inv["_errors"])
    # message text (with its ARN) must never be stored
    assert "arn:aws" not in repr(inv["_errors"]) and "should-never-be-stored" not in repr(inv)
    assert set(inv["_coverage"].values()) == {"partial"}
    # nothing readable -> nothing evaluated; zero false findings and zero false passes
    assert evaluated_total(inv) == 0
    assert inv["account"] == {} and inv["iam_users"] == [] and inv["s3_buckets"] == []
    assert "cloudtrail" not in inv and "guardduty_enabled" not in inv


def test_password_policy_unset_vs_denied():
    beh = base_behaviors()
    beh["iam"]["get_account_password_policy"] = AwsErr("NoSuchEntityException", 404)
    inv = aws_live.collect({}, session=FakeSession(beh))
    assert inv["account"]["password_policy"] == {"min_length": 0, "reuse_prevention": 0}
    assert "AWS-IAM-006" in failed_ids(inv)  # genuinely unset policy is a real finding
    assert inv["_coverage"]["iam"] == "ok"   # a 404 "not configured" is not a coverage gap

    beh = base_behaviors()
    beh["iam"]["get_account_password_policy"] = AwsErr("AccessDeniedException")
    inv = aws_live.collect({}, session=FakeSession(beh))
    assert "password_policy" not in inv["account"]  # unknown is not "weak"
    assert "AWS-IAM-006" not in failed_ids(inv) and "AWS-IAM-006" not in {
        ev.rule.id for ev in evaluate("aws", inv) for _ in ev.results}
    assert inv["_coverage"]["iam"] == "partial"


def test_login_profile_and_user_subreads():
    def login_profile(UserName):
        if UserName == "alice":
            raise AwsErr("NoSuchEntityException", 404)  # genuinely no console password
        raise AwsErr("AccessDeniedException")           # bob's console state is unknown
    beh = base_behaviors()
    beh["iam"].update({
        "list_users": {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]},
        "get_login_profile": login_profile,
        "list_mfa_devices": {"MFADevices": []},
        # list_access_keys / list_attached_user_policies fall through to AccessDenied
    })
    inv = aws_live.collect({}, session=FakeSession(beh))
    alice, bob = inv["iam_users"]
    assert alice["console_access"] is False      # NoSuchEntity = real state, evaluated
    assert bob["console_access"] is None         # denied = unknown, skipped by IAM-003
    assert bob["access_keys"] is None and bob["attached_policies"] is None
    iam003 = next(ev for ev in evaluate("aws", inv) if ev.rule.id == "AWS-IAM-003")
    assert iam003.results == []                  # neither user is falsely flagged
    for rid in ("AWS-IAM-004", "AWS-IAM-005"):
        ev = next(e for e in evaluate("aws", inv) if e.rule.id == rid)
        assert all("bob" not in r.resource_id for r in ev.results)


def test_s3_bucket_partial_reads():
    beh = base_behaviors()
    beh["s3"] = {
        "list_buckets": {"Buckets": [{"Name": "synthetic-bucket"}]},
        "get_public_access_block": AwsErr("AccessDeniedException"),
        "get_bucket_acl": {"Grants": [{"Grantee": {"DisplayName": "owner"}}]},
        "get_bucket_policy_status": AwsErr("NoSuchBucketPolicy", 404),
        "get_bucket_encryption": AwsErr("ServerSideEncryptionConfigurationNotFoundError", 404),
        "get_bucket_versioning": {},
    }
    inv = aws_live.collect({}, session=FakeSession(beh))
    b = inv["s3_buckets"][0]
    assert b["_unknown"] == ["public_access_block"]
    assert b["acl_public"] is False and b["policy_public"] is False
    assert b["encryption"] is None and b["versioning"] is False
    failed = failed_ids(inv)
    assert "AWS-S3-001" not in failed  # PAB unknown: not reclassified as failing
    assert "AWS-S3-002" not in failed  # ACL and policy both read, both private: passes
    assert {"AWS-S3-003", "AWS-S3-004"} <= failed  # real states: no encryption, no versioning


def test_cloudtrail_status_unknown_vs_no_trails():
    def trail(**kw):
        return {"trailList": [{"TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/synthetic",
                               "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}]}
    beh = base_behaviors()
    beh["cloudtrail"] = {"describe_trails": trail}  # GetTrailStatus falls through to denied
    inv = aws_live.collect({}, session=FakeSession(beh))
    assert inv["cloudtrail"]["enabled"] is None
    ev = next(e for e in evaluate("aws", inv) if e.rule.id == "AWS-LOG-001")
    assert ev.results == []  # unknown logging state is not "disabled"


# ---------------------------------------------------------------- scan-run plumbing
def _scan_with_inventory(org, inv):
    from shieldiq.extensions import db
    from shieldiq.models import Integration
    from shieldiq.services.scanner import scan_integration
    integ = Integration(org_id=org.id, provider="aws", name="synthetic fixture", mode="snapshot", snapshot=inv)
    db.session.add(integ)
    db.session.commit()
    run = scan_integration(integ, "test@example.com", deliver_alerts=False)
    return integ, run


def test_scan_run_partial_coverage_status(demo):
    inv = {"account_id": "123456789012", "region": "us-east-1", "_source": "test",
           "account": {"root_mfa": True}, "s3_buckets": [], "iam_users": [], "iam_roles": [],
           "security_groups": [], "ec2_instances": [], "rds_instances": [], "kms_keys": [],
           "guardduty_enabled": True,
           "_errors": [{"call": "ec2:DescribeSecurityGroups", "code": "AccessDeniedException",
                        "status": 403, "kind": "denied"}],
           "_coverage": {"iam": "ok", "ec2": "partial"}}
    integ, run = _scan_with_inventory(demo, inv)
    assert run.status == "partial"
    assert "Partial coverage" in run.error and "access-denied" in run.error
    assert integ.status == "connected" and integ.last_error == run.error
    assert run.checks_run == evaluated_total(inv)  # only evaluated checks are counted


def test_scan_run_completed_and_empty(demo):
    inv = {"account_id": "123456789012", "region": "us-east-1", "_source": "test",
           "account": {"root_mfa": True}, "s3_buckets": [], "iam_users": [], "iam_roles": [],
           "security_groups": [], "ec2_instances": [], "rds_instances": [], "kms_keys": [],
           "guardduty_enabled": True, "_errors": []}
    integ, run = _scan_with_inventory(demo, inv)
    assert run.status == "completed" and integ.last_error is None
    assert run.checks_run == 2 and run.error is None

    empty = {"account_id": "123456789012", "region": "us-east-1", "_source": "test", "account": {},
             "s3_buckets": [], "iam_users": [], "iam_roles": [], "security_groups": [],
             "ec2_instances": [], "rds_instances": [], "kms_keys": [], "_errors": []}
    integ2, run2 = _scan_with_inventory(demo, empty)
    assert run2.status == "completed" and run2.checks_run == 0
    assert "No checks were evaluated" in run2.error


def test_scan_view_flash_reports_partial(admin, demo):
    from shieldiq.extensions import db
    from shieldiq.models import Integration
    inv = {"account_id": "123456789012", "region": "us-east-1", "_source": "test",
           "account": {"root_mfa": True}, "s3_buckets": [], "iam_users": [], "iam_roles": [],
           "security_groups": [], "ec2_instances": [], "rds_instances": [], "kms_keys": [],
           "_errors": [{"call": "cloudtrail:DescribeTrails", "code": "AccessDeniedException",
                        "status": 403, "kind": "denied"}]}
    integ = Integration(org_id=demo.id, provider="aws", name="synthetic fixture", mode="snapshot", snapshot=inv)
    db.session.add(integ)
    db.session.commit()
    resp = admin.post(f"/integrations/{integ.id}/scan", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Partial coverage" in resp.data  # the flash tells the user coverage was partial


def test_notfound_is_not_blanket_legit():
    """Only the exact per-API absent codes mean 'not configured'. NoSuchBucket on a sub-call
    (bucket deleted between List and read) is unknown, not an all-false configuration."""
    beh = base_behaviors()
    beh["s3"] = {
        "list_buckets": {"Buckets": [{"Name": "vanished-bucket"}]},
        "get_public_access_block": AwsErr("NoSuchBucket", 404),
        "get_bucket_acl": AwsErr("NoSuchBucket", 404),
        "get_bucket_policy_status": AwsErr("NoSuchBucket", 404),
        "get_bucket_encryption": AwsErr("NoSuchBucket", 404),
        "get_bucket_versioning": AwsErr("NoSuchBucket", 404),
    }
    inv = aws_live.collect({}, session=FakeSession(beh))
    b = inv["s3_buckets"][0]
    assert set(b["_unknown"]) == {"public_access_block", "acl_public", "policy_public",
                                  "encryption", "versioning"}
    s3_failed = {ev.rule.id for ev in evaluate("aws", inv) if ev.rule.service == "S3" for _ in ev.results}
    assert not s3_failed, "nothing may be evaluated for a bucket whose reads all failed"
    assert inv["_coverage"]["s3"] == "partial"
    assert any(e["code"] == "NoSuchBucket" for e in inv["_errors"])  # recorded, not swallowed


def test_exact_absent_codes_still_legit():
    beh = base_behaviors()
    beh["s3"] = {
        "list_buckets": {"Buckets": [{"Name": "plain-bucket"}]},
        "get_public_access_block": AwsErr("NoSuchPublicAccessBlockConfiguration", 404),
        "get_bucket_acl": {"Grants": [{"Grantee": {"DisplayName": "owner"}}]},
        "get_bucket_policy_status": AwsErr("NoSuchBucketPolicy", 404),
        "get_bucket_encryption": AwsErr("ServerSideEncryptionConfigurationNotFoundError", 404),
        "get_bucket_versioning": {},
    }
    inv = aws_live.collect({}, session=FakeSession(beh))
    b = inv["s3_buckets"][0]
    assert "_unknown" not in b and inv["_errors"] == [] and inv["_coverage"]["s3"] == "ok"
    failed = failed_ids(inv)
    assert {"AWS-S3-001", "AWS-S3-003", "AWS-S3-004"} <= failed  # real misconfigurations
    assert "AWS-S3-002" not in failed                            # ACL + policy both read, both private


def test_legacy_string_errors_still_mark_partial(demo):
    inv = {"account_id": "123456789012", "region": "us-east-1", "_source": "test",
           "account": {"root_mfa": True}, "s3_buckets": [], "iam_users": [], "iam_roles": [],
           "security_groups": [], "ec2_instances": [], "rds_instances": [], "kms_keys": [],
           # the format v2.1.2 stored for snapshots of live scans
           "_errors": ["cloudtrail:DescribeTrails: AccessDeniedException"]}
    integ, run = _scan_with_inventory(demo, inv)
    assert run.status == "partial" and "cloudtrail:DescribeTrails" in run.error


def test_dashboard_and_exports_flag_partial_coverage(admin, demo):
    from shieldiq.extensions import db
    from shieldiq.models import Integration
    from shieldiq.services import coverage_notes, dashboard_data
    inv = {"account_id": "123456789012", "region": "us-east-1", "_source": "test",
           "account": {"root_mfa": True}, "s3_buckets": [], "iam_users": [], "iam_roles": [],
           "security_groups": [], "ec2_instances": [], "rds_instances": [], "kms_keys": [],
           "_errors": [{"call": "kms:ListKeys", "code": "AccessDeniedException",
                        "status": 403, "kind": "denied"}]}
    integ = Integration(org_id=demo.id, provider="aws", name="synthetic partial", mode="snapshot", snapshot=inv)
    db.session.add(integ)
    db.session.commit()
    admin.post(f"/integrations/{integ.id}/scan", follow_redirects=True)

    notes = coverage_notes(demo.id)
    assert any(n["name"] == "synthetic partial" for n in notes)
    assert dashboard_data(demo.id)["coverage"] == notes

    resp = admin.get("/dashboard", follow_redirects=True)
    assert b"Covers evaluated checks only" in resp.data  # the score is never presented as complete

    import json as jsonlib
    body = jsonlib.loads(admin.get("/export/findings.json").data)
    assert any(n["name"] == "synthetic partial" for n in body["coverage_notes"])
    assert "evaluated checks only" in body["coverage_disclaimer"]

    admin.post("/reports/generate", data={}, follow_redirects=True)
    from shieldiq.models import Report
    rep = Report.query.filter_by(org_id=demo.id).order_by(Report.id.desc()).first()
    assert rep and rep.filename != "pending"
    resp = admin.get(f"/reports/{rep.id}/download?inline=1")
    assert resp.status_code == 200 and b"%PDF" in resp.data[:8]


# ---------------------------------------------------------------- auto-resolve must not lie
def _sg_inv(errors):
    """Inventory with one SSH-open security group, or with that read failed."""
    inv = {"account_id": "123456789012", "region": "us-east-1", "_source": "test",
           "account": {"root_mfa": True}, "s3_buckets": [], "iam_users": [], "iam_roles": [],
           "ec2_instances": [], "rds_instances": [], "kms_keys": [], "_errors": errors}
    if not errors:
        inv["security_groups"] = [{"id": "sg-1", "name": "ssh", "ingress": [
            {"protocol": "tcp", "from": 22, "to": 22, "cidr": "0.0.0.0/0"}]}]
    else:
        inv["security_groups"] = []
    return inv


def test_partial_scan_preserves_unverified_findings(demo):
    from shieldiq.extensions import db
    from shieldiq.models import Finding, Integration
    from shieldiq.services import attack_graph
    from shieldiq.services.scanner import posture_score, scan_integration
    integ = Integration(org_id=demo.id, provider="aws", name="sg fixture", mode="snapshot",
                        snapshot=_sg_inv([]))
    db.session.add(integ)
    db.session.commit()

    run1 = scan_integration(integ, "t@example.com", deliver_alerts=False)
    assert run1.status == "completed"
    f = Finding.query.filter_by(integration_id=integ.id, rule_id="AWS-EC2-001").one()
    assert f.status == "open"
    score1 = posture_score(demo.id)
    paths1 = len(attack_graph.build(demo.id)["paths"])

    # second scan: the security-group read failed - nothing about sg-1 was evaluated
    integ.snapshot = _sg_inv([{"call": "ec2:DescribeSecurityGroups", "code": "AccessDeniedException",
                               "status": 403, "kind": "denied"}])
    db.session.commit()
    run2 = scan_integration(integ, "t@example.com", deliver_alerts=False)
    db.session.refresh(f)
    assert run2.status == "partial"
    assert f.status == "open"                     # NOT resolved: unknown is not fixed
    assert "Unverified" in f.status_note
    assert run2.resolved_findings == 0
    score2 = posture_score(demo.id)
    assert score2 <= score1                       # partial coverage never improves the score
    assert len(attack_graph.build(demo.id)["paths"]) >= paths1  # attack paths stay honest

    # third scan: clean read, issue genuinely fixed -> only now may it resolve
    fixed = _sg_inv([])
    fixed["security_groups"][0]["ingress"] = [{"protocol": "tcp", "from": 443, "to": 443, "cidr": "0.0.0.0/0"}]
    integ.snapshot = fixed
    db.session.commit()
    run3 = scan_integration(integ, "t@example.com", deliver_alerts=False)
    db.session.refresh(f)
    assert run3.status == "completed" and f.status == "resolved"
    assert f.status_note == "Auto-resolved: passed in the latest scan"


def test_partial_scan_resolves_only_what_it_evaluated(demo):
    """A partial run may still auto-resolve a finding whose check DID run and pass."""
    from shieldiq.extensions import db
    from shieldiq.models import Finding, Integration
    from shieldiq.services.scanner import scan_integration
    bad = _sg_inv([])
    bad["account"]["password_policy"] = {"min_length": 6, "reuse_prevention": 0}
    integ = Integration(org_id=demo.id, provider="aws", name="pp fixture", mode="snapshot", snapshot=bad)
    db.session.add(integ)
    db.session.commit()
    scan_integration(integ, "t@example.com", deliver_alerts=False)
    f = Finding.query.filter_by(integration_id=integ.id, rule_id="AWS-IAM-006").one()
    assert f.status == "open"

    # partial run (SG read now fails) but the password policy was read and is now compliant
    nxt = _sg_inv([{"call": "ec2:DescribeSecurityGroups", "code": "AccessDeniedException",
                    "status": 403, "kind": "denied"}])
    nxt["account"]["password_policy"] = {"min_length": 14, "reuse_prevention": 24}
    integ.snapshot = nxt
    db.session.commit()
    run = scan_integration(integ, "t@example.com", deliver_alerts=False)
    db.session.refresh(f)
    assert run.status == "partial" and f.status == "resolved"  # evaluated + passed resolves even when partial
