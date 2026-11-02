"""v2.3 IAM effective-permission engine, attack paths, collection completeness and safe remediation.

All AWS data here is synthetic: the IAM lab inventory (shieldiq/sample_data/aws_iam_lab.json), botocore Stubber
responses and fake sessions. No network, no credentials, no real AWS account.
"""
import copy
import json
import os
from datetime import datetime, timezone

import pytest

from shieldiq.iam import ALLOWED, DENIED, INDETERMINATE, RequestContext, build_model, evaluate
from shieldiq.iam.analysis import Analyzer
from shieldiq.iam.policy import eval_conditions, stmt_matches_action, stmt_matches_resource

LAB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "shieldiq", "sample_data",
                        "aws_iam_lab.json")
ACCT = "111122223333"


def lab():
    with open(LAB_PATH) as fh:
        return json.load(fh)


def model(inv=None):
    return build_model(inv or lab())


def ev(m, name, action, resource="*", kind="user", ctx=None):
    return evaluate(m, m.get(kind, name), action, resource, ctx)


def arn(kind, name):
    return f"arn:aws:iam::{ACCT}:{kind}/{name}"


# ================================================================ policy language
def test_action_wildcards_are_case_insensitive_and_notaction_inverts():
    assert stmt_matches_action({"Action": "IAM:pass*"}, "iam:PassRole")
    assert stmt_matches_action({"Action": ["s3:Get?bject"]}, "s3:GetObject")
    assert not stmt_matches_action({"Action": "s3:*"}, "iam:PassRole")
    assert stmt_matches_action({"NotAction": "iam:*"}, "sts:AssumeRole")
    assert not stmt_matches_action({"NotAction": ["iam:*"]}, "iam:CreateUser")


def test_resource_wildcards_notresource_and_variables():
    ctx = RequestContext({"aws:username": "alice"})
    assert stmt_matches_resource({"Resource": "arn:aws:s3:::data-*/*"}, "arn:aws:s3:::data-bucket/x", ctx) is True
    assert stmt_matches_resource({"NotResource": "arn:aws:s3:::secret/*"}, "arn:aws:s3:::secret/k", ctx) is False
    assert stmt_matches_resource({"Resource": "arn:aws:iam::1:user/${aws:username}"}, "arn:aws:iam::1:user/alice", ctx) is True
    assert stmt_matches_resource({"Resource": "arn:aws:iam::1:user/${aws:username}"}, "arn:aws:iam::1:user/bob", ctx) is False
    # unknown variable value: could match -> UNKNOWN (never silently True/False)
    assert stmt_matches_resource({"Resource": "arn:aws:s3:::b/${aws:PrincipalTag/team}/*"}, "arn:aws:s3:::b/x/y",
                                 RequestContext()) is None
    assert stmt_matches_resource({"Resource": "arn:aws:s3:::other/${aws:PrincipalTag/team}"}, "arn:aws:s3:::b/x",
                                 RequestContext()) is False


@pytest.mark.parametrize("cond,ctx,expected", [
    ({"Bool": {"aws:MultiFactorAuthPresent": "true"}}, RequestContext(), None),             # key unknown
    ({"Bool": {"aws:MultiFactorAuthPresent": "true"}}, RequestContext({}, complete=True), False),
    ({"Bool": {"aws:MultiFactorAuthPresent": "true"}}, RequestContext({"aws:MultiFactorAuthPresent": "true"}), True),
    ({"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}}, RequestContext({}, complete=True), True),
    ({"StringEqualsIfExists": {"aws:RequestedRegion": "us-east-1"}}, RequestContext({}, complete=True), True),
    ({"Null": {"aws:TokenIssueTime": "true"}}, RequestContext({}, complete=True), True),
    ({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, RequestContext({"aws:SourceIp": "10.1.2.3"}), True),
    ({"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, RequestContext({"aws:SourceIp": "10.1.2.3"}), False),
    ({"ForAllValues:StringEquals": {"aws:TagKeys": ["a", "b"]}}, RequestContext({"aws:TagKeys": []}), True),
    ({"ForAnyValue:StringLike": {"aws:TagKeys": ["team*"]}}, RequestContext({"aws:TagKeys": ["x", "team1"]}), True),
    ({"BinaryEquals": {"k": "AA=="}}, RequestContext({"k": "AA=="}), None),                   # unsupported -> unknown
    ({"DateLessThan": {"aws:CurrentTime": "2030-01-01T00:00:00Z"}},
     RequestContext({"aws:CurrentTime": "2026-10-31T00:00:00Z"}), True),
])
def test_condition_three_valued_semantics(cond, ctx, expected):
    assert eval_conditions(cond, ctx)[0] is expected


# ================================================================ evaluator
def test_direct_inline_allow_has_statement_evidence():
    d = ev(model(), "alice", "s3:DeleteBucket", "arn:aws:s3:::data-bucket")
    assert d.decision == ALLOWED
    e = d.evidence[0]
    assert e["policy"] == "AdminInline" and e["via"] == "direct" and e["sid"] == "Everything" and e["layer"] == "identity"


def test_group_inherited_permission_is_attributed_to_the_group():
    m = model()
    d = ev(m, "bob", "s3:PutObject", "arn:aws:s3:::data-bucket/report.csv")
    assert d.decision == ALLOWED
    assert d.evidence[0]["via"] == "group:devs" and d.evidence[0]["policy"] == "DevPolicy"
    assert d.evidence[0]["version"] == "v3"
    assert ev(m, "bob", "s3:PutObject", "arn:aws:s3:::secret-bucket/x").decision == DENIED
    src = m.get("user", "bob").sources_summary()
    assert src["direct"] == [] and src["group"][0]["name"] == "DevPolicy"


def test_managed_vs_inline_and_role_permissions():
    m = model()
    d = ev(m, "carol", "iam:PassRole", arn("role", "admin-role"))
    assert d.decision == ALLOWED and d.evidence[0]["policy_kind"] == "managed" and d.evidence[0]["sid"] == "PassAdmin"
    assert ev(m, "carol", "iam:PassRole", arn("role", "ops-role")).decision == DENIED  # scoped to admin-role only
    r = ev(m, "app-role", "s3:GetObject", "arn:aws:s3:::data-bucket/k", kind="role")
    assert r.decision == ALLOWED and r.evidence[0]["via"] == "role"


def test_explicit_deny_wins_over_allow_everything():
    d = ev(model(), "frank", "iam:CreateUser", arn("user", "x"))
    assert d.decision == DENIED and d.reason == "explicit_deny"
    assert d.evidence[0]["effect"] == "Deny" and d.evidence[0]["via"] == "group:restricted"
    assert ev(model(), "frank", "s3:GetObject", "arn:aws:s3:::data-bucket/k").decision == ALLOWED


def test_permissions_boundary_limits_identity_grants():
    m = model()
    d = ev(m, "dave", "iam:CreateUser", arn("user", "x"))
    assert d.decision == DENIED and d.reason == "implicit_deny_boundary"
    assert d.layers["identity_allow"] is True and d.layers["boundary_allow"] is False
    assert ev(m, "dave", "s3:GetObject", "arn:aws:s3:::data-bucket/k").decision == DENIED  # boundary alone grants nothing


def _with_scp(status, levels=None, note=""):
    inv = lab()
    inv["iam"]["scps"] = {"status": status, "levels": levels or [], "note": note}
    return build_model(inv)


FULL = {"name": "FullAWSAccess", "document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}


def test_scp_explicit_deny_and_allow_list_restrict_even_an_admin():
    deny_ou = {"name": "DenyPolicyVersions", "document": {"Statement": [
        {"Effect": "Deny", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]}}
    m = _with_scp("collected", [{"target": "r-root", "policies": [FULL]}, {"target": "ou-1", "policies": [FULL, deny_ou]},
                               {"target": ACCT, "policies": [FULL]}])
    d = ev(m, "alice", "iam:CreatePolicyVersion", arn("policy", "x"))
    assert d.decision == DENIED and d.reason == "explicit_deny" and d.evidence[0]["layer"] == "scp:ou-1"
    allow_list = {"name": "OnlyS3", "document": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}
    m2 = _with_scp("collected", [{"target": "r-root", "policies": [FULL]}, {"target": ACCT, "policies": [allow_list]}])
    d2 = ev(m2, "alice", "ec2:RunInstances")
    assert d2.decision == DENIED and d2.reason == "implicit_deny_scp"
    assert ev(m2, "alice", "s3:GetObject", "arn:aws:s3:::data-bucket/k").decision == ALLOWED


def test_unavailable_scps_make_allowed_indeterminate_but_not_management_account():
    m = _with_scp("unavailable", note="AccessDenied on ListPoliciesForTarget")
    d = ev(m, "alice", "s3:GetObject", "arn:aws:s3:::data-bucket/k")
    assert d.decision == INDETERMINATE and any("SCPs" in x for x in d.missing)
    # a Denied result stays Denied: an unknown SCP can only restrict further
    assert ev(m, "dave", "iam:CreateUser").decision == DENIED
    assert ev(_with_scp("management_account"), "alice", "s3:GetObject", "arn:aws:s3:::data-bucket/k").decision == ALLOWED


def test_notresource_excludes_the_secret_bucket():
    m = model()
    assert ev(m, "judy", "s3:GetObject", "arn:aws:s3:::data-bucket/k").decision == ALLOWED
    assert ev(m, "judy", "s3:GetObject", "arn:aws:s3:::secret-bucket/k").decision == DENIED


def test_conditions_give_indeterminate_until_context_is_known():
    m = model()
    target = arn("policy", "GracePolicy")
    d = ev(m, "grace", "iam:CreatePolicyVersion", target)
    assert d.decision == INDETERMINATE and "aws:MultiFactorAuthPresent" in " ".join(d.notes)
    assert ev(m, "grace", "iam:CreatePolicyVersion", target,
              ctx=RequestContext({"aws:MultiFactorAuthPresent": "true"}, complete=True)).decision == ALLOWED
    assert ev(m, "grace", "iam:CreatePolicyVersion", target, ctx=RequestContext({}, complete=True)).decision == DENIED


def test_missing_policy_document_is_indeterminate_and_never_secure():
    m = model()
    d = ev(m, "ivan", "s3:GetObject", "arn:aws:s3:::data-bucket/k")
    assert d.decision == INDETERMINATE and any("UnreadablePolicy" in x for x in d.missing)
    rep = Analyzer(m).principal_report(m.get("user", "ivan"))
    assert rep["state"] == "Unknown" and rep["identity_complete"] is False


def test_unknown_boundary_in_legacy_inventory_is_indeterminate():
    inv = {"account_id": ACCT, "iam_users": [{"name": "u", "attached_policies": [], "policies_complete": True,
                                              "policy_documents": [{"name": "p", "source": "inline", "document": {
                                                  "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}]}]}
    m = build_model(inv)
    d = evaluate(m, m.get("user", "u"), "s3:GetObject", "arn:aws:s3:::b/k")
    assert d.decision == INDETERMINATE
    assert any("boundary" in x for x in d.missing) and any("SCPs" in x for x in d.missing)


def test_resource_policy_grants_and_denies():
    inv = lab()
    pol = {"Statement": [
        {"Effect": "Allow", "Principal": {"AWS": arn("user", "bob")}, "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::secret-bucket/*"},
        {"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::secret-bucket/*",
         "Condition": {"StringEquals": {"aws:PrincipalArn": arn("user", "alice")}}}]}
    inv["iam"]["resource_policies"]["arn:aws:s3:::secret-bucket/top.txt"] = {"status": "collected", "document": pol}
    m = build_model(inv)
    d = ev(m, "bob", "s3:GetObject", "arn:aws:s3:::secret-bucket/top.txt")
    assert d.decision == ALLOWED and d.reason == "allowed_by_resource_policy"
    a = ev(m, "alice", "s3:GetObject", "arn:aws:s3:::secret-bucket/top.txt")
    assert a.decision == DENIED and a.reason == "explicit_deny" and a.evidence[0]["layer"] == "resource"
    inv["iam"]["resource_policies"]["arn:aws:s3:::secret-bucket/top.txt"] = {"status": "unknown"}
    assert ev(build_model(inv), "alice", "s3:GetObject", "arn:aws:s3:::secret-bucket/top.txt").decision == INDETERMINATE


def test_policy_name_alone_is_not_proof():
    from shieldiq.rules import evaluate as run_rules
    inv = {"account_id": ACCT, "iam_users": [{"name": "named-admin", "attached_policies": ["AdministratorAccess"]},
                                             {"name": "named-scoped", "attached_policies": ["ReadOnlyAccess"]}],
           "iam_roles": []}
    m = build_model(inv)
    assert evaluate(m, m.get("user", "named-admin"), "s3:GetObject").decision == INDETERMINATE
    ev5 = next(e for e in run_rules("aws", inv) if e.rule.id == "AWS-IAM-005")
    admin = next(r for r in ev5.results if r.resource_id.endswith("named-admin"))
    assert admin.passed is False and admin.evidence["basis"] == "policy name only (unverified)"
    assert "unverified" in admin.detail
    # a name list cannot prove a principal is scoped: Unknown, not passed
    assert not any(r.resource_id.endswith("named-scoped") for r in ev5.results)
    assert any(r.resource_id.endswith("named-scoped") for r in ev5.unknown)


# ================================================================ attack paths
def _paths():
    return {p["start"]["name"]: p for p in reversed(Analyzer(model()).paths())}


def test_attack_paths_are_built_from_evaluated_permissions_with_evidence():
    ps = _paths()
    carol = ps["carol"]
    assert carol["confidence"] == "confirmed" and carol["severity"] == "critical"
    step = carol["steps"][0]
    assert step["kind"] == "pass_role"
    sids = {s["sid"] for e in step["evidence"] for s in e["statements"]}
    assert {"PassAdmin", "Launch"} <= sids
    erin = ps["erin"]
    assert [s["kind"] for s in erin["steps"]] == ["assume_role", "self_escalation"]
    assert erin["steps"][1]["evidence"][0]["statements"][0]["policy"] == "OpsSelfAttach"
    # an explicit Deny on iam:* does not stop sts:AssumeRole into an escalatable role
    assert ps["frank"]["steps"][0]["kind"] == "assume_role"
    for p in ps.values():
        for s in p["steps"]:
            assert s["evidence"] and all(ev["statements"] or ev["decision"] for ev in s["evidence"])


def test_uncertain_paths_are_not_presented_as_confirmed():
    ps = _paths()
    g = ps["grace"]
    assert g["confidence"] == "likely" and g["severity"] != "critical"
    assert "not confirmed" in g["status"]
    # boundary-limited, scoped and unreadable principals get no path
    assert "dave" not in ps and "bob" not in ps and "judy" not in ps and "ivan" not in ps
    assert "alice" not in ps  # already admin: reported by AWS-IAM-005, not as a path


def test_path_disappears_when_the_edge_permission_is_removed():
    inv = lab()
    ops = next(r for r in inv["iam"]["roles"] if r["name"] == "ops-role")
    ops["inline"] = []
    ps = {p["start"]["name"] for p in Analyzer(build_model(inv)).paths()}
    assert "erin" not in ps and "frank" not in ps and "carol" in ps


def test_unknown_trust_policy_makes_assume_edges_unverified():
    inv = lab()
    for r in inv["iam"]["roles"]:
        if r["name"] == "ops-role":
            r["trust_policy"] = None
    ps = _paths_from(inv)
    assert ps["erin"]["confidence"] == "unverified"
    assert any("trust policy of ops-role" in m for m in ps["erin"]["missing"])


def _paths_from(inv):
    return {p["start"]["name"]: p for p in reversed(Analyzer(build_model(inv)).paths())}


def test_rule_007_secure_finding_unknown_states():
    from shieldiq.rules import evaluate as run_rules
    e = next(x for x in run_rules("aws", lab()) if x.rule.id == "AWS-IAM-007")
    by = {r.resource_id.split("/")[-1]: r for r in e.results}
    assert by["carol"].passed is False and by["erin"].passed is False and by["grace"].passed is False
    assert by["dave"].passed is True and by["bob"].passed is True
    assert [u.resource_id.split("/")[-1] for u in e.unknown] == ["ivan"]


# ================================================================ collection (Stubber / fakes)
def _iam_client():
    import boto3
    return boto3.client("iam", region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")


def test_authorization_details_are_paginated_and_complete():
    from botocore.stub import Stubber
    from shieldiq.collectors import aws_iam
    iam = _iam_client()
    doc = json.dumps({"Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}]})
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    page1 = {"UserDetailList": [{"UserName": "u1", "UserId": "AIDAEXAMPLE1EXAMPLE1", "Arn": arn("user", "u1"),
                                 "Path": "/", "CreateDate": now, "GroupList": ["g1"],
                                 "AttachedManagedPolicies": [{"PolicyName": "Cust", "PolicyArn": arn("policy", "Cust")}],
                                 "PermissionsBoundary": {"PermissionsBoundaryType": "Policy",
                                                         "PermissionsBoundaryArn": arn("policy", "Cust")}}],
             "GroupDetailList": [], "RoleDetailList": [], "Policies": [], "IsTruncated": True, "Marker": "m1"}
    page2 = {"UserDetailList": [{"UserName": "u2", "UserId": "AIDAEXAMPLE2EXAMPLE2", "Arn": arn("user", "u2"),
                                 "Path": "/", "CreateDate": now}],
             "GroupDetailList": [{"GroupName": "g1", "GroupId": "AGPAEXAMPLEEXAMPLE01", "Arn": arn("group", "g1"),
                                  "Path": "/", "CreateDate": now,
                                  "GroupPolicyList": [{"PolicyName": "gi", "PolicyDocument": doc}]}],
             "RoleDetailList": [{"RoleName": "r1", "RoleId": "AROAEXAMPLEEXAMPLE01", "Arn": arn("role", "r1"),
                                 "Path": "/", "CreateDate": now,
                                 "AssumeRolePolicyDocument": json.dumps({"Statement": [{"Effect": "Allow",
                                     "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}),
                                 "AttachedManagedPolicies": [{"PolicyName": "AdministratorAccess",
                                                              "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}],
             "Policies": [{"PolicyName": "Cust", "PolicyId": "ANPAEXAMPLEEXAMPLE01", "Arn": arn("policy", "Cust"),
                           "DefaultVersionId": "v2", "PolicyVersionList": [
                               {"Document": doc, "VersionId": "v2", "IsDefaultVersion": True, "CreateDate": now},
                               {"Document": doc, "VersionId": "v1", "IsDefaultVersion": False, "CreateDate": now}]}],
             "IsTruncated": False}
    flt = ["User", "Role", "Group", "LocalManagedPolicy"]
    reads = []
    with Stubber(iam) as st:
        st.add_response("get_account_authorization_details", page1, {"Filter": flt})
        st.add_response("get_account_authorization_details", page2, {"Filter": flt, "Marker": "m1"})
        rich = aws_iam.collect_authorization(iam, ACCT, managed_doc=lambda a: reads.append(a) or
                                             {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        st.assert_no_pending_responses()
    assert [u["name"] for u in rich["users"]] == ["u1", "u2"]
    assert rich["users"][0]["boundary"]["status"] == "present" and rich["users"][1]["boundary"]["status"] == "none"
    assert rich["policies"][arn("policy", "Cust")]["default_version"] == "v2"
    assert reads == ["arn:aws:iam::aws:policy/AdministratorAccess"]  # attached AWS-managed doc read separately
    m = build_model({"account_id": ACCT, "iam": rich})
    d = evaluate(m, m.get("user", "u1"), "iam:PassRole", arn("role", "r1"))
    # SCP status was not collected in this unit (collect_scps not called): Allowed is not claimed
    assert d.decision == INDETERMINATE and any("SCPs" in x for x in d.missing)
    rich["scps"] = {"status": "not_applicable"}
    m = build_model({"account_id": ACCT, "iam": rich})
    d = evaluate(m, m.get("user", "u1"), "iam:PassRole", arn("role", "r1"))
    assert {e["via"] for e in d.evidence} == {"direct", "group:g1", "boundary"} and d.decision == ALLOWED


class _Err(Exception):
    def __init__(self, code, status=403):
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "arn:aws:iam::111122223333:user/secret"},
                         "ResponseMetadata": {"HTTPStatusCode": status}}


class _Fake:
    def __init__(self, beh):
        self.beh = beh

    def __getattr__(self, op):
        def call(**kw):
            v = self.beh.get(op, _Err("AccessDenied"))
            if isinstance(v, Exception):
                raise v
            return v(**kw) if callable(v) else v
        return call


def test_gaad_denied_falls_back_and_reports_structured_errors():
    from shieldiq.collectors import aws_iam
    inv = {"account_id": ACCT, "iam_users": [{"name": "u1"}], "iam_roles": [{"name": "r1"}], "s3_buckets": [{"name": "b"}]}
    clients = {"iam": _Fake({"get_role": {"Role": {"RoleName": "r1", "PermissionsBoundary": {
        "PermissionsBoundaryArn": arn("policy", "B")}}}}),
        "organizations": _Fake({}), "s3": _Fake({"get_bucket_policy": _Err("ThrottlingException", 400)})}
    aws_iam.collect(lambda svc, rg=None: clients[svc], "us-east-1", inv, managed_doc=lambda a: None)
    ctx = inv["iam_context"]
    apis = {(e["api"], e["resource"], e["kind"]) for e in ctx["errors"]}
    assert ("iam:GetAccountAuthorizationDetails", None, "denied") in apis
    assert ("iam:GetUser", "u1", "denied") in apis
    assert ("s3:GetBucketPolicy", "b", "throttled") in apis
    assert all("secret" not in json.dumps(e) for e in ctx["errors"])  # message text never stored
    assert inv["iam_users"][0]["permissions_boundary"]["status"] == "unknown"
    assert inv["iam_roles"][0]["permissions_boundary"]["status"] == "present"
    assert ctx["scps"]["status"] == "unavailable" and ctx["sources"]["permissions_boundaries"]["status"] == "partial"
    m = build_model(inv)
    assert m.get("user", "u1").boundary_status == "unknown" and m.get("role", "r1").boundary_status == "present"


def test_scp_collection_paths():
    from botocore.stub import Stubber
    import boto3
    from shieldiq.collectors import aws_iam
    org = boto3.client("organizations", region_name="us-east-1", aws_access_key_id="t", aws_secret_access_key="t")
    rec = aws_iam._Rec()
    scp = json.dumps({"Statement": [{"Effect": "Deny", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]})
    with Stubber(org) as st:
        st.add_response("describe_organization", {"Organization": {"Id": "o-abcdefghij", "MasterAccountId": "999999999999"}})
        st.add_response("list_roots", {"Roots": [{"Id": "r-ab12", "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY",
                                                                                    "Status": "ENABLED"}]}]})
        st.add_response("list_parents", {"Parents": [{"Id": "ou-ab12-abcdefgh", "Type": "ORGANIZATIONAL_UNIT"}]},
                        {"ChildId": ACCT})
        st.add_response("list_parents", {"Parents": [{"Id": "r-ab12", "Type": "ROOT"}]}, {"ChildId": "ou-ab12-abcdefgh"})
        for target, pid in (("r-ab12", "p-full0001"), ("ou-ab12-abcdefgh", "p-deny0001"), (ACCT, "p-full0001")):
            st.add_response("list_policies_for_target", {"Policies": [{"Id": pid, "Name": pid}]},
                            {"TargetId": target, "Filter": "SERVICE_CONTROL_POLICY"})
            st.add_response("describe_policy", {"Policy": {"Content": scp if pid == "p-deny0001" else json.dumps(
                {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})}}, {"PolicyId": pid})
        out = aws_iam.collect_scps(org, ACCT, rec)
    assert out["status"] == "collected" and [lvl["target"] for lvl in out["levels"]] == ["r-ab12", "ou-ab12-abcdefgh", ACCT]
    with Stubber(org) as st:
        st.add_client_error("describe_organization", "AWSOrganizationsNotInUseException")
        assert aws_iam.collect_scps(org, ACCT, rec)["status"] == "not_applicable"
    with Stubber(org) as st:
        st.add_response("describe_organization", {"Organization": {"Id": "o-abcdefghij", "MasterAccountId": "999999999999"}})
        st.add_response("list_roots", {"Roots": [{"Id": "r-ab12", "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY",
                                                                                    "Status": "ENABLED"}]}]})
        st.add_response("list_parents", {"Parents": [{"Id": "r-ab12", "Type": "ROOT"}]}, {"ChildId": ACCT})
        st.add_client_error("list_policies_for_target", "AccessDeniedException", http_status_code=403)
        out = aws_iam.collect_scps(org, ACCT, rec)
    assert out["status"] == "unavailable" and rec.errors[-1]["kind"] == "denied"


def test_live_collector_writes_completeness_indicator():
    from shieldiq.collectors import aws_live
    from test_collector_errors import FakeSession, base_behaviors
    beh = base_behaviors()
    beh["iam"]["list_users"] = {"Users": [{"UserName": "u1", "Arn": arn("user", "u1")}]}
    beh["iam"].update({"get_login_profile": _Err("NoSuchEntity", 404), "list_mfa_devices": {"MFADevices": []},
                       "list_access_keys": {"AccessKeyMetadata": []}, "list_attached_user_policies": {"AttachedPolicies": []},
                       "list_user_policies": {"PolicyNames": []}, "list_groups_for_user": {"Groups": []}})
    inv = aws_live.collect({}, session=FakeSession(beh))
    rows = {r["source"]: r for r in inv["_sources"]}
    assert rows["iam"]["status"] == "collected" and rows["ec2"]["status"] == "collected"
    assert rows["authorization_details"]["status"] == "denied"
    assert rows["permissions_boundaries"]["status"] == "unavailable"
    assert rows["scps"]["status"] == "unavailable"
    assert inv["_errors"] == []  # core coverage semantics unchanged; IAM gaps are tracked per source
    m = build_model(inv)
    d = evaluate(m, m.get("user", "u1"), "s3:GetObject")
    assert d.decision == DENIED  # no grant at all: an unknown boundary/SCP can only restrict


def test_throttling_is_its_own_error_kind():
    from shieldiq.collectors import aws_live
    assert aws_live._kind("ThrottlingException") == "throttled"
    assert aws_live._kind("RequestLimitExceeded") == "throttled"
    assert aws_live._kind("AccessDeniedException") == "denied"


# ================================================================ scanner: Unknown state
def _lab_integration(demo, mode="snapshot", inv=None):
    from shieldiq.extensions import db
    from shieldiq.models import Integration
    from shieldiq.services.scanner import scan_integration
    integ = Integration(org_id=demo.id, provider="aws", name="IAM lab", mode=mode, snapshot=inv or lab())
    db.session.add(integ)
    db.session.commit()
    run = scan_integration(integ, "test@shieldiq.local", deliver_alerts=False)
    return integ, run


def test_unknown_state_is_counted_and_never_resolves(demo):
    from shieldiq.models import Finding
    integ, run = _lab_integration(demo)
    assert integ.check_stats["AWS-IAM-007"]["unknown"] == 1
    assert integ.check_stats["AWS-IAM-005"]["unknown"] == 1
    ids = {f.resource_id.split("/")[-1] for f in Finding.query.filter_by(integration_id=integ.id, rule_id="AWS-IAM-007")}
    assert ids == {"carol", "erin", "frank", "grace", "ops-role"}
    # a finding on ivan from an earlier scan must stay open (unverified) when ivan becomes Unknown
    from shieldiq.extensions import db
    from shieldiq.services.scanner import fingerprint, scan_integration
    f = Finding(org_id=demo.id, integration_id=integ.id, source="snapshot", rule_id="AWS-IAM-007", provider="aws",
                service="IAM", resource_id=arn("user", "ivan"), title="t", severity="high",
                fingerprint=fingerprint(integ.id, "AWS-IAM-007", arn("user", "ivan")))
    db.session.add(f)
    db.session.commit()
    scan_integration(integ, "test@shieldiq.local", deliver_alerts=False)
    db.session.refresh(f)
    assert f.status == "open" and f.status_note.startswith("Unverified")


# ================================================================ remediation workflow
def test_preview_is_a_dry_run_with_diff_impact_and_validation(demo):
    from shieldiq.models import Finding
    from shieldiq.services import iam_service
    integ, _ = _lab_integration(demo)
    before = copy.deepcopy(integ.snapshot)
    f = Finding.query.filter_by(integration_id=integ.id, rule_id="AWS-IAM-007", resource_id=arn("user", "carol")).one()
    rem = iam_service.preview(f, "analyst@shieldiq.local")
    s = rem.steps
    assert rem.status == "preview" and s["dry_run"] is True and s["ok"]
    assert integ.snapshot == before  # nothing applied
    ch = s["changes"][0]
    assert ch["policy"] == "PassRoleEC2" and "-" in ch["diff"] and "iam:PassRole" in ch["removed_actions"]
    assert s["validation"]["resolved_in_model"] is True and not s["validation"]["structural_problems"]
    assert "carol" in s["risk"] and s["offending"][0]["statements"]
    assert any("create-policy-version" in i for i in s["instructions"])


def test_wildcard_grant_gets_an_explicit_deny_guard(demo):
    from shieldiq.iam.remediation import GUARD_SID, propose
    prev = propose(lab(), arn("user", "frank"), "AWS-IAM-007")
    after = prev["changes"][0]["after"]
    guard = [s for s in after["Statement"] if s.get("Sid") == GUARD_SID]
    assert guard and guard[0]["Effect"] == "Deny" and "sts:AssumeRole" in guard[0]["Action"]
    assert prev["validation"]["resolved_in_model"] is True
    # impact: actions frank loses are listed (here: none of the sampled non-risky ones)
    assert isinstance(prev["impact"], list)


def test_approval_is_required_and_apply_rescans_and_verifies(demo):
    from shieldiq.models import Finding
    from shieldiq.services import iam_service
    integ, _ = _lab_integration(demo)
    f = Finding.query.filter_by(integration_id=integ.id, rule_id="AWS-IAM-007", resource_id=arn("user", "carol")).one()
    rem = iam_service.preview(f, "a@x")
    with pytest.raises(iam_service.IamWorkflowError, match="Approve"):
        iam_service.apply(f, rem.id, "a@x")
    with pytest.raises(iam_service.IamWorkflowError, match="Type the principal name"):
        iam_service.approve(f, rem.id, "a@x", "wrong")
    iam_service.approve(f, rem.id, "a@x", "carol")
    rem = iam_service.apply(f, rem.id, "a@x")
    assert rem.status == "verified" and rem.steps["verification"]["resolved"] is True
    assert f.status == "resolved"
    assert rem.steps["approval"]["by"] == "a@x"


def test_live_integration_is_never_changed_and_verify_rescans(demo, monkeypatch):
    from shieldiq.collectors import aws_live
    from shieldiq.models import Finding
    from shieldiq.services import iam_service
    state = {"inv": lab()}
    monkeypatch.setattr("shieldiq.services.scanner.collect_inventory", lambda integ: copy.deepcopy(state["inv"]))
    integ, run = _lab_integration(demo, mode="live")
    f = Finding.query.filter_by(integration_id=integ.id, rule_id="AWS-IAM-007", resource_id=arn("user", "carol")).one()
    rem = iam_service.preview(f, "a@x")
    assert rem.steps["mode"] == "manual"
    iam_service.approve(f, rem.id, "a@x", "carol")
    with pytest.raises(iam_service.IamWorkflowError, match="never changes AWS"):
        iam_service.apply(f, rem.id, "a@x")
    rem = iam_service.verify(f, rem.id, "a@x")  # operator has not applied it yet
    assert rem.status == "not_resolved"
    # operator applies the approved policy out of band; the next verification re-scan sees it
    from shieldiq.iam.remediation import apply_to_inventory
    apply_to_inventory(state["inv"], arn("user", "carol"), rem.steps["changes"])
    rem = iam_service.verify(f, rem.id, "a@x")
    assert rem.status == "verified" and f.status == "resolved"
    assert aws_live  # the collector itself was never called with credentials here


def test_viewer_cannot_create_previews_and_ui_shows_workflow(client, demo):
    integ, _ = _lab_integration(demo)
    from shieldiq.models import Finding
    f = Finding.query.filter_by(integration_id=integ.id, rule_id="AWS-IAM-007", resource_id=arn("user", "carol")).one()
    client.post("/login", data={"email": "viewer@shieldiq.local", "password": "ShieldIQ@2026"})
    assert client.post(f"/findings/{f.id}/iam-remediation/preview").status_code in (302, 403)
    from shieldiq.models import Remediation
    assert Remediation.query.filter_by(finding_id=f.id).count() == 0


# ================================================================ UI / API / Copilot
def test_iam_pages_render_states_completeness_and_paths(admin, demo):
    integ, _ = _lab_integration(demo)
    html = admin.get(f"/iam?integration={integ.id}").get_data(as_text=True)
    assert "data-completeness" in html and 'data-state="Unknown"' in html and 'data-state="Secure"' in html
    assert "IAM-PATH-" in html and "PassAdmin" in html
    p = admin.get(f"/iam/{integ.id}/principal/user/grace?action=iam:CreatePolicyVersion"
                  f"&resource=arn:aws:iam::{ACCT}:policy/GracePolicy").get_data(as_text=True)
    assert 'data-eval-result="Indeterminate"' in p and "MultiFactorAuthPresent" in p
    p2 = admin.get(f"/iam/{integ.id}/principal/user/grace?action=iam:CreatePolicyVersion&resource="
                   f"arn:aws:iam::{ACCT}:policy/GracePolicy&context=aws:MultiFactorAuthPresent%3Dtrue&complete=1").get_data(as_text=True)
    assert 'data-eval-result="Allowed"' in p2
    ap = admin.get("/attack-paths").get_data(as_text=True)
    assert 'id="iam-paths"' in ap and "data-iam-path" in ap


def test_finding_page_preview_approve_apply_flow(admin, demo):
    from shieldiq.models import Finding, Remediation
    integ, _ = _lab_integration(demo)
    f = Finding.query.filter_by(integration_id=integ.id, rule_id="AWS-IAM-007", resource_id=arn("user", "erin")).one()
    assert "data-iam-remediation" in admin.get(f"/findings/{f.id}").get_data(as_text=True)
    admin.post(f"/findings/{f.id}/iam-remediation/preview")
    rem = Remediation.query.filter_by(finding_id=f.id, mode="iam_preview").one()
    html = admin.get(f"/findings/{f.id}").get_data(as_text=True)
    assert "type erin to approve" in html and "+++" in html
    admin.post(f"/findings/{f.id}/iam-remediation/{rem.id}/approve", data={"confirm": "erin"})
    admin.post(f"/findings/{f.id}/iam-remediation/{rem.id}/apply")
    from shieldiq.extensions import db
    db.session.refresh(rem)
    db.session.refresh(f)
    assert rem.status == "verified" and f.status == "resolved"


def test_iam_api(app, demo, client):
    from shieldiq.extensions import db
    from shieldiq.models import ApiToken, User
    integ, _ = _lab_integration(demo)
    user = User.query.filter_by(email="demo@shieldiq.local").one()
    _, raw = ApiToken.issue(user, "t")
    db.session.commit()
    h = {"Authorization": f"Bearer {raw}"}
    j = client.get(f"/api/v1/iam/{integ.id}", headers=h).json
    assert j["counts"]["Unknown"] == 1 and j["verified_by_scanner"] is False and j["attack_paths"]
    r = client.post(f"/api/v1/iam/{integ.id}/evaluate", headers=h, json={
        "kind": "user", "name": "dave", "action": "iam:CreateUser"}).json
    assert r["decision"] == "Denied" and r["reason"] == "implicit_deny_boundary"
    assert client.post(f"/api/v1/iam/{integ.id}/evaluate", headers=h, json={"kind": "x"}).status_code == 400


def test_copilot_separates_facts_assumptions_and_missing_data(app, demo):
    from shieldiq.services import copilot
    _lab_integration(demo)
    ans = copilot.iam_answer(demo.id, f"why can carol use iam:PassRole on arn:aws:iam::{ACCT}:role/admin-role?")
    assert "**Allowed**" in ans and "PassRoleEC2" in ans
    assert "Verified from collected policies" in ans and "Assumptions" in ans and "Missing data" in ans
    summary = copilot.iam_answer(demo.id, "summarize iam escalation risk")
    assert "unknown/incomplete" in summary and "not confirmed" in summary


# ================================================================ AWS policy simulator (Stubber)
def test_simulator_results_are_mapped_and_compared():
    from botocore.stub import Stubber
    from shieldiq.iam.simulate import compare, simulate_principal
    iam = _iam_client()
    with Stubber(iam) as st:
        st.add_response("simulate_principal_policy", {"EvaluationResults": [
            {"EvalActionName": "iam:PassRole", "EvalResourceName": arn("role", "admin-role"), "EvalDecision": "allowed",
             "MatchedStatements": [{"SourcePolicyId": "PassRoleEC2"}],
             "PermissionsBoundaryDecisionDetail": {"AllowedByPermissionsBoundary": True}}], "IsTruncated": False},
            {"PolicySourceArn": arn("user", "carol"), "ActionNames": ["iam:PassRole"],
             "ResourceArns": [arn("role", "admin-role")]})
        res = simulate_principal(iam, arn("user", "carol"), ["iam:PassRole"], arn("role", "admin-role"))
    assert res[0]["decision"] == ALLOWED and res[0]["allowed_by_boundary"] is True
    assert compare(ALLOWED, res[0]) == "match" and compare(DENIED, res[0]) == "mismatch"
    assert compare(INDETERMINATE, res[0]) == "shieldiq-indeterminate"


def test_least_disruptive_change_breaks_the_chain_at_the_iam_permission():
    from shieldiq.iam.remediation import propose
    prev = propose(lab(), arn("user", "carol"), "AWS-IAM-007")
    after = prev["changes"][0]["after"]
    acts = [a for s in after["Statement"] for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])]
    assert "ec2:RunInstances" in acts and "iam:PassRole" not in acts  # launch rights kept, PassRole removed


def test_emptied_policy_is_removed_not_published_empty(demo):
    from shieldiq.models import Finding
    from shieldiq.services import iam_service
    integ, _ = _lab_integration(demo)
    f = Finding.query.filter_by(integration_id=integ.id, rule_id="AWS-IAM-007", resource_id=arn("user", "grace")).one()
    rem = iam_service.preview(f, "a@x")
    ch = rem.steps["changes"][0]
    assert ch["remove_policy"] is True and rem.steps["validation"]["ok"]
    assert any("detach-user-policy" in i for i in rem.steps["instructions"])
    iam_service.approve(f, rem.id, "a@x", "grace")
    rem = iam_service.apply(f, rem.id, "a@x")
    assert rem.status == "verified"
    grace = next(u for u in integ.snapshot["iam"]["users"] if u["name"] == "grace")
    assert grace["attached"] == []


def test_full_admin_preview_removes_the_wildcard_statement_without_fake_actions(demo):
    from shieldiq.iam.remediation import propose
    prev = propose(lab(), arn("user", "alice"), "AWS-IAM-005")
    ch = prev["changes"][0]
    assert ch["remove_policy"] is True and ch["denied_by_guard"] == []
    assert not any(i["action"].startswith("shieldiq-probe") for i in prev["impact"])
    assert prev["validation"]["admin_after"] == DENIED and prev["validation"]["resolved_in_model"]
    assert "practically anything" in prev["risk"]
