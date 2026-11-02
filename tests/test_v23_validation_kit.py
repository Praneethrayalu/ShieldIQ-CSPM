"""v2.3 validation kit (validation/): safety guards, dry runs, setup -> run -> report -> cleanup against the in-memory
mock. The mock's simulator answers are the documented expectations from cases.json - this proves the kit's plumbing,
NOT agreement with real AWS (that needs the live run in tests/integration/)."""
import json
import os
import sys

import pytest

VAL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "validation")
sys.path.insert(0, VAL)

import mock_aws  # noqa: E402
import shieldiq_validate as kit  # noqa: E402

ACCT = "000000000000"


def session():
    return mock_aws.MockSession(ACCT, kit.load_cases(ACCT))


def test_full_mock_cycle_passes_and_cleans_up(tmp_path):
    meta, result = kit.mock_cycle(str(tmp_path), log=lambda *_: None)
    assert meta["passed"] == meta["total"] == len(kit.load_cases(ACCT)["checks"])
    assert meta["cleanup_left"] == {"users": 0, "groups": 0, "roles": 0, "policies": 0}
    md = (tmp_path / "validation_report.md").read_text()
    assert "LIVE AWS VALIDATION NOT EXECUTED" in md and "| D09 |" in md and "## Limitations" in md
    data = json.loads((tmp_path / "validation_report.json").read_text())
    kinds = {r["polarity"] for r in data["rows"]}
    assert {"positive", "negative", "uncertain"} <= kinds
    d09 = next(r for r in data["rows"] if r["id"] == "D09")
    assert d09["actual"] == "Indeterminate" and d09["comparison"] == "shieldiq-indeterminate"


def test_report_flags_a_mismatch(tmp_path):
    s = session()
    cases = kit.load_cases(ACCT)
    kit.setup(s.client("iam"), cases, ACCT, apply=True, log=lambda *_: None)
    bad = json.loads(json.dumps(cases))
    next(c for c in bad["checks"] if c["id"] == "D03")["expected"] = "Allowed"  # wrong expectation on purpose
    res = kit.run(s, bad)
    row = next(r for r in res["rows"] if r["id"] == "D03")
    assert row["result"] == "FAIL" and row["actual"] == "Denied"


@pytest.mark.parametrize("env,account,msg", [
    ({}, ACCT, "SHIELDIQ_VALIDATION_ACCOUNT"),
    ({"SHIELDIQ_VALIDATION_ACCOUNT": "111111111111"}, "111111111111", "not 111111111111"),
    ({"SHIELDIQ_VALIDATION_ACCOUNT": ACCT}, "12", "12-digit"),
])
def test_guards_refuse_unconfirmed_or_wrong_accounts(env, account, msg):
    with pytest.raises(kit.GuardError, match=msg):
        kit.guard(session(), account, env=env)


def test_guard_refuses_management_account_and_prod_alias(monkeypatch):
    s = session()
    monkeypatch.setattr(mock_aws._Generic, "describe_organization",
                        lambda self: {"Organization": {"MasterAccountId": ACCT}})
    with pytest.raises(kit.GuardError, match="management account"):
        kit.guard(s, ACCT, env={"SHIELDIQ_VALIDATION_ACCOUNT": ACCT})
    monkeypatch.undo()
    monkeypatch.setattr(mock_aws.MockIAM, "list_account_aliases", lambda self: {"AccountAliases": ["acme-prod"]})
    with pytest.raises(kit.GuardError, match="production"):
        kit.guard(session(), ACCT, env={"SHIELDIQ_VALIDATION_ACCOUNT": ACCT})


def test_setup_and_cleanup_are_dry_runs_by_default():
    s = session()
    lines = []
    kit.setup(s.client("iam"), kit.load_cases(ACCT), ACCT, apply=False, log=lines.append)
    assert not s.state.users and not s.state.policies and any("Dry run" in x for x in lines)
    kit.setup(s.client("iam"), kit.load_cases(ACCT), ACCT, apply=True, log=lambda *_: None)
    actions, _ = kit.cleanup(s.client("iam"), apply=False, log=lambda *_: None)
    assert actions and len(s.state.users) == 8  # nothing deleted in dry run


def test_cleanup_never_touches_untagged_or_out_of_path_resources():
    s = session()
    iam = s.client("iam")
    kit.setup(iam, kit.load_cases(ACCT), ACCT, apply=True, log=lambda *_: None)
    iam.create_user(UserName="prod-admin", Path="/")                                   # outside the path
    iam.create_user(UserName="siqv-untagged", Path="/shieldiq-validation/", Tags=[])    # in path, no tag
    _, skipped = kit.cleanup(iam, apply=True, log=lambda *_: None)
    assert set(s.state.users) == {"prod-admin", "siqv-untagged"}
    assert any("siqv-untagged" in x for x in skipped)


def test_no_credentials_are_ever_created():
    s = session()
    kit.setup(s.client("iam"), kit.load_cases(ACCT), ACCT, apply=True, log=lambda *_: None)
    assert not any(c in s.state.calls for c in ("create_access_key", "create_login_profile"))
    with open(os.path.join(VAL, "policies", "shieldiq-validation-setup-policy.json")) as fh:
        pol = json.load(fh)
    deny = next(st for st in pol["Statement"] if st["Sid"] == "NeverCreateCredentials")
    assert deny["Effect"] == "Deny" and "iam:CreateAccessKey" in deny["Action"]
    trusts = [r["trust"] for r in kit.load_cases(ACCT)["roles"]]
    for t in trusts:
        principal = t["Statement"][0]["Principal"]
        assert "Service" in principal or all("/shieldiq-validation/" in p for p in
                                             ([principal["AWS"]] if isinstance(principal["AWS"], str) else principal["AWS"]))
