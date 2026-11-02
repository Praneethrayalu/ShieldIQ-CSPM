"""LIVE AWS validation - isolated test account only. SKIPPED unless explicitly enabled:

    export SHIELDIQ_LIVE_AWS_VALIDATION=1
    export SHIELDIQ_VALIDATION_ACCOUNT=<12-digit dedicated test account id>
    export AWS_PROFILE=<profile for that account, with validation/policies/* attached>
    pytest tests/integration -v

It runs: guard -> setup (creates siqv-* resources under /shieldiq-validation/, no credentials) -> ShieldIQ scan ->
iam:SimulatePrincipalPolicy comparison -> report (validation/out-live/) -> cleanup. It never runs in CI by default and
has NOT been executed by the v2.3 author (no AWS account was available).
"""
import os
import sys

import pytest

ENABLED = os.getenv("SHIELDIQ_LIVE_AWS_VALIDATION") == "1" and os.getenv("SHIELDIQ_VALIDATION_ACCOUNT") \
    and os.getenv("AWS_PROFILE")
pytestmark = pytest.mark.skipif(not ENABLED, reason="live AWS validation not enabled (see module docstring)")

VAL = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "validation")
sys.path.insert(0, VAL)


def test_live_validation_cycle():
    import boto3
    import shieldiq_validate as kit
    acct = os.environ["SHIELDIQ_VALIDATION_ACCOUNT"]
    s = boto3.Session(profile_name=os.environ["AWS_PROFILE"], region_name=os.getenv("AWS_REGION", "us-east-1"))
    kit.guard(s, acct)
    cases = kit.load_cases(acct)
    iam = s.client("iam")
    try:
        kit.setup(iam, cases, acct, apply=True)
        import time
        time.sleep(int(os.getenv("SHIELDIQ_VALIDATION_SETTLE_SECONDS", "20")))  # IAM is eventually consistent
        meta = kit.report(kit.run(s, cases), "live", os.path.join(VAL, "out-live"))
    finally:
        kit.cleanup(iam, apply=True)
    assert meta["passed"] == meta["total"], f"see {os.path.join(VAL, 'out-live', 'validation_report.md')}"
