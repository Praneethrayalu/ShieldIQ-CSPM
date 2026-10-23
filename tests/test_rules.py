import copy

import pytest

from shieldiq.collectors import demo_inventory
from shieldiq.models import SEVERITIES
from shieldiq.rules import RULES, evaluate, rules_for
from shieldiq.services.compliance import rule_controls

PROVIDERS = ["aws", "gcp", "azure", "github", "slack", "kubernetes"]


def test_rule_catalog_is_complete():
    assert len(RULES) >= 60
    for r in RULES.values():
        assert r.severity in SEVERITIES, r.id
        assert r.title and r.root_cause and r.impact and r.steps, r.id
        assert r.cli or r.terraform, r.id
        assert r.fix is not None, f"{r.id} has no auto-fix"
        assert rule_controls(r), f"{r.id} maps to no compliance control"


@pytest.mark.parametrize("provider", PROVIDERS)
def test_demo_inventory_has_failures_and_passes(provider):
    evs = evaluate(provider, demo_inventory(provider))
    results = [res for ev in evs for res in ev.results]
    assert any(not r.passed for r in results), "demo should contain misconfigurations"
    assert any(r.passed for r in results), "demo should contain compliant resources too"


@pytest.mark.parametrize("provider", PROVIDERS)
def test_every_fixer_makes_its_check_pass(provider):
    base = demo_inventory(provider)
    checked = 0
    for ev in evaluate(provider, base):
        for res in ev.failed:
            inv = copy.deepcopy(base)
            assert ev.rule.fix(inv, res.resource_id), f"{ev.rule.id} could not fix {res.resource_id}"
            after = {r.resource_id: r.passed for r in ev.rule.check(inv)}
            assert after.get(res.resource_id, True), f"{ev.rule.id} still failing on {res.resource_id}"
            checked += 1
    assert checked > 0


def test_specific_aws_detections():
    failed = {(ev.rule.id, r.resource_id) for ev in evaluate("aws", demo_inventory("aws")) for r in ev.failed}
    assert ("AWS-S3-001", "arn:aws:s3:::acme-customer-exports") in failed
    assert ("AWS-EC2-001", "sg-0a1b2c3d4e5f60001") in failed
    assert ("AWS-RDS-001", "acme-analytics-db") in failed
    assert ("AWS-IAM-001", "arn:aws:iam::123456789012:root") in failed
    # compliant resources must not be flagged
    assert ("AWS-S3-001", "arn:aws:s3:::acme-db-backups") not in failed
    assert ("AWS-EC2-001", "sg-0a1b2c3d4e5f60002") not in failed  # 443 only
    assert ("AWS-EC2-003", "i-0web5c1e2d3f4a5b6") not in failed  # IMDSv2 required


def test_sg_port_range_and_ipv6():
    inv = {"security_groups": [{"id": "sg-1", "ingress": [{"protocol": "tcp", "from": 20, "to": 30, "cidr": "::/0"}]},
                               {"id": "sg-2", "ingress": [{"protocol": "tcp", "from": 22, "to": 22, "cidr": "10.0.0.0/8"}]}]}
    rule = RULES["AWS-EC2-001"]
    res = {r.resource_id: r.passed for r in rule.check(inv)}
    assert res == {"sg-1": False, "sg-2": True}


def test_broken_inventory_never_crashes_engine():
    for p in PROVIDERS:
        evaluate(p, {"unexpected": True})
        evaluate(p, {})
    assert rules_for("aws")
