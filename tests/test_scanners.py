from pathlib import Path

import pytest

from shieldiq.collectors import CollectorError, validate_snapshot
from shieldiq.collectors.iac import parse_any, parse_kubernetes, parse_terraform
from shieldiq.rules import evaluate
from shieldiq.rules.code import mask, scan_text
from shieldiq.seed import sample_leaky_code

SAMPLES = Path(__file__).resolve().parent.parent / "shieldiq" / "sample_data" / "uploads"


def failed_ids(provider, inv):
    return {ev.rule.id for ev in evaluate(provider, inv) for _ in ev.failed}


def test_terraform_sample():
    inv = parse_terraform((SAMPLES / "main.tf").read_text())
    ids = failed_ids("aws", inv)
    assert {"AWS-S3-001", "AWS-EC2-001", "AWS-EC2-003", "AWS-EC2-004", "AWS-RDS-001", "AWS-RDS-002",
            "AWS-RDS-003", "AWS-KMS-001"} <= ids


def test_terraform_secure_config_passes():
    tf = '''
resource "aws_s3_bucket" "ok" { bucket = "ok-bucket" }
resource "aws_s3_bucket_public_access_block" "ok" {
  bucket = aws_s3_bucket.ok.id
  block_public_acls = true
  ignore_public_acls = true
  block_public_policy = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_versioning" "ok" {
  bucket = aws_s3_bucket.ok.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
    inv = parse_terraform(tf)
    assert failed_ids("aws", inv) == set()


def test_terraform_public_policy_and_acl():
    tf = '''
resource "aws_s3_bucket" "b" { bucket = "pub" }
resource "aws_s3_bucket_acl" "b" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read"
}
'''
    assert "AWS-S3-002" in failed_ids("aws", parse_terraform(tf))


def test_kubernetes_sample():
    inv = parse_kubernetes((SAMPLES / "deployment.yaml").read_text())
    ids = failed_ids("kubernetes", inv)
    assert {"K8S-001", "K8S-003", "K8S-005", "K8S-006", "K8S-007", "K8S-008", "K8S-009"} <= ids


def test_kubernetes_hardened_pod_passes():
    y = """
apiVersion: v1
kind: Pod
metadata: {name: ok, namespace: apps}
spec:
  securityContext: {runAsNonRoot: true}
  containers:
    - name: app
      image: acme/app:1.2.3
      resources: {limits: {cpu: 100m, memory: 64Mi}}
      env: [{name: DB_PASSWORD, valueFrom: {secretKeyRef: {name: db, key: pw}}}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny, namespace: apps}
spec: {podSelector: {}}
"""
    assert failed_ids("kubernetes", parse_kubernetes(y)) == set()


@pytest.mark.parametrize("bad", ["resource {{{", "this is not hcl ="])
def test_terraform_parse_errors_are_clean(bad):
    with pytest.raises(CollectorError):
        parse_terraform(bad)


def test_parse_any_rejects_unknown_types():
    with pytest.raises(CollectorError):
        parse_any("notes.docx", "x")
    with pytest.raises(CollectorError):
        parse_kubernetes("key: [unclosed")


def test_secret_detectors():
    hits = scan_text("settings.py", sample_leaky_code())
    types = {h["type"] for h in hits}
    assert {"AWS Access Key ID", "AWS Secret Access Key", "GitHub Token", "Database URL with password",
            "Private Key"} <= types
    assert any(h["type"] == "Hard-coded password" for h in hits)
    # values are masked, never returned in full
    assert all("ZT4M2N8QW5R7Y6PX" not in h["match"] for h in hits)
    # the os.getenv line is not flagged
    assert not any(h["line"] == 10 for h in hits)


def test_secret_placeholders_and_low_entropy_ignored():
    text = 'password = "changeme123"\napi_key = "your-api-key"\npassword = "aaaaaaaa"\ntoken = os.getenv("T")\n'
    assert scan_text("x.py", text) == []


def test_mask():
    assert mask("ABCDEFGHIJKLMNOP").startswith("ABCD") and mask("ABCDEFGHIJKLMNOP").endswith("MNOP")
    assert "*" in mask("short")


def test_snapshot_validation():
    assert validate_snapshot("aws", {"s3_buckets": []}) == {"s3_buckets": []}
    with pytest.raises(CollectorError):
        validate_snapshot("aws", ["not", "a", "dict"])
    with pytest.raises(CollectorError):
        validate_snapshot("aws", {"random": 1})
    with pytest.raises(CollectorError):
        validate_snapshot("aws", {"s3_buckets": "nope"})


def test_crlf_line_endings_parse():
    """Browsers post <textarea> content with CRLF, and Windows editors save files that way."""
    tf = (SAMPLES / "main.tf").read_text().replace("\n", "\r\n")
    provider, inv = parse_any("pasted.tf", tf)
    assert provider == "aws" and failed_ids("aws", inv)
    yml = (SAMPLES / "deployment.yaml").read_text().replace("\n", "\r\n")
    provider, inv = parse_any("pasted.yaml", yml)
    assert provider == "kubernetes" and failed_ids("kubernetes", inv)
