"""Database models. Every tenant-owned row carries org_id (multi-tenant isolation)."""
import hashlib
import json
import secrets
from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}
ROLES = ["admin", "analyst", "viewer"]
FINDING_STATUSES = ["open", "in_progress", "resolved", "accepted"]


class JSONText(db.TypeDecorator):
    impl = db.Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else json.dumps(value)

    def process_result_value(self, value, dialect):
        return None if value is None else json.loads(value)


class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    # alert settings
    alert_min_severity = db.Column(db.String(10), default="high")
    alert_score_drop = db.Column(db.Integer, default=5)
    slack_webhook_enc = db.Column(db.Text)  # encrypted
    alert_email = db.Column(db.String(255))
    github_repo = db.Column(db.String(200))  # owner/repo for remediation PRs
    github_token_enc = db.Column(db.Text)  # encrypted


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="admin", nullable=False)
    is_active_user = db.Column(db.Boolean, default=True)
    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    last_login_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow)
    theme = db.Column(db.String(10), default="light")

    org = db.relationship("Organization")

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)

    @property
    def is_active(self):
        return bool(self.is_active_user)

    def can(self, action):
        """RBAC: admin > analyst > viewer."""
        rules = {
            "view": {"admin", "analyst", "viewer"},
            "scan": {"admin", "analyst"},
            "triage": {"admin", "analyst"},
            "remediate": {"admin", "analyst"},
            "report": {"admin", "analyst"},
            "integrate": {"admin"},
            "admin": {"admin"},
        }
        return self.role in rules.get(action, set())

    @property
    def initials(self):
        parts = [p for p in self.full_name.split() if p]
        return ("".join(p[0] for p in parts[:2]) or self.email[0]).upper()


class ApiToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    prefix = db.Column(db.String(12), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    last_used_at = db.Column(db.DateTime)
    user = db.relationship("User")

    @staticmethod
    def hash(raw):
        return hashlib.sha256(raw.encode()).hexdigest()

    @classmethod
    def issue(cls, user, name):
        raw = "siq_" + secrets.token_urlsafe(32)
        tok = cls(user_id=user.id, name=name, token_hash=cls.hash(raw), prefix=raw[:10])
        db.session.add(tok)
        return tok, raw


class RateBucket(db.Model):
    """Fixed-window rate-limit counter (per key, e.g. 'login:1.2.3.4')."""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(150), nullable=False, index=True)
    window_start = db.Column(db.DateTime, nullable=False)
    count = db.Column(db.Integer, nullable=False, default=0)


class Integration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False, index=True)
    provider = db.Column(db.String(20), nullable=False)  # aws gcp azure github slack kubernetes
    name = db.Column(db.String(120), nullable=False)
    mode = db.Column(db.String(20), nullable=False, default="demo")  # demo | snapshot | upload | live
    config = db.Column(JSONText, default=dict)  # non-secret settings
    secret_enc = db.Column(db.Text)  # encrypted credentials JSON (live mode)
    snapshot = db.Column(JSONText)  # latest inventory (demo / snapshot / upload / live)
    check_stats = db.Column(JSONText)  # {rule_id: {"total": n, "failed": m}} from the latest scan
    status = db.Column(db.String(20), default="connected")
    last_error = db.Column(db.Text)
    last_scan_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow)


class ScanRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False, index=True)
    integration_id = db.Column(db.Integer, db.ForeignKey("integration.id"))
    source = db.Column(db.String(40), nullable=False)  # integration | iac | kubernetes | secrets | all
    started_at = db.Column(db.DateTime, default=utcnow)
    finished_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="running")
    checks_run = db.Column(db.Integer, default=0)
    checks_failed = db.Column(db.Integer, default=0)
    new_findings = db.Column(db.Integer, default=0)
    resolved_findings = db.Column(db.Integer, default=0)
    posture_score = db.Column(db.Integer)
    critical = db.Column(db.Integer, default=0)
    high = db.Column(db.Integer, default=0)
    medium = db.Column(db.Integer, default=0)
    low = db.Column(db.Integer, default=0)
    error = db.Column(db.Text)
    triggered_by = db.Column(db.String(255))

    integration = db.relationship("Integration")

    __table_args__ = (
        # Database-level guarantee: never two scans running for one integration at the same time.
        db.Index("uq_scanrun_running", "integration_id", unique=True,
                 sqlite_where=db.text("status = 'running'")),
    )


class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False, index=True)
    integration_id = db.Column(db.Integer, db.ForeignKey("integration.id"), index=True)
    source = db.Column(db.String(40), default="integration")
    rule_id = db.Column(db.String(40), nullable=False, index=True)
    provider = db.Column(db.String(20), nullable=False)
    service = db.Column(db.String(40), nullable=False)
    resource_id = db.Column(db.String(255), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    detail = db.Column(db.Text)
    severity = db.Column(db.String(10), nullable=False, index=True)
    status = db.Column(db.String(20), default="open", index=True)
    status_note = db.Column(db.Text)
    fingerprint = db.Column(db.String(64), nullable=False, index=True)
    __table_args__ = (db.UniqueConstraint("integration_id", "fingerprint", name="uq_finding_fingerprint"),)
    first_seen = db.Column(db.DateTime, default=utcnow)
    last_seen = db.Column(db.DateTime, default=utcnow)
    resolved_at = db.Column(db.DateTime)
    evidence = db.Column(JSONText)

    integration = db.relationship("Integration")

    @property
    def is_active(self):
        return self.status in ("open", "in_progress")

    def to_dict(self):
        return {
            "id": self.id, "rule_id": self.rule_id, "provider": self.provider, "service": self.service,
            "resource_id": self.resource_id, "title": self.title, "detail": self.detail,
            "severity": self.severity, "status": self.status, "status_note": self.status_note,
            "source": self.source, "integration_id": self.integration_id,
            "first_seen": self.first_seen.isoformat() + "Z" if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() + "Z" if self.last_seen else None,
            "resolved_at": self.resolved_at.isoformat() + "Z" if self.resolved_at else None,
            "evidence": self.evidence or {},
        }


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False, index=True)
    kind = db.Column(db.String(30), nullable=False)  # new_finding | score_drop | scan_failed | remediation
    severity = db.Column(db.String(10), default="medium")
    title = db.Column(db.String(255), nullable=False)
    body = db.Column(db.Text)
    finding_id = db.Column(db.Integer, db.ForeignKey("finding.id"))
    created_at = db.Column(db.DateTime, default=utcnow)
    read = db.Column(db.Boolean, default=False)
    delivered = db.Column(JSONText)  # {"slack": "sent"|"error ..", "email": ...}


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), index=True)
    user_email = db.Column(db.String(255))
    action = db.Column(db.String(60), nullable=False)
    target = db.Column(db.String(255))
    detail = db.Column(db.Text)
    ip = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=utcnow, index=True)


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    framework = db.Column(db.String(20))
    created_by = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=utcnow)
    filename = db.Column(db.String(255), nullable=False)
    posture_score = db.Column(db.Integer)
    finding_count = db.Column(db.Integer)


class Remediation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False, index=True)
    finding_id = db.Column(db.Integer, db.ForeignKey("finding.id"))
    mode = db.Column(db.String(20))  # demo_apply | script | github_pr
    status = db.Column(db.String(20))  # verified | failed | generated | pr_opened
    steps = db.Column(JSONText)
    output = db.Column(db.Text)
    pr_url = db.Column(db.String(500))
    executed_by = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=utcnow)
