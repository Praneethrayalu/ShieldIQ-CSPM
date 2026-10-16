"""In-app alerts with optional Slack webhook / SMTP email delivery (graceful when not configured)."""
import smtplib
from email.message import EmailMessage

import requests
from flask import current_app

from ..extensions import db
from ..models import SEVERITIES, Alert
from ..security import decrypt


def _deliver(org, alert):
    out = {}
    webhook = decrypt(org.slack_webhook_enc) or current_app.config.get("SLACK_WEBHOOK_URL")
    if webhook:
        try:
            r = requests.post(webhook, json={"text": f":shield: *ShieldIQ* [{alert.severity.upper()}] {alert.title}\n{alert.body or ''}"},
                              timeout=8)
            out["slack"] = "sent" if r.status_code < 300 else f"error {r.status_code}"
        except requests.RequestException as exc:
            out["slack"] = f"error {exc.__class__.__name__}"
    cfg = current_app.config
    if org.alert_email and cfg.get("SMTP_HOST"):
        try:
            msg = EmailMessage()
            msg["Subject"] = f"[ShieldIQ] {alert.title}"
            msg["From"] = cfg.get("SMTP_FROM") or cfg.get("SMTP_USER")
            msg["To"] = org.alert_email
            msg.set_content(alert.body or alert.title)
            with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10) as s:
                s.starttls()
                if cfg.get("SMTP_USER"):
                    s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
                s.send_message(msg)
            out["email"] = "sent"
        except Exception as exc:
            out["email"] = f"error {exc.__class__.__name__}"
    return out


def raise_alert(org, kind, title, body="", severity="medium", finding_id=None, deliver=True):
    a = Alert(org_id=org.id, kind=kind, title=title[:255], body=body, severity=severity, finding_id=finding_id)
    db.session.add(a)
    if deliver:
        a.delivered = _deliver(org, a) or None
    return a


def severity_at_least(sev, threshold):
    return SEVERITIES.index(sev) <= SEVERITIES.index(threshold or "high")
