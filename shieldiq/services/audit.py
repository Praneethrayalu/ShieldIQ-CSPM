from flask import has_request_context

from ..extensions import db
from ..models import AuditLog


def log(org_id, user_email, action, target="", detail=""):
    ip = None
    if has_request_context():
        from ..security import client_ip
        ip = client_ip()
    db.session.add(AuditLog(org_id=org_id, user_email=user_email, action=action, target=str(target)[:255],
                            detail=str(detail)[:2000] if detail else None, ip=ip))
