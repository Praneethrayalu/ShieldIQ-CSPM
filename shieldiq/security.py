"""App-level security helpers: field encryption, login throttling, password policy, RBAC decorator."""
import json
import re
from datetime import timedelta
from functools import wraps

from cryptography.fernet import Fernet, InvalidToken
from flask import abort, current_app, jsonify, request
from flask_login import current_user

from .extensions import db
from .models import utcnow


def _cipher():
    return Fernet(current_app.config["ENCRYPTION_KEY"].encode())


def encrypt(value) -> str:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        value = json.dumps(value)
    return _cipher().encrypt(value.encode()).decode()


def decrypt(token, as_json=False):
    if not token:
        return {} if as_json else None
    try:
        raw = _cipher().decrypt(token.encode()).decode()
    except InvalidToken:
        return {} if as_json else None
    return json.loads(raw) if as_json else raw


PASSWORD_RULES = "At least 10 characters, with an uppercase letter, a lowercase letter and a number."


def password_problems(pw: str):
    problems = []
    if len(pw or "") < 10:
        problems.append("at least 10 characters")
    if not re.search(r"[A-Z]", pw or ""):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", pw or ""):
        problems.append("a lowercase letter")
    if not re.search(r"\d", pw or ""):
        problems.append("a number")
    return problems


EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[A-Za-z]{2,24}$")


def valid_email(e):
    return bool(EMAIL_RE.match(e or ""))


def register_failed_login(user):
    user.failed_logins = (user.failed_logins or 0) + 1
    if user.failed_logins >= current_app.config["LOGIN_MAX_ATTEMPTS"]:
        user.locked_until = utcnow() + timedelta(seconds=current_app.config["LOGIN_LOCKOUT_SECONDS"])
        user.failed_logins = 0


def is_locked(user):
    return bool(user.locked_until and user.locked_until > utcnow())


def requires(action):
    """RBAC decorator for views and API endpoints."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not current_user.is_authenticated:
                abort(401)
            if not current_user.can(action):
                if request.path.startswith("/api/"):
                    return jsonify(error=f"Your role ({current_user.role}) cannot perform '{action}'"), 403
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


def hit_rate(key, limit, window_seconds):
    """Fixed-window rate limiter. Returns True if this hit is allowed, False when the window is full.
    Keyed rows are small and self-cleaning: an expired window resets the same row."""
    from .models import RateBucket, utcnow
    now = utcnow()
    b = RateBucket.query.filter_by(key=key).first()
    if b is None or (now - b.window_start).total_seconds() >= window_seconds:
        if b is None:
            db.session.add(RateBucket(key=key, window_start=now, count=1))
        else:
            b.window_start, b.count = now, 1
        db.session.commit()
        return True
    b.count += 1
    db.session.commit()
    return b.count <= limit


def client_ip():
    from flask import current_app
    if current_app.config.get("TRUST_PROXY_HEADERS"):
        fwd = request.headers.get("X-Forwarded-For")
        if fwd:
            return fwd.split(",")[0].strip()[:64]
    return (request.remote_addr or "")[:64]
