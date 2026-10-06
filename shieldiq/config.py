"""ShieldIQ configuration.

Everything has a safe default so the app runs out of the box. Secrets that are
not provided are generated once and stored in the instance/ folder (never in git).
"""
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent.parent

try:  # optional .env next to run.py (real environment variables win)
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except ImportError:  # pragma: no cover
    pass


def _persistent_secret(instance_dir: Path, name: str, factory) -> str:
    """Return a secret from instance/<name>, creating it on first run."""
    instance_dir.mkdir(parents=True, exist_ok=True)
    path = instance_dir / name
    if path.exists():
        return path.read_text().strip()
    value = factory()
    path.write_text(value)
    try:
        os.chmod(path, 0o600)
    except OSError:  # Windows
        pass
    return value


class Config:
    INSTANCE_DIR = Path(os.getenv("SHIELDIQ_INSTANCE_DIR", BASE_DIR / "instance"))

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB uploads
    # Set SHIELDIQ_TRUST_PROXY=1 only when running behind a reverse proxy that sets X-Forwarded-For.
    TRUST_PROXY_HEADERS = os.getenv("SHIELDIQ_TRUST_PROXY", "").lower() in ("1", "true", "yes")
    WTF_CSRF_TIME_LIMIT = None

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SHIELDIQ_SECURE_COOKIES", "0") == "1"
    REMEMBER_COOKIE_HTTPONLY = True

    # Login protection
    LOGIN_MAX_ATTEMPTS = int(os.getenv("SHIELDIQ_LOGIN_MAX_ATTEMPTS", "5"))
    # Per-network throttles, on top of the per-account lockout above.
    LOGIN_IP_MAX_ATTEMPTS = int(os.getenv("SHIELDIQ_LOGIN_IP_MAX_ATTEMPTS", "30"))
    LOGIN_IP_WINDOW_SECONDS = int(os.getenv("SHIELDIQ_LOGIN_IP_WINDOW_SECONDS", "300"))
    REGISTER_IP_MAX_ATTEMPTS = int(os.getenv("SHIELDIQ_REGISTER_IP_MAX_ATTEMPTS", "10"))
    REGISTER_IP_WINDOW_SECONDS = int(os.getenv("SHIELDIQ_REGISTER_IP_WINDOW_SECONDS", "3600"))
    LOGIN_LOCKOUT_SECONDS = int(os.getenv("SHIELDIQ_LOGIN_LOCKOUT_SECONDS", "300"))

    # Optional integrations (all free / optional)
    LLM_API_KEY = os.getenv("SHIELDIQ_LLM_API_KEY") or os.getenv("OPENAI_API_KEY", "")
    LLM_BASE_URL = os.getenv("SHIELDIQ_LLM_BASE_URL", "https://api.openai.com/v1")
    LLM_MODEL = os.getenv("SHIELDIQ_LLM_MODEL", "gpt-4o-mini")
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
    SLACK_WEBHOOK_URL = os.getenv("SHIELDIQ_SLACK_WEBHOOK_URL", "")
    SMTP_HOST = os.getenv("SHIELDIQ_SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SHIELDIQ_SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SHIELDIQ_SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SHIELDIQ_SMTP_PASSWORD", "")
    SMTP_FROM = os.getenv("SHIELDIQ_SMTP_FROM", "")

    SEED_DEMO = os.getenv("SHIELDIQ_SEED_DEMO", "1") == "1"

    @classmethod
    def finalize(cls, app):
        inst = Path(app.config["INSTANCE_DIR"])
        inst.mkdir(parents=True, exist_ok=True)
        app.config.setdefault("SQLALCHEMY_DATABASE_URI",
                              os.getenv("DATABASE_URL", f"sqlite:///{inst / 'shieldiq.db'}"))
        app.config["SECRET_KEY"] = os.getenv("SHIELDIQ_SECRET_KEY") or app.config.get("SECRET_KEY") or \
            _persistent_secret(inst, "secret_key", lambda: secrets.token_urlsafe(48))
        key = os.getenv("SHIELDIQ_ENCRYPTION_KEY") or app.config.get("ENCRYPTION_KEY")
        if key:
            try:
                Fernet(key.encode())  # validate early with a clear error (the original app crashed here)
            except (ValueError, TypeError):
                raise ValueError("SHIELDIQ_ENCRYPTION_KEY is not a valid Fernet key. Leave it empty to auto-generate one, "
                                 "or create one with: python -c \"from cryptography.fernet import Fernet; "
                                 "print(Fernet.generate_key().decode())\"") from None
        else:
            key = _persistent_secret(inst, "encryption_key", lambda: Fernet.generate_key().decode())
        app.config["ENCRYPTION_KEY"] = key
        app.config.setdefault("REPORTS_DIR", str(inst / "reports"))
        Path(app.config["REPORTS_DIR"]).mkdir(parents=True, exist_ok=True)


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SEED_DEMO = False
    # Tests post login/register repeatedly; keep the per-IP windows effectively open.
    LOGIN_IP_MAX_ATTEMPTS = 10**9
    REGISTER_IP_MAX_ATTEMPTS = 10**9
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    LLM_API_KEY = ""
    GITHUB_TOKEN = ""
    SLACK_WEBHOOK_URL = ""
    SMTP_HOST = ""
