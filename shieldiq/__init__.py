"""ShieldIQ - cloud security posture management (CSPM) platform."""
import logging
import os

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from .config import Config
from .extensions import csrf, db, login_manager

__version__ = "2.3.0"


def create_app(config_class=Config, **overrides):
    load_dotenv()
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_class)
    app.config.update(overrides)
    config_class.finalize(app)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"

    from .models import User

    @login_manager.user_loader
    def load_user(uid):
        # Flask-Login does not re-check is_active when it restores a session, so a disabled user's existing
        # session (or remember-me cookie) would keep working. Returning None ends it on the next request.
        try:
            user = db.session.get(User, int(uid))
        except (TypeError, ValueError):
            return None
        if user is None or not user.is_active:
            return None
        return user

    from .api import bp as api_bp
    from .auth import bp as auth_bp
    from .views import bp as views_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(views_bp)
    app.register_blueprint(api_bp)
    csrf.exempt(api_bp)  # the API does its own CSRF check for cookie sessions (see api.py)

    from .filters import register_filters
    register_filters(app)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                "script-src 'self'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                                "base-uri 'self'; form-action 'self'")
        return resp

    def _err(code, title, msg):
        if request.path.startswith("/api/"):
            return jsonify(error=title), code
        return render_template("error.html", code=code, title=title, message=msg), code

    app.register_error_handler(403, lambda e: _err(403, "Forbidden", "Your role does not allow this action."))
    app.register_error_handler(404, lambda e: _err(404, "Not found", "That page or item does not exist."))
    app.register_error_handler(413, lambda e: _err(413, "File too large", "Uploads are limited to 2 MB."))
    app.register_error_handler(500, lambda e: _err(500, "Something went wrong", "The error was logged."))

    from flask_wtf.csrf import CSRFError
    app.register_error_handler(CSRFError, lambda e: _err(400, "Session expired", "Please reload the page and try again."))

    with app.app_context():
        db.create_all()
        if app.config.get("SEED_DEMO") and not os.getenv("SHIELDIQ_SKIP_SEED"):
            from .seed import seed_demo
            seed_demo()

    from .cli import register_cli
    register_cli(app)
    return app
