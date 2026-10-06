from urllib.parse import urlparse

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from .extensions import db
from .models import Organization, User, utcnow
from .security import (PASSWORD_RULES, client_ip, hit_rate, is_locked, password_problems,
                       register_failed_login, valid_email)
from .services import audit

bp = Blueprint("auth", __name__)


def _safe_next(target):
    if not target:
        return None
    p = urlparse(target)
    return target if not p.netloc and not p.scheme and target.startswith("/") else None


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("views.dashboard"))
    if request.method == "POST":
        if not hit_rate(f"login:{client_ip()}", current_app.config["LOGIN_IP_MAX_ATTEMPTS"],
                        current_app.config["LOGIN_IP_WINDOW_SECONDS"]):
            flash("Too many login attempts from this network. Wait a few minutes and try again.", "error")
            return render_template("auth/login.html"), 429
        email = (request.form.get("email") or "").strip().lower()
        pw = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()
        generic = "Invalid email or password."
        if user and is_locked(user):
            flash("Too many failed attempts. This account is locked for a few minutes.", "error")
            audit.log(user.org_id, email, "auth.locked_attempt", email)
            db.session.commit()
            return render_template("auth/login.html", email=email), 429
        if not user or not user.check_password(pw) or not user.is_active:
            if user:
                register_failed_login(user)
                audit.log(user.org_id, email, "auth.failed_login", email)
                db.session.commit()
            flash(generic, "error")
            return render_template("auth/login.html", email=email), 401
        user.failed_logins, user.locked_until, user.last_login_at = 0, None, utcnow()
        login_user(user, remember=bool(request.form.get("remember")))
        audit.log(user.org_id, email, "auth.login", email)
        db.session.commit()
        return redirect(_safe_next(request.args.get("next")) or url_for("views.dashboard"))
    return render_template("auth/login.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("views.dashboard"))
    form = request.form
    if request.method == "POST":
        if not hit_rate(f"register:{client_ip()}", current_app.config["REGISTER_IP_MAX_ATTEMPTS"],
                        current_app.config["REGISTER_IP_WINDOW_SECONDS"]):
            flash("Too many accounts created from this network. Try again later.", "error")
            return render_template("auth/register.html", form={}, rules=PASSWORD_RULES), 429
        name = (form.get("full_name") or "").strip()[:120]
        email = (form.get("email") or "").strip().lower()
        org_name = (form.get("org_name") or "").strip()[:120]
        pw = form.get("password") or ""
        errors = []
        if len(name) < 2:
            errors.append("Enter your full name.")
        if len(email) > 255 or not valid_email(email):
            errors.append("Enter a valid email address (255 characters or fewer).")
        if len(org_name) < 2:
            errors.append("Enter an organization name.")
        probs = password_problems(pw)
        if probs:
            errors.append("Password needs " + ", ".join(probs) + ".")
        if pw != form.get("confirm"):
            errors.append("Passwords do not match.")
        if User.query.filter_by(email=email).first():
            errors.append("An account with that email already exists.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("auth/register.html", form=form, rules=PASSWORD_RULES), 400
        org = Organization(name=org_name)
        db.session.add(org)
        db.session.flush()
        user = User(org_id=org.id, full_name=name, email=email, role="admin")
        user.set_password(pw)
        db.session.add(user)
        audit.log(org.id, email, "auth.register", org_name)
        db.session.commit()
        login_user(user)
        flash("Welcome to ShieldIQ! Connect your first environment to start scanning.", "success")
        return redirect(url_for("views.integrations"))
    return render_template("auth/register.html", form={}, rules=PASSWORD_RULES)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit.log(current_user.org_id, current_user.email, "auth.logout", current_user.email)
    db.session.commit()
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("auth.login"))
