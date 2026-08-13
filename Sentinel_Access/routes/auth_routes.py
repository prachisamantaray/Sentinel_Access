"""Login, MFA challenge/enrollment, and logout.

This is where Auth Service + Risk Engine + MFA + Session/RBAC connect, per
the system flow:
[Login Page] -> [Auth Service] -> [Risk Engine] -> [MFA Challenge if needed] -> [Session + RBAC] -> [Dashboard]
"""

from datetime import datetime, timezone

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from config import Config
from services import auth_service, geo_service, log_service, mfa_service, risk_engine
from utils import get_client_ip, get_device_fingerprint, parse_device_label

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")
    device_fp = get_device_fingerprint(ua)
    device_label = parse_device_label(ua)

    user = auth_service.get_user(username)

    if not user:
        log_service.log_attempt(username or "(unknown)", ip, device_label, device_fp,
                                 None, 0, "invalid_credentials", ["Unknown username"])
        flash("Invalid username or password.", "danger")
        return render_template("login.html"), 401

    if user.get("is_blocked"):
        log_service.log_attempt(username, ip, device_label, device_fp,
                                 None, 0, "account_blocked", ["Account is blocked"])
        flash("This account is blocked. Contact your administrator.", "danger")
        return render_template("login.html"), 403

    if not auth_service.verify_password(user, password):
        log_service.log_attempt(username, ip, device_label, device_fp,
                                 None, 0, "invalid_credentials", ["Incorrect password"])
        flash("Invalid username or password.", "danger")
        return render_template("login.html"), 401

    # Password correct - hand off to the risk engine.
    login_time = datetime.now(timezone.utc)
    location = geo_service.get_location(ip, token=Config.IPINFO_TOKEN or None)
    score, signals = risk_engine.compute_risk(user, ip, device_fp, login_time, location)
    decision = risk_engine.decide(score)

    if decision == "block":
        auth_service.set_blocked(username, True)
        log_service.log_attempt(username, ip, device_label, device_fp, location, score, "blocked", signals)
        flash("Login blocked due to highly suspicious activity. Your account has been locked - "
              "contact your administrator.", "danger")
        return render_template("login.html"), 403

    if decision == "mfa_required":
        ref = log_service.log_attempt(username, ip, device_label, device_fp, location, score, "mfa_required", signals)
        session["pending_user"] = username
        session["pending_log_id"] = ref.id
        session["mfa_attempts"] = 0
        return redirect(url_for("auth.mfa"))

    # decision == "allow"
    log_service.log_attempt(username, ip, device_label, device_fp, location, score, "allowed", signals)
    session["user_id"] = username
    session["role"] = user["role"]
    flash(f"Welcome back, {username}.", "success")
    return redirect(url_for("dashboard"))


@auth_bp.route("/mfa", methods=["GET", "POST"])
def mfa():
    username = session.get("pending_user")
    if not username:
        return redirect(url_for("auth.login"))

    user = auth_service.get_user(username)
    if not user:
        session.clear()
        return redirect(url_for("auth.login"))

    enrolling = not user.get("mfa_enrolled")

    def build_qr():
        secret = user.get("totp_secret")
        if not secret:
            secret = mfa_service.generate_secret()
            auth_service.set_totp_secret(username, secret)
            user["totp_secret"] = secret
        uri = mfa_service.get_totp_uri(secret, username, issuer=Config.APP_ISSUER)
        return mfa_service.generate_qr_data_uri(uri), secret

    if request.method == "GET":
        qr_data_uri, secret = (build_qr() if enrolling else (None, user.get("totp_secret")))
        return render_template("mfa.html", enrolling=enrolling, qr_data_uri=qr_data_uri,
                                secret=secret if enrolling else None)

    code = request.form.get("code", "").strip()
    secret = user.get("totp_secret")

    if mfa_service.verify_otp(secret, code):
        if enrolling:
            auth_service.set_mfa_enrolled(username, True)
        log_id = session.get("pending_log_id")
        if log_id:
            log_service.update_attempt_result(log_id, "allowed")
        session.pop("pending_user", None)
        session.pop("pending_log_id", None)
        session.pop("mfa_attempts", None)
        session["user_id"] = username
        session["role"] = user["role"]
        flash("MFA verified. Welcome back!", "success")
        return redirect(url_for("dashboard"))

    # Invalid code
    session["mfa_attempts"] = session.get("mfa_attempts", 0) + 1
    if session["mfa_attempts"] >= Config.MAX_MFA_ATTEMPTS:
        auth_service.set_blocked(username, True)
        log_id = session.get("pending_log_id")
        if log_id:
            log_service.update_attempt_result(log_id, "blocked", extra_signals=["Too many failed MFA attempts"])
        session.clear()
        flash("Too many failed MFA attempts. Your account has been blocked - contact your administrator.", "danger")
        return redirect(url_for("auth.login"))

    flash("Invalid code. Please try again.", "danger")
    qr_data_uri, secret = (build_qr() if enrolling else (None, secret))
    return render_template("mfa.html", enrolling=enrolling, qr_data_uri=qr_data_uri,
                            secret=secret if enrolling else None), 401


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
