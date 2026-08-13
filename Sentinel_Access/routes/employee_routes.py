"""Employee routes: access to own profile/data only."""

from flask import Blueprint, jsonify, render_template, session

from decorators import roles_required
from services import auth_service, log_service

employee_bp = Blueprint("employee", __name__, url_prefix="/employee")


@employee_bp.route("/")
@roles_required("employee")
def dashboard():
    username = session["user_id"]
    user = auth_service.get_user(username)
    attempts = log_service.get_recent_attempts_for_user(username, limit=10)
    return render_template("employee_dashboard.html", user=user, attempts=attempts)


@employee_bp.route("/api/profile")
@roles_required("employee")
def api_profile():
    username = session["user_id"]
    user = auth_service.get_user(username)
    return jsonify({
        "username": user["username"],
        "role": user.get("role"),
        "typical_ip": user.get("typical_ip"),
        "typical_location": user.get("typical_location"),
        "typical_login_hours": user.get("typical_login_hours"),
        "mfa_enrolled": user.get("mfa_enrolled", False),
    })
