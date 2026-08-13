"""Admin routes: full access - user management, security dashboard, all logs,
unblock users. Every route here requires role == 'admin' (403 otherwise)."""

from datetime import datetime, timedelta, timezone

from flask import Blueprint, flash, jsonify, redirect, render_template, url_for

from decorators import roles_required
from services import auth_service, log_service

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@roles_required("admin")
def dashboard():
    users = auth_service.get_all_users()
    attempts = log_service.get_all_attempts(limit=200)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_blocked = [a for a in attempts if a.get("result") == "blocked" and a.get("timestamp") and a["timestamp"] >= cutoff]

    stats = {
        "total_users": len(users),
        "blocked_users": sum(1 for u in users if u.get("is_blocked")),
        "alerts_24h": len(recent_blocked),
        "attempts_24h": sum(1 for a in attempts if a.get("timestamp") and a["timestamp"] >= cutoff),
    }
    return render_template("admin_dashboard.html", stats=stats, recent_alerts=recent_blocked[:5])


@admin_bp.route("/users")
@roles_required("admin")
def users():
    return render_template("admin_users.html", users=auth_service.get_all_users())


@admin_bp.route("/users/<username>/unblock", methods=["POST"])
@roles_required("admin")
def unblock_user(username):
    auth_service.set_blocked(username, False)
    flash(f"'{username}' has been unblocked.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<username>/block", methods=["POST"])
@roles_required("admin")
def block_user(username):
    auth_service.set_blocked(username, True)
    flash(f"'{username}' has been blocked.", "warning")
    return redirect(url_for("admin.users"))


@admin_bp.route("/security")
@roles_required("admin")
def security():
    return render_template("admin_security.html")


@admin_bp.route("/api/logs")
@roles_required("admin")
def api_logs():
    attempts = log_service.get_all_attempts(limit=200)
    out = []
    for a in attempts:
        ts = a.get("timestamp")
        out.append({
            "id": a.get("id"),
            "user_id": a.get("user_id"),
            "ip": a.get("ip"),
            "device": a.get("device"),
            "location": (a.get("location") or {}).get("label"),
            "timestamp": ts.isoformat() if ts else None,
            "risk_score": a.get("risk_score", 0),
            "result": a.get("result"),
            "risk_signals_triggered": a.get("risk_signals_triggered", []),
        })
    return jsonify(out)


@admin_bp.route("/api/users")
@roles_required("admin")
def api_users():
    users = auth_service.get_all_users()
    out = [{
        "username": u["username"],
        "role": u.get("role"),
        "is_blocked": u.get("is_blocked", False),
        "typical_ip": u.get("typical_ip"),
        "typical_location": u.get("typical_location"),
        "mfa_enrolled": u.get("mfa_enrolled", False),
    } for u in users]
    return jsonify(out)


@admin_bp.route("/api/users/<username>/unblock", methods=["POST"])
@roles_required("admin")
def api_unblock_user(username):
    """AJAX unblock used by the Security Dashboard's one-click button."""
    auth_service.set_blocked(username, False)
    return jsonify({"username": username, "is_blocked": False})
