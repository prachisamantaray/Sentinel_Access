"""Manager routes: team data + limited reports only. No security logs -
role_required('manager') means an admin hitting these gets in (not required,
but only managers are granted access here) while employees get a 403."""

from flask import Blueprint, jsonify, render_template

from decorators import roles_required
from services import auth_service

manager_bp = Blueprint("manager", __name__, url_prefix="/manager")


def _team_report():
    employees = auth_service.get_users_by_role("employee")
    roster = [{
        "username": e["username"],
        "typical_location": e.get("typical_location"),
        "is_blocked": e.get("is_blocked", False),
    } for e in employees]
    report = {
        "team_size": len(roster),
        "blocked_count": sum(1 for e in roster if e["is_blocked"]),
    }
    return roster, report


@manager_bp.route("/")
@roles_required("manager")
def dashboard():
    roster, report = _team_report()
    return render_template("manager_dashboard.html", roster=roster, report=report)


@manager_bp.route("/api/team")
@roles_required("manager")
def api_team():
    roster, report = _team_report()
    return jsonify({"roster": roster, "report": report})
