"""RBAC middleware: login_required + roles_required decorators.

Any endpoint under a path containing '/api/' is treated as an API call and
gets a JSON 401/403 response; page routes get a redirect/rendered 403 page.
"""

from functools import wraps

from flask import flash, jsonify, redirect, render_template, request, session, url_for


def _is_api_request():
    return "/api/" in request.path


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            if _is_api_request():
                return jsonify({"error": "Authentication required"}), 401
            flash("Please log in to continue.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return wrapper


def roles_required(*allowed_roles):
    """Require an authenticated session with a role in allowed_roles.
    Any authenticated user with a different role gets a 403 - this is the
    least-privilege enforcement point for every admin/manager/employee route.
    """

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                if _is_api_request():
                    return jsonify({"error": "Authentication required"}), 401
                flash("Please log in to continue.", "warning")
                return redirect(url_for("auth.login"))

            if session.get("role") not in allowed_roles:
                if _is_api_request():
                    return jsonify({"error": "Forbidden: insufficient role privileges"}), 403
                return render_template("403.html"), 403

            return f(*args, **kwargs)

        return wrapper

    return decorator
