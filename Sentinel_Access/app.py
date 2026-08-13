"""SentinelAccess - Adaptive MFA & Role-Based Threat Detection System.

Flask application factory. Wires together Firebase/Firestore, the auth +
risk engine + MFA flow, RBAC-protected blueprints, and the frontend.
"""

from flask import Flask, redirect, render_template, session, url_for

from config import Config
from firebase_init import init_firebase
from routes.admin_routes import admin_bp
from routes.auth_routes import auth_bp
from routes.employee_routes import employee_bp
from routes.manager_routes import manager_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    app.secret_key = Config.SECRET_KEY

    # Fail fast with a clear message if serviceAccountKey.json isn't in place yet.
    init_firebase(Config.FIREBASE_CRED_PATH)

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(manager_bp)
    app.register_blueprint(employee_bp)

    @app.template_filter("datetimeformat")
    def datetimeformat(value):
        if value is None:
            return "-"
        try:
            return value.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return str(value)

    @app.route("/")
    def root():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("auth.login"))

    @app.route("/dashboard")
    def dashboard():
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        role = session.get("role")
        if role == "admin":
            return redirect(url_for("admin.dashboard"))
        if role == "manager":
            return redirect(url_for("manager.dashboard"))
        if role == "employee":
            return redirect(url_for("employee.dashboard"))
        session.clear()
        return redirect(url_for("auth.login"))

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("403.html"), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("404.html"), 404

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
