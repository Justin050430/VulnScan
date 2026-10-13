"""REST API blueprint registration."""
from flask import Blueprint


def register_blueprints(app):
    from app.routes.audit_logs import audit_logs_bp
    from app.routes.auth import auth_bp
    from app.routes.scan_profiles import scan_profiles_bp
    from app.routes.scans import scans_bp
    from app.routes.users import users_bp
    from app.routes.vulnerabilities import vulnerabilities_bp

    api = Blueprint("api", __name__, url_prefix="/api")

    api.register_blueprint(auth_bp)
    api.register_blueprint(users_bp)
    api.register_blueprint(vulnerabilities_bp)
    api.register_blueprint(scan_profiles_bp)
    api.register_blueprint(scans_bp)
    api.register_blueprint(audit_logs_bp)

    @api.get("/health")
    def health():
        """
        Liveness + readiness probe.

        The database is pinged so a database outage is reported as
        `503 degraded` instead of a misleading `200 ok`.
        """
        from sqlalchemy import text
        from app.extensions import db

        try:
            db.session.execute(text("SELECT 1"))
        except Exception:
            db.session.rollback()
            return {
                "status": "degraded",
                "service": "vulnscan",
                "database": "unavailable",
            }, 503
        return {"status": "ok", "service": "vulnscan", "database": "ok"}

    # ------------------------------------------------------------ web (UI)
    from flask import render_template

    @app.route("/")
    def index():
        return render_template("index.html")

    # Register everything only after all routes are declared.
    app.register_blueprint(api)
