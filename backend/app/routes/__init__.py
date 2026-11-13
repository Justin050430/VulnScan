"""REST API blueprint registration."""
from flask import Blueprint


def register_blueprints(app):
    from app.routes.assets import assets_bp
    from app.routes.audit_logs import audit_logs_bp
    from app.routes.auth import auth_bp
    from app.routes.credentials import credentials_bp
    from app.routes.organisations import (
        invitations_bp,
        organisations_bp,
        projects_bp,
    )
    from app.routes.payments import payments_bp, payments_scoped_bp
    from app.routes.scan_profiles import scan_profiles_bp
    from app.routes.scans import scans_bp
    from app.routes.trust_scans import trust_scans_bp
    from app.routes.users import users_bp
    from app.routes.vulnerabilities import vulnerabilities_bp

    api = Blueprint("api", __name__, url_prefix="/api")

    api.register_blueprint(auth_bp)
    api.register_blueprint(users_bp)
    api.register_blueprint(vulnerabilities_bp)
    api.register_blueprint(scan_profiles_bp)
    api.register_blueprint(scans_bp)
    api.register_blueprint(audit_logs_bp)

    # Trust Boundary Extension - additive /api/v1 surface.
    v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")

    from flask import jsonify

    from app.trust import schema

    @v1.before_request
    def _require_trust_schema():
        """Fail closed with an actionable error when the schema is missing."""
        details = schema.problem()
        if details is None:
            return None
        payload, status = schema.missing_schema_response(details)
        return jsonify(payload), status

    v1.register_blueprint(organisations_bp)
    v1.register_blueprint(projects_bp)
    v1.register_blueprint(invitations_bp)
    v1.register_blueprint(assets_bp)
    v1.register_blueprint(credentials_bp)
    v1.register_blueprint(payments_bp)
    v1.register_blueprint(payments_scoped_bp)
    v1.register_blueprint(trust_scans_bp)

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
    app.register_blueprint(v1)
