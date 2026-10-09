"""
VulnScan - Intelligent Web Application Vulnerability Assessment Platform
with Risk Assessment and Remediation Knowledge Base.

Application factory.  Author: OOI JIAN XIN (TAR UMT).
"""
import logging
import os

from flask import Flask, jsonify
from flask_jwt_extended import get_jwt

from app.extensions import db, jwt, migrate
from config import get_config

logger = logging.getLogger("vulnscan")


def create_app(config_name=None):
    config_obj = get_config(config_name)
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
        instance_relative_config=True,
    )
    app.config.from_object(config_obj)
    os.makedirs(app.instance_path, exist_ok=True)

    # Production must never run with a placeholder/empty secret.
    if app.config.get("REQUIRE_SECRET"):
        if not app.config.get("SECRET_KEY"):
            raise RuntimeError("SECRET_KEY must be set for the production environment.")
        if not app.config.get("JWT_SECRET_KEY"):
            raise RuntimeError("JWT_SECRET_KEY must be set for the production environment.")

    # ------------------------------------------------------------- extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    _register_jwt_handlers(app)
    _register_error_handlers(app)
    _register_blueprints(app)
    _register_cli(app)
    _recover_orphan_scans(app)

    return app


def _recover_orphan_scans(app):
    """
    Fail scans orphaned by a previous process so users are never stuck with a
    permanently 'Running' scan (F1).  Never fatal: startup must proceed even
    when the schema does not exist yet.
    """
    if not app.config.get("SCANNER_RECOVER_ORPHAN_SCANS", True):
        return
    try:
        with app.app_context():
            from app.services.scan_service import recover_orphan_scans

            recovered = recover_orphan_scans()
            if recovered:
                app.logger.warning(
                    "Startup recovery failed %d orphaned scan(s): %s",
                    len(recovered), recovered,
                )
    except Exception:
        # e.g. tables not created yet (first run / before migrations).
        app.logger.debug("Orphan scan recovery skipped", exc_info=True)


# --------------------------------------------------------------------------- JWT
def _register_jwt_handlers(app):
    from flask_jwt_extended import verify_jwt_in_request
    from flask_jwt_extended.exceptions import NoAuthorizationError

    from app.services.auth_service import is_token_revoked

    @jwt.token_in_blocklist_loader
    def _check_if_token_revoked(jwt_header, jwt_payload):
        return is_token_revoked(jwt_payload)

    @jwt.user_lookup_loader
    def _user_lookup_callback(_jwt_header, jwt_payload):
        from app.models import User

        user_id = jwt_payload.get("sub")
        if user_id is None:
            return None
        user = db.session.get(User, int(user_id))
        if user is None or not user.IsActive:
            return None
        return user

    @jwt.expired_token_loader
    def _expired_token_callback(_jwt_header, _jwt_payload):
        return (
            jsonify({"message": "The token has expired.", "code": "token_expired"}),
            401,
        )

    @jwt.invalid_token_loader
    def _invalid_token_callback(reason):
        return (
            jsonify({"message": "Invalid token.", "code": "token_invalid"}),
            401,
        )

    @jwt.unauthorized_loader
    def _missing_token_callback(reason):
        return (
            jsonify({"message": "Authentication required.", "code": "token_missing"}),
            401,
        )

    @jwt.revoked_token_loader
    def _revoked_token_callback(_jwt_header, _jwt_payload):
        return (
            jsonify({"message": "The token has been revoked.", "code": "token_revoked"}),
            401,
        )


# --------------------------------------------------------------------------- errors
def _register_error_handlers(app):
    from werkzeug.exceptions import HTTPException

    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        payload = {"message": error.description or error.name}
        return jsonify(payload), error.code

    @app.errorhandler(Exception)
    def handle_unhandled_exception(error):
        # Log the real error for debugging but do not leak internals.
        logger.exception("Unhandled error: %s", error)
        return (
            jsonify({"message": "An internal server error occurred."}),
            500,
        )


# --------------------------------------------------------------------------- blueprints
def _register_blueprints(app):
    from app.routes import register_blueprints

    register_blueprints(app)


# --------------------------------------------------------------------------- CLI
def _register_cli(app):
    import click

    @app.cli.command("init-db")
    def init_db_command():
        """Create all tables (development shortcut before migrations are used)."""
        db.create_all()
        click.echo("Database tables created.")

    @app.cli.command("seed")
    def seed_command():
        """Seed the database with initial reference data."""
        from app.seeds import run_seed

        run_seed()
        click.echo("Seed data applied.")

    @app.cli.command("seed-reset")
    def seed_reset_command():
        """Drop all tables, recreate and seed (development only)."""
        db.drop_all()
        db.create_all()
        from app.seeds import run_seed

        run_seed()
        click.echo("Database reset and seeded.")
