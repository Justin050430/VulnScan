"""Trust Boundary schema availability check.

Fails closed: if the additive Trust Boundary tables (or a column added by a
later additive migration) are missing, the ``/api/v1`` API answers with
``503 TRUST_BOUNDARY_UNAVAILABLE`` and an actionable hint instead of a generic
500 from a raw SQL error.

Checking columns as well as tables matters because the application reads
columns that later migrations add.  A database with every Trust table but an
old column set would otherwise fail every request with
``Invalid column name ...`` and no indication of what to run.
"""
import time

from flask import current_app
from sqlalchemy import inspect

from app.extensions import db
from app.models import TRUST_ENTITIES

_AVAILABLE_KEY = "TRUST_SCHEMA_AVAILABLE"
_CHECKED_AT_KEY = "TRUST_SCHEMA_CHECKED_AT"
_PROBLEM_KEY = "TRUST_SCHEMA_PROBLEM"
#: Re-check a missing schema at most this often (lets an operator run the
#: migration without restarting the process).
RETRY_SECONDS = 30

#: Columns the application reads that were added by a later additive migration.
#: {table: {column: revision that adds it}}
REQUIRED_COLUMNS = {
    "TrustOrganisationMembership": {
        "InviteEmail": "d9f2a4c8b1e7_invitation_email",
    },
    "TrustProjectMembership": {
        "InviteEmail": "d9f2a4c8b1e7_invitation_email",
    },
}

#: Revision that creates the Trust Boundary tables themselves.
BASE_MIGRATION = "c4d8f1a2b6e9_temporary_scan_credentials"


def check_schema(inspector):
    """
    Return ``(missing_tables, missing_columns)`` for the current database.

    Pure function over an SQLAlchemy inspector so it can be tested without a
    deliberately broken database.
    """
    tables = set(inspector.get_table_names())
    missing_tables = sorted(set(TRUST_ENTITIES) - tables)

    missing_columns = []
    for table, columns in REQUIRED_COLUMNS.items():
        if table in missing_tables:
            continue
        present = {column["name"] for column in inspector.get_columns(table)}
        for column, revision in columns.items():
            if column not in present:
                missing_columns.append(
                    {"table": table, "column": column, "migration": revision}
                )
    return missing_tables, missing_columns


def problem():
    """
    Return the schema problem for the current database, or None when complete.

    The result is cached per process: a complete schema is remembered for the
    process lifetime, an incomplete one is re-checked every RETRY_SECONDS so an
    operator can migrate without restarting the web app.
    """
    if current_app.config.get(_AVAILABLE_KEY) is True:
        return None

    if current_app.config.get(_AVAILABLE_KEY) is False:
        checked_at = current_app.config.get(_CHECKED_AT_KEY) or 0
        if (time.time() - checked_at) < RETRY_SECONDS:
            return current_app.config.get(_PROBLEM_KEY)

    try:
        missing_tables, missing_columns = check_schema(inspect(db.engine))
    except Exception:
        # A database outage is handled by /api/health; treat it as unavailable.
        missing_tables, missing_columns = sorted(TRUST_ENTITIES), []

    result = None
    if missing_tables or missing_columns:
        result = {
            "missing_tables": missing_tables,
            "missing_columns": missing_columns,
        }

    current_app.config[_AVAILABLE_KEY] = result is None
    current_app.config[_CHECKED_AT_KEY] = time.time()
    current_app.config[_PROBLEM_KEY] = result
    return result


def available():
    """True when every required Trust Boundary table and column exists."""
    return problem() is None


def missing_schema_response(details=None):
    """Build the 503 payload naming the exact migration that must be run."""
    details = details if details is not None else (problem() or {})
    missing_tables = details.get("missing_tables") or []
    missing_columns = details.get("missing_columns") or []

    if missing_tables:
        migration = BASE_MIGRATION
        reason = (
            "The Trust Boundary tables are missing from this database "
            f"({', '.join(missing_tables[:3])}"
            + (", ..." if len(missing_tables) > 3 else "")
            + ")."
        )
    else:
        migration = missing_columns[0]["migration"] if missing_columns else BASE_MIGRATION
        listed = ", ".join(
            f"{item['table']}.{item['column']}" for item in missing_columns[:3]
        )
        reason = f"This database is missing required column(s): {listed}."

    return {
        "message": (
            f"{reason} Run 'python -m flask --app run.py db upgrade' in the "
            "backend directory (this database is behind migration "
            f"'{migration}'), then retry."
        ),
        "code": "TRUST_BOUNDARY_UNAVAILABLE",
        "details": {
            "missing_migration": migration,
            "missing_tables": missing_tables,
            "missing_columns": missing_columns,
        },
    }, 503
