"""Trust Boundary schema availability check.

Fails closed: if the additive Trust Boundary tables are missing (for example the
database is still at the core migration), the ``/api/v1`` API answers with
``503 TRUST_BOUNDARY_UNAVAILABLE`` and an actionable hint instead of a generic
500 from a raw SQL error.
"""
import time

from flask import current_app
from sqlalchemy import inspect

from app.extensions import db
from app.models import TRUST_ENTITIES

_AVAILABLE_KEY = "TRUST_SCHEMA_AVAILABLE"
_CHECKED_AT_KEY = "TRUST_SCHEMA_CHECKED_AT"
#: Re-check a missing schema at most this often (lets an operator run the
#: migration without restarting the process).
RETRY_SECONDS = 30


def available():
    """True when every Trust Boundary table exists in the current database."""
    if current_app.config.get(_AVAILABLE_KEY) is True:
        return True

    checked_at = current_app.config.get(_CHECKED_AT_KEY) or 0
    if current_app.config.get(_AVAILABLE_KEY) is False:
        if (time.time() - checked_at) < RETRY_SECONDS:
            return False

    try:
        tables = set(inspect(db.engine).get_table_names())
    except Exception:
        # A database outage is handled by /api/health; treat it as unavailable.
        tables = set()

    ok = set(TRUST_ENTITIES).issubset(tables)
    current_app.config[_AVAILABLE_KEY] = ok
    current_app.config[_CHECKED_AT_KEY] = time.time()
    return ok


def missing_schema_response():
    return {
        "message": (
            "The Trust Boundary schema is not installed on this database. "
            "Run 'python -m flask --app run.py db upgrade' in the backend "
            "directory, then retry."
        ),
        "code": "TRUST_BOUNDARY_UNAVAILABLE",
        "details": {"missing_migration": "aaf9e35de1fe_trust_boundary_extension"},
    }, 503
