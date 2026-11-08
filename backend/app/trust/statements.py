"""Versioned authorisation attestation statement helpers."""
import hashlib

from app.trust.constants import (
    ATTESTATION_STATEMENT_TEXT,
    ATTESTATION_STATEMENT_VERSION,
)


def statement_text(version=None):
    """Return the canonical statement text for a version."""
    # Only v1 exists in this slice; unknown versions are rejected upstream.
    return ATTESTATION_STATEMENT_TEXT


def statement_hash(text):
    """SHA-256 of the canonical statement text (hex)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_statement(version=None):
    version = version or ATTESTATION_STATEMENT_VERSION
    text = statement_text(version)
    return version, text, statement_hash(text)
