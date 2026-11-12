"""Encryption at rest for temporary scan credentials.

The plaintext secret is never stored.  Fernet (AES-128-CBC + HMAC-SHA256) is
used through ``MultiFernet`` so a key can be rotated without losing existing
rows: encryption always uses the first key, decryption accepts every configured
key.

Production must supply ``TRUST_CREDENTIAL_KEY``; a development/test key is
derived from ``SECRET_KEY`` only when the application is not production.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from flask import current_app

TOKEN_PREFIX = "v1:"
DERIVATION_LABEL = b"vulnscan-credential-key:"


class CredentialCryptoError(Exception):
    """Credential encryption is unavailable or the ciphertext is unusable."""


def _valid_fernet_key(value):
    if not value:
        return None
    try:
        candidate = str(value).strip().encode("ascii")
        Fernet(candidate)
        return candidate
    except Exception:
        return None


def _configured_keys():
    config = current_app.config
    keys = []
    primary = _valid_fernet_key(config.get("TRUST_CREDENTIAL_KEY"))
    if primary is None:
        if config.get("REQUIRE_SECRET"):
            # Production never derives a credential key from the JWT secret.
            return []
        secret = config.get("SECRET_KEY") or ""
        digest = hashlib.sha256(DERIVATION_LABEL + secret.encode("utf-8")).digest()
        primary = base64.urlsafe_b64encode(digest)
    keys.append(primary)
    old = _valid_fernet_key(config.get("TRUST_CREDENTIAL_KEY_OLD"))
    if old and old != primary:
        keys.append(old)
    return keys


def _fernet():
    keys = _configured_keys()
    if not keys:
        return None
    try:
        return MultiFernet([Fernet(key) for key in keys])
    except Exception:
        current_app.logger.exception("Invalid credential encryption key")
        return None


def storage_available():
    """True when a usable credential key is configured."""
    return _fernet() is not None


def encrypt_secret(plaintext):
    if plaintext is None or plaintext == "":
        raise CredentialCryptoError("A secret is required.")
    fernet = _fernet()
    if fernet is None:
        raise CredentialCryptoError(
            "Credential storage is not configured on this server."
        )
    token = fernet.encrypt(str(plaintext).encode("utf-8")).decode("ascii")
    return TOKEN_PREFIX + token


def decrypt_secret(stored):
    if not stored:
        raise CredentialCryptoError("No secret is stored for this credential.")
    if not str(stored).startswith(TOKEN_PREFIX):
        raise CredentialCryptoError("Unsupported credential ciphertext format.")
    fernet = _fernet()
    if fernet is None:
        raise CredentialCryptoError(
            "Credential storage is not configured on this server."
        )
    try:
        return fernet.decrypt(
            str(stored)[len(TOKEN_PREFIX):].encode("ascii")
        ).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise CredentialCryptoError(
            "The stored credential could not be decrypted."
        ) from exc
