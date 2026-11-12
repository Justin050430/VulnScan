"""Temporary authenticated-scan credential lifecycle.

Controls implemented here:
  * creator submits, a different project owner approves (maker-checker),
  * the secret is encrypted at rest and never serialised,
  * credentials expire and are single-use (one scan binding),
  * revoking or expiring a credential destroys the stored secret,
  * every transition is recorded in the append-only trust audit ledger.
"""
import hashlib
import json
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse

from flask import current_app

from app.extensions import db
from app.models import (
    TrustScanCredential,
    TrustScanCredentialBinding,
)
from app.scanner.auth import AuthSession, LoginConfig, LoginError
from app.scanner.client import HttpClient
from app.scanner.safety import check_target_allowed
from app.services import attestation_service
from app.services import trust_audit_service as audit
from app.services.asset_verification_service import ensure_verified
from app.trust import credential_crypto
from app.trust.constants import (
    AUTH_TYPE_FORM,
    AUTH_TYPES,
    CREDENTIAL_APPROVAL_STATEMENT_TEXT,
    CREDENTIAL_APPROVED,
    CREDENTIAL_EXPIRED,
    CREDENTIAL_PENDING,
    CREDENTIAL_REJECTED,
    CREDENTIAL_REVOKED,
    CREDENTIAL_USED,
    ERR_CREDENTIAL_ALREADY_USED,
    ERR_CREDENTIAL_EXPIRED,
    ERR_CREDENTIAL_LOGIN_FAILED,
    ERR_CREDENTIAL_NOT_APPROVED,
    ERR_CREDENTIAL_SELF_APPROVAL,
    ERR_CREDENTIAL_STORAGE_UNAVAILABLE,
    ERR_NOT_FOUND,
    ERR_RATE_LIMITED,
    ERR_VALIDATION,
    EVENT_CREDENTIAL_APPROVED,
    EVENT_CREDENTIAL_CREATED,
    EVENT_CREDENTIAL_LOGIN_FAILED,
    EVENT_CREDENTIAL_REJECTED,
    EVENT_CREDENTIAL_RELEASED,
    EVENT_CREDENTIAL_REVOKED,
    EVENT_CREDENTIAL_SECRET_PURGED,
    EVENT_CREDENTIAL_TESTED,
    EVENT_CREDENTIAL_USED,
)
from app.trust.hostnames import url_matches_asset
from app.trust.permissions import TrustError

_FIELD_RE = re.compile(r"^[A-Za-z0-9_\[\]\.\-]{1,64}$")
_MAX_EXTRA_FIELDS = 20


# --------------------------------------------------------------------- helpers
def _storage_error():
    return TrustError(
        "Credential storage is not configured on this server.",
        ERR_CREDENTIAL_STORAGE_UNAVAILABLE,
        503,
    )


def _require_storage():
    if not credential_crypto.storage_available():
        raise _storage_error()


def _now():
    return datetime.utcnow()


def _metadata(credential):
    """Audit metadata keys deliberately avoid the redacted word 'credential'."""
    return {
        "auth_ref": credential.CredentialID,
        "auth_type": credential.AuthType,
        "asset_id": credential.AssetID,
        "login_host": urlparse(credential.LoginURL).hostname,
        "expires_at": credential.ExpiresAt.isoformat()
        if credential.ExpiresAt else None,
    }


def _text(value, field, max_length, required=True):
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise TrustError(f"{field} must be text.", ERR_VALIDATION, 400)
    value = value.strip()
    if required and not value:
        raise TrustError(f"{field} is required.", ERR_VALIDATION, 400)
    if len(value) > max_length:
        raise TrustError(
            f"{field} must be at most {max_length} characters.",
            ERR_VALIDATION,
            400,
        )
    return value


def _field_name(value, label):
    if value is None or value == "":
        return None
    value = _text(value, label, 64)
    if not _FIELD_RE.match(value):
        raise TrustError(
            f"{label} contains characters that are not allowed.",
            ERR_VALIDATION,
            400,
        )
    return value


def _extra_fields(value):
    if value in (None, ""):
        return None
    if not isinstance(value, dict):
        raise TrustError(
            "extra_fields must be an object of field/value pairs.",
            ERR_VALIDATION,
            400,
        )
    if len(value) > _MAX_EXTRA_FIELDS:
        raise TrustError(
            f"extra_fields may contain at most {_MAX_EXTRA_FIELDS} entries.",
            ERR_VALIDATION,
            400,
        )
    cleaned = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _FIELD_RE.match(key):
            raise TrustError(
                "extra_fields contains an invalid field name.",
                ERR_VALIDATION,
                400,
            )
        if item is None:
            item = ""
        if not isinstance(item, (str, int, float, bool)):
            raise TrustError(
                "extra_fields values must be scalar.",
                ERR_VALIDATION,
                400,
            )
        cleaned[key] = str(item)[:500]
    encoded = json.dumps(cleaned, separators=(",", ":"), sort_keys=True)
    if len(encoded) > 1000:
        raise TrustError(
            "extra_fields is too large (maximum 1000 characters).",
            ERR_VALIDATION,
            400,
        )
    return encoded


def _login_url(asset, value):
    url = _text(value, "login_url", 500)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise TrustError(
            "login_url must be an absolute http(s) URL.", ERR_VALIDATION, 400
        )
    if parsed.username or parsed.password:
        raise TrustError(
            "login_url must not contain embedded credentials.",
            ERR_VALIDATION,
            400,
        )
    if not url_matches_asset(url, asset.Hostname, asset.Scheme):
        raise TrustError(
            "login_url must use the verified asset's exact hostname and scheme.",
            ERR_VALIDATION,
            400,
        )
    allow_private = bool(
        current_app.config.get("SCANNER_ALLOW_PRIVATE_TARGETS", True)
    )
    ok, reason = check_target_allowed(url, allow_private=allow_private)
    if not ok:
        raise TrustError(
            f"login_url is not an allowed target: {reason}.",
            ERR_VALIDATION,
            400,
        )
    return url


def _expiry(value):
    max_hours = int(current_app.config.get("TRUST_CREDENTIAL_MAX_HOURS", 24))
    default_hours = int(
        current_app.config.get("TRUST_CREDENTIAL_DEFAULT_HOURS", 4)
    )
    if value is None:
        minutes = default_hours * 60
    else:
        try:
            minutes = int(value)
        except (TypeError, ValueError):
            raise TrustError(
                "expires_in_minutes must be an integer.",
                ERR_VALIDATION,
                400,
            ) from None
    if minutes < 5 or minutes > max_hours * 60:
        raise TrustError(
            f"expires_in_minutes must be between 5 and {max_hours * 60}.",
            ERR_VALIDATION,
            400,
        )
    return _now() + timedelta(minutes=minutes)


def _assert_project(credential, access):
    if (
        credential.OrganisationID != access.organisation_id
        or credential.ProjectID != access.project_id
    ):
        raise TrustError("Credential not found.", ERR_NOT_FOUND, 404)


def get_project_credential(project_id, credential_id):
    credential = db.session.get(TrustScanCredential, int(credential_id))
    if credential is None or credential.ProjectID != int(project_id):
        raise TrustError("Credential not found.", ERR_NOT_FOUND, 404)
    return credential


# ------------------------------------------------------------------ lifecycle
def create_credential(actor, access, asset, payload, ip_address=None):
    _require_storage()
    ensure_verified(asset)

    auth_type = (payload.get("auth_type") or AUTH_TYPE_FORM).upper()
    if auth_type not in AUTH_TYPES:
        raise TrustError(
            "Only FORM authentication is supported in this release.",
            ERR_VALIDATION,
            400,
        )
    name = _text(payload.get("name"), "name", 100)
    login_url = _login_url(asset, payload.get("login_url"))
    username = _text(payload.get("username"), "username", 255)
    password = payload.get("password")
    if not isinstance(password, str) or not password:
        raise TrustError("password is required.", ERR_VALIDATION, 400)
    if len(password) > 500:
        raise TrustError(
            "password must be at most 500 characters.", ERR_VALIDATION, 400
        )
    username_field = _field_name(payload.get("username_field"), "username_field")
    password_field = _field_name(payload.get("password_field"), "password_field")
    extra_fields = _extra_fields(payload.get("extra_fields"))
    success_url = _text(
        payload.get("success_url_contains"), "success_url_contains", 255,
        required=False,
    )
    success_text = _text(
        payload.get("success_text"), "success_text", 255, required=False
    )
    if not success_url and not success_text:
        raise TrustError(
            "Provide success_url_contains or success_text so a failed login "
            "cannot be mistaken for success.",
            ERR_VALIDATION,
            400,
        )
    expires_at = _expiry(payload.get("expires_in_minutes"))

    credential = TrustScanCredential(
        OrganisationID=access.organisation_id,
        ProjectID=access.project_id,
        AssetID=asset.AssetID,
        Name=name,
        AuthType=auth_type,
        LoginURL=login_url,
        UsernameField=username_field,
        PasswordField=password_field,
        ExtraFieldsJson=extra_fields,
        SuccessURLContains=success_url or None,
        SuccessText=success_text or None,
        Username=username,
        SecretEncrypted=credential_crypto.encrypt_secret(password),
        Status=CREDENTIAL_PENDING,
        ExpiresAt=expires_at,
        CreatedByUserID=actor.UserID,
    )
    db.session.add(credential)
    db.session.flush()
    audit.record(
        EVENT_CREDENTIAL_CREATED,
        organisation_id=access.organisation_id,
        project_id=access.project_id,
        actor=actor,
        entity_type="TrustScanCredential",
        entity_id=credential.CredentialID,
        metadata=_metadata(credential),
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return credential


def approve_credential(actor, access, credential, acknowledge,
                       ip_address=None):
    _assert_project(credential, access)
    if not acknowledge:
        raise TrustError(
            "The approval statement must be acknowledged.",
            ERR_VALIDATION,
            400,
        )
    if credential.Status != CREDENTIAL_PENDING:
        raise TrustError(
            "Only a pending credential can be approved.", ERR_VALIDATION, 409
        )
    if credential.is_expired():
        _expire_and_purge(credential, "expired before approval")
        db.session.commit()
        raise TrustError(
            "The credential has expired; create a new one.",
            ERR_CREDENTIAL_EXPIRED,
            409,
        )
    allow_self = bool(
        current_app.config.get("TRUST_CREDENTIAL_ALLOW_SELF_APPROVAL", False)
    )
    if not allow_self and actor.UserID == credential.CreatedByUserID:
        raise TrustError(
            "A different project owner must approve this credential.",
            ERR_CREDENTIAL_SELF_APPROVAL,
            403,
        )

    from app.models import TrustAsset

    asset = db.session.get(TrustAsset, credential.AssetID)
    if asset is None:
        raise TrustError("Asset not found.", ERR_NOT_FOUND, 404)
    ensure_verified(asset)
    attestation = attestation_service.active_for_asset(asset)
    if attestation is None:
        from app.trust.constants import ERR_ATTESTATION_REQUIRED

        raise TrustError(
            "An active authorisation attestation is required before a "
            "credential can be approved.",
            ERR_ATTESTATION_REQUIRED,
            409,
        )

    credential.Status = CREDENTIAL_APPROVED
    credential.ApprovedByUserID = actor.UserID
    credential.ApprovedAt = _now()
    credential.ApprovalStatementHash = hashlib.sha256(
        CREDENTIAL_APPROVAL_STATEMENT_TEXT.encode("utf-8")
    ).hexdigest()
    credential.Version += 1
    audit.record(
        EVENT_CREDENTIAL_APPROVED,
        organisation_id=access.organisation_id,
        project_id=access.project_id,
        actor=actor,
        entity_type="TrustScanCredential",
        entity_id=credential.CredentialID,
        metadata={
            **_metadata(credential),
            "approved_by": actor.UserID,
            "statement_hash": credential.ApprovalStatementHash,
        },
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return credential


def reject_credential(actor, access, credential, reason=None, ip_address=None):
    _assert_project(credential, access)
    if credential.Status != CREDENTIAL_PENDING:
        raise TrustError(
            "Only a pending credential can be rejected.", ERR_VALIDATION, 409
        )
    credential.Status = CREDENTIAL_REJECTED
    credential.RejectedAt = _now()
    credential.StatusReason = _text(reason, "reason", 500, required=False) or None
    credential.Version += 1
    _purge_secret(credential, "credential rejected")
    audit.record(
        EVENT_CREDENTIAL_REJECTED,
        organisation_id=access.organisation_id,
        project_id=access.project_id,
        actor=actor,
        entity_type="TrustScanCredential",
        entity_id=credential.CredentialID,
        metadata=_metadata(credential),
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return credential


def revoke_credential(actor, access, credential, reason=None, ip_address=None):
    _assert_project(credential, access)
    if credential.Status == CREDENTIAL_REVOKED:
        return credential
    if credential.Status in (CREDENTIAL_REJECTED, CREDENTIAL_EXPIRED):
        raise TrustError(
            "This credential is already closed.", ERR_VALIDATION, 409
        )
    credential.Status = CREDENTIAL_REVOKED
    credential.RevokedAt = _now()
    credential.RevokedByUserID = actor.UserID
    credential.StatusReason = _text(reason, "reason", 500, required=False) or None
    credential.Version += 1
    _purge_secret(credential, "credential revoked")
    audit.record(
        EVENT_CREDENTIAL_REVOKED,
        organisation_id=access.organisation_id,
        project_id=access.project_id,
        actor=actor,
        entity_type="TrustScanCredential",
        entity_id=credential.CredentialID,
        metadata=_metadata(credential),
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return credential


def list_credentials(access, asset_id=None):
    query = TrustScanCredential.query.filter_by(ProjectID=access.project_id)
    if asset_id is not None:
        query = query.filter_by(AssetID=int(asset_id))
    rows = query.order_by(TrustScanCredential.CredentialID.desc()).all()
    changed = False
    for credential in rows:
        if credential.is_expired() and credential.Status in (
            CREDENTIAL_PENDING, CREDENTIAL_APPROVED, CREDENTIAL_USED
        ):
            _expire_and_purge(credential, "expired")
            changed = True
    if changed:
        db.session.commit()
    return rows


# ------------------------------------------------------------------- scanning
def resolve_for_scan(access, asset, credential_id):
    credential = get_project_credential(access.project_id, credential_id)
    _assert_project(credential, access)
    if credential.AssetID != asset.AssetID:
        raise TrustError(
            "The credential belongs to a different asset.", ERR_VALIDATION, 400
        )
    if credential.is_expired():
        _expire_and_purge(credential, "expired before scan")
        db.session.commit()
        raise TrustError(
            "The credential has expired; create and approve a new one.",
            ERR_CREDENTIAL_EXPIRED,
            409,
        )
    if credential.binding is not None or credential.Status == CREDENTIAL_USED:
        raise TrustError(
            "This credential was already used for a scan.",
            ERR_CREDENTIAL_ALREADY_USED,
            409,
        )
    if credential.Status != CREDENTIAL_APPROVED:
        raise TrustError(
            "The credential is not approved for use.", ERR_CREDENTIAL_NOT_APPROVED,
            409,
        )
    if not credential.has_secret:
        raise TrustError(
            "The stored credential is no longer available.",
            ERR_CREDENTIAL_EXPIRED,
            409,
        )
    return credential


def bind_to_scan(credential, scan_id, actor=None):
    """Bind a credential to exactly one scan (caller owns the transaction)."""
    now = _now()
    db.session.add(
        TrustScanCredentialBinding(
            ScanID=scan_id, CredentialID=credential.CredentialID, BoundAt=now
        )
    )
    credential.Status = CREDENTIAL_USED
    credential.UsedAt = now
    credential.LastUsedAt = now
    credential.Version += 1
    db.session.flush()
    audit.record(
        EVENT_CREDENTIAL_USED,
        organisation_id=credential.OrganisationID,
        project_id=credential.ProjectID,
        actor=actor,
        entity_type="TrustScanCredential",
        entity_id=credential.CredentialID,
        metadata={**_metadata(credential), "scan_id": scan_id},
        commit=False,
    )


def unbind_from_scan(credential, scan_id, actor=None):
    binding = db.session.get(TrustScanCredentialBinding, int(scan_id))
    if binding is not None:
        db.session.delete(binding)
    if credential is not None:
        credential.Status = CREDENTIAL_APPROVED
        credential.UsedAt = None
        credential.Version += 1
        audit.record(
            EVENT_CREDENTIAL_RELEASED,
            organisation_id=credential.OrganisationID,
            project_id=credential.ProjectID,
            actor=actor,
            entity_type="TrustScanCredential",
            entity_id=credential.CredentialID,
            metadata={**_metadata(credential), "scan_id": scan_id},
            commit=False,
        )
    db.session.flush()


def credential_for_scan(scan_id):
    binding = db.session.get(TrustScanCredentialBinding, int(scan_id))
    return binding.credential if binding is not None else None


def scan_credential_usable(scan_id, now=None):
    """Return (ok, reason) for a running authenticated scan."""
    credential = credential_for_scan(scan_id)
    if credential is None:
        return True, None
    now = now or _now()
    if credential.Status == CREDENTIAL_REVOKED:
        return False, "the approved credential was revoked"
    if credential.is_expired(now):
        return False, "the approved credential expired"
    if not credential.has_secret:
        return False, "the approved credential is no longer available"
    return True, None


def mark_login_failure(credential, reason):
    """Consume a single-use credential after a failed login."""
    if credential is None:
        return
    credential.FailureReason = str(reason)[:500]
    credential.LastUsedAt = _now()
    credential.Version += 1
    _purge_secret(credential, "login failed")
    audit.record(
        EVENT_CREDENTIAL_LOGIN_FAILED,
        organisation_id=credential.OrganisationID,
        project_id=credential.ProjectID,
        reason_code=ERR_CREDENTIAL_LOGIN_FAILED,
        entity_type="TrustScanCredential",
        entity_id=credential.CredentialID,
        metadata=_metadata(credential),
        commit=False,
    )


def decrypt_for_use(credential):
    try:
        return credential_crypto.decrypt_secret(credential.SecretEncrypted)
    except credential_crypto.CredentialCryptoError as exc:
        raise TrustError(
            str(exc), ERR_CREDENTIAL_STORAGE_UNAVAILABLE, 503
        ) from exc


def login_config(credential, password=None):
    extra = {}
    if credential.ExtraFieldsJson:
        try:
            parsed = json.loads(credential.ExtraFieldsJson)
            if isinstance(parsed, dict):
                extra = parsed
        except ValueError:
            extra = {}
    return LoginConfig(
        login_url=credential.LoginURL,
        username=credential.Username,
        password=password if password is not None else decrypt_for_use(credential),
        username_field=credential.UsernameField,
        password_field=credential.PasswordField,
        extra_fields=extra,
        success_url_contains=credential.SuccessURLContains,
        success_text=credential.SuccessText,
    )


def build_http_client(target_url):
    """Hardened client for a credential test (asset host only)."""
    allow_private = bool(
        current_app.config.get("SCANNER_ALLOW_PRIVATE_TARGETS", True)
    )
    base_host = urlparse(target_url).netloc.lower()

    def validator(url):
        ok, reason = check_target_allowed(url, allow_private=allow_private)
        if not ok:
            return False, reason
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "only http(s) is allowed"
        if parsed.netloc.lower() != base_host:
            return False, "outside the asset host"
        return True, ""

    return HttpClient(
        timeout=float(current_app.config.get("TRUST_CREDENTIAL_TIMEOUT", 10)),
        delay_ms=0,
        verify_ssl=current_app.config.get("SCANNER_VERIFY_SSL", True),
        url_validator=validator,
    )


def test_login(actor, access, credential, ip_address=None):
    _assert_project(credential, access)
    if credential.Status not in (CREDENTIAL_PENDING, CREDENTIAL_APPROVED):
        raise TrustError(
            "Only a pending or approved credential can be validated.",
            ERR_CREDENTIAL_NOT_APPROVED,
            409,
        )
    if credential.is_expired():
        _expire_and_purge(credential, "expired before test")
        db.session.commit()
        raise TrustError(
            "The credential has expired.", ERR_CREDENTIAL_EXPIRED, 409
        )
    cooldown = int(
        current_app.config.get("TRUST_CREDENTIAL_TEST_COOLDOWN_SECONDS", 10)
    )
    now = _now()
    if (
        credential.LastTestedAt is not None
        and (now - credential.LastTestedAt).total_seconds() < cooldown
    ):
        raise TrustError(
            f"Wait at least {cooldown} seconds between login tests.",
            ERR_RATE_LIMITED,
            429,
        )
    credential.LastTestedAt = now
    db.session.commit()

    http = build_http_client(credential.LoginURL)
    try:
        session = AuthSession(http, login_config(credential))
        result = session.login()
    except LoginError as exc:
        credential.FailureReason = str(exc)[:500]
        credential.Version += 1
        audit.record(
            EVENT_CREDENTIAL_LOGIN_FAILED,
            organisation_id=access.organisation_id,
            project_id=access.project_id,
            actor=actor,
            reason_code=ERR_CREDENTIAL_LOGIN_FAILED,
            entity_type="TrustScanCredential",
            entity_id=credential.CredentialID,
            metadata=_metadata(credential),
            ip_address=ip_address,
            commit=False,
        )
        db.session.commit()
        raise TrustError(str(exc), ERR_CREDENTIAL_LOGIN_FAILED, 409) from exc
    finally:
        http.close()

    credential.FailureReason = None
    credential.Version += 1
    audit.record(
        EVENT_CREDENTIAL_TESTED,
        organisation_id=access.organisation_id,
        project_id=access.project_id,
        actor=actor,
        entity_type="TrustScanCredential",
        entity_id=credential.CredentialID,
        metadata={**_metadata(credential), "final_url": result.get("FinalURL")},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return result


# --------------------------------------------------------------------- purge
def _purge_secret(credential, reason):
    if not credential.has_secret:
        return False
    credential.SecretEncrypted = None
    credential.Version += 1
    audit.record(
        EVENT_CREDENTIAL_SECRET_PURGED,
        organisation_id=credential.OrganisationID,
        project_id=credential.ProjectID,
        entity_type="TrustScanCredential",
        entity_id=credential.CredentialID,
        metadata={**_metadata(credential), "reason": reason},
        commit=False,
    )
    return True


def _expire_and_purge(credential, reason):
    if credential.Status in (CREDENTIAL_PENDING, CREDENTIAL_APPROVED,
                             CREDENTIAL_USED):
        credential.Status = CREDENTIAL_EXPIRED
        credential.StatusReason = credential.StatusReason or reason
    _purge_secret(credential, reason)


__all__ = [
    "create_credential",
    "approve_credential",
    "reject_credential",
    "revoke_credential",
    "list_credentials",
    "get_project_credential",
    "resolve_for_scan",
    "bind_to_scan",
    "unbind_from_scan",
    "credential_for_scan",
    "scan_credential_usable",
    "mark_login_failure",
    "decrypt_for_use",
    "login_config",
    "build_http_client",
    "test_login",
]
