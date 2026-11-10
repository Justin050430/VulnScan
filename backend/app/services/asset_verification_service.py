"""Asset registration and domain-ownership verification.

Supported methods (FYP slice):
  * ``DNS_TXT``  - TXT record ``_vulnscan-challenge.<host>`` containing
    ``vulnscan-verify=<token>``;
  * ``WEB_FILE`` - ``https://<host>/.well-known/vulnscan.txt`` containing the
    same value.

Only exact hostnames are accepted (no wildcards, no IP literals, no
sub-domain scanning).  Only a hash of the challenge token is stored, and the
stored evidence is a fixed human-readable statement that never contains the
token.
"""
import hashlib
import secrets
from datetime import datetime, timedelta

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import TrustAsset
from app.scanner.client import HttpClient
from app.scanner.safety import check_target_allowed
from app.services import trust_audit_service as audit
from app.trust.constants import (
    ASSET_EXPIRED,
    ASSET_PENDING,
    ASSET_REVOKED,
    ASSET_UNVERIFIED,
    ASSET_VERIFIED,
    ERR_ASSET_EXPIRED,
    ERR_ASSET_NOT_VERIFIED,
    ERR_ASSET_REVOKED,
    ERR_DUPLICATE_ASSET,
    ERR_VALIDATION,
    ERR_VERIFICATION_MISMATCH,
    ERR_VERIFICATION_PENDING,
    ERR_VERIFICATION_TOKEN_EXPIRED,
    EVENT_ASSET_REGISTERED,
    EVENT_ASSET_REVOKED,
    EVENT_ASSET_VERIFICATION_FAILED,
    EVENT_ASSET_VERIFICATION_STARTED,
    EVENT_ASSET_VERIFIED,
    OUTCOME_FAILURE,
    VERIFY_METHOD_DNS,
    VERIFY_METHOD_FILE,
    VERIFY_METHODS,
)
from app.trust.hostnames import normalise_hostname
from app.trust.permissions import TrustError

DNS_RECORD_PREFIX = "_vulnscan-challenge"
WEB_FILE_PATH = "/.well-known/vulnscan.txt"
CHALLENGE_PREFIX = "vulnscan-verify="


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _verification_days():
    return int(current_app.config.get("TRUST_ASSET_VERIFICATION_DAYS", 90))


def _token_minutes():
    return int(current_app.config.get("TRUST_VERIFICATION_TOKEN_MINUTES", 30))


def register_asset(actor, access, hostname, scheme="https", ip_address=None):
    host = normalise_hostname(hostname)
    scheme = (scheme or "https").lower()
    if scheme not in ("http", "https"):
        raise TrustError("Scheme must be http or https.", ERR_VALIDATION, 400)
    asset = TrustAsset(
        OrganisationID=access.organisation_id,
        ProjectID=access.project_id,
        Hostname=host,
        Scheme=scheme,
        VerificationStatus=ASSET_UNVERIFIED,
        CreatedByUserID=actor.UserID,
    )
    db.session.add(asset)
    try:
        db.session.flush()
        audit.record(
            EVENT_ASSET_REGISTERED,
            organisation_id=access.organisation_id,
            project_id=access.project_id,
            actor=actor,
            entity_type="TrustAsset",
            entity_id=asset.AssetID,
            metadata={"hostname": host, "scheme": scheme},
            ip_address=ip_address,
            commit=False,
        )
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise TrustError(
            "This hostname is already registered in the project.",
            ERR_DUPLICATE_ASSET,
            409,
        )
    return asset


def list_assets(project_id):
    return (
        TrustAsset.query.filter_by(ProjectID=int(project_id))
        .order_by(TrustAsset.Hostname.asc())
        .all()
    )


def refresh_status(asset, now=None):
    """Move a verified asset whose verification lapsed to ``Expired``."""
    now = now or datetime.utcnow()
    if (
        asset.VerificationStatus == ASSET_VERIFIED
        and asset.VerificationExpiresAt is not None
        and asset.VerificationExpiresAt <= now
    ):
        asset.VerificationStatus = ASSET_EXPIRED
        db.session.commit()
    return asset


def ensure_verified(asset):
    """Raise the precise denial for an asset that cannot be scanned."""
    refresh_status(asset)
    if asset.VerificationStatus == ASSET_REVOKED:
        raise TrustError("This asset has been revoked.", ERR_ASSET_REVOKED, 403)
    if asset.VerificationStatus == ASSET_EXPIRED:
        raise TrustError(
            "Asset verification has expired; re-verify before scanning.",
            ERR_ASSET_EXPIRED,
            403,
        )
    if asset.VerificationStatus != ASSET_VERIFIED:
        raise TrustError(
            "The asset must be verified before an active scan can start.",
            ERR_ASSET_NOT_VERIFIED,
            403,
            {"asset_id": asset.AssetID, "status": asset.VerificationStatus},
        )
    return asset


def start_verification(actor, access, asset, method, ip_address=None):
    method = (method or "").upper()
    if method not in VERIFY_METHODS:
        raise TrustError(
            "Verification method must be DNS_TXT or WEB_FILE.",
            ERR_VALIDATION,
            400,
        )
    if asset.VerificationStatus == ASSET_REVOKED:
        raise TrustError("This asset has been revoked.", ERR_ASSET_REVOKED, 403)

    token = secrets.token_urlsafe(32)
    asset.VerificationMethod = method
    asset.VerificationTokenHash = _hash_token(token)
    asset.VerificationTokenExpiresAt = datetime.utcnow() + timedelta(
        minutes=_token_minutes()
    )
    asset.VerificationStatus = ASSET_PENDING
    asset.Version += 1
    audit.record(
        EVENT_ASSET_VERIFICATION_STARTED,
        organisation_id=asset.OrganisationID,
        project_id=asset.ProjectID,
        actor=actor,
        entity_type="TrustAsset",
        entity_id=asset.AssetID,
        metadata={"hostname": asset.Hostname, "method": method},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()

    challenge_value = f"{CHALLENGE_PREFIX}{token}"
    if method == VERIFY_METHOD_DNS:
        challenge = {
            "Method": method,
            "RecordName": f"{DNS_RECORD_PREFIX}.{asset.Hostname}",
            "RecordType": "TXT",
            "RecordValue": challenge_value,
            "ExpiresAt": asset.VerificationTokenExpiresAt.isoformat(),
        }
    else:
        scheme = asset.Scheme or "https"
        port = int(current_app.config.get("TRUST_WEBFILE_PORT", 0) or 0)
        netloc = f"{asset.Hostname}:{port}" if port else asset.Hostname
        challenge = {
            "Method": method,
            "FileURL": f"{scheme}://{netloc}{WEB_FILE_PATH}",
            "FileContent": challenge_value,
            "ExpiresAt": asset.VerificationTokenExpiresAt.isoformat(),
        }
    return asset, challenge


def _resolve_txt(record_name):
    """Return TXT record strings for a name (patchable in tests)."""
    import dns.resolver

    answers = dns.resolver.resolve(record_name, "TXT", lifetime=8)
    values = []
    for answer in answers:
        values.append(b"".join(answer.strings).decode("utf-8", errors="replace"))
    return values


def _fetch_well_known(asset):
    scheme = asset.Scheme or "https"
    port = int(current_app.config.get("TRUST_WEBFILE_PORT", 0) or 0)
    host = asset.Hostname
    netloc = f"{host}:{port}" if port else host
    url = f"{scheme}://{netloc}{WEB_FILE_PATH}"

    allow_private = bool(
        current_app.config.get("SCANNER_ALLOW_PRIVATE_TARGETS", True)
    )
    ok, reason = check_target_allowed(url, allow_private=allow_private)
    if not ok:
        return None, reason

    def _no_redirect(_target):
        return False, "redirects are not followed during asset verification"

    http = HttpClient(
        timeout=float(current_app.config.get("TRUST_WEBFILE_TIMEOUT", 8)),
        delay_ms=0,
        max_body_bytes=int(current_app.config.get("TRUST_WEBFILE_MAX_BYTES", 4096)),
        max_redirects=0,
        url_validator=_no_redirect,
    )
    # No credentials or cookies are ever sent.
    http._session.cookies.clear()
    http._session.headers.pop("Authorization", None)
    try:
        response = http.get(url)
    finally:
        http.close()
    if not response.ok:
        return None, response.error or "request failed"
    if response.status_code != 200:
        return None, f"HTTP {response.status_code}"
    return response.text or "", None


def check_verification(actor, access, asset, ip_address=None):
    if asset.VerificationMethod is None:
        raise TrustError(
            "Start verification before checking it.", ERR_VERIFICATION_PENDING, 409
        )
    if (
        asset.VerificationTokenExpiresAt is None
        or asset.VerificationTokenExpiresAt <= datetime.utcnow()
    ):
        raise TrustError(
            "The verification challenge has expired; start again.",
            ERR_VERIFICATION_TOKEN_EXPIRED,
            409,
        )

    expected_suffix = None
    # The plaintext token is only known to the caller; compare hashes instead.
    stored_hash = asset.VerificationTokenHash
    if asset.VerificationMethod == VERIFY_METHOD_DNS:
        record_name = f"{DNS_RECORD_PREFIX}.{asset.Hostname}"
        try:
            values = _resolve_txt(record_name)
        except Exception as exc:  # network/DNS failure
            values = []
            reason = f"DNS lookup failed: {type(exc).__name__}"
        else:
            reason = "TXT record not found"

        matched = any(
            _token_matches(value, stored_hash) for value in (values or [])
        )
        evidence = (
            f"TXT record matched at {record_name}"
            if matched else None
        )
    else:
        body, error = _fetch_well_known(asset)
        if body is None:
            matched = False
            reason = error or "file not retrievable"
        else:
            matched = _token_matches(body, stored_hash)
            reason = "file content did not match the challenge"
        evidence = (
            f"{WEB_FILE_PATH} matched on {asset.Hostname}" if matched else None
        )

    if not matched:
        audit.record(
            EVENT_ASSET_VERIFICATION_FAILED,
            outcome=OUTCOME_FAILURE,
            organisation_id=asset.OrganisationID,
            project_id=asset.ProjectID,
            actor=actor,
            entity_type="TrustAsset",
            entity_id=asset.AssetID,
            reason_code=ERR_VERIFICATION_MISMATCH,
            metadata={"hostname": asset.Hostname, "method": asset.VerificationMethod},
            ip_address=ip_address,
        )
        raise TrustError(
            f"Asset verification failed: {reason}.",
            ERR_VERIFICATION_MISMATCH,
            409,
        )

    now = datetime.utcnow()
    asset.VerificationStatus = ASSET_VERIFIED
    asset.VerifiedAt = now
    asset.VerificationExpiresAt = now + timedelta(days=_verification_days())
    asset.VerificationEvidence = evidence
    asset.LastVerificationIP = ip_address
    asset.VerifiedByUserID = actor.UserID
    asset.VerificationTokenHash = None
    asset.VerificationTokenExpiresAt = None
    asset.Version += 1
    audit.record(
        EVENT_ASSET_VERIFIED,
        organisation_id=asset.OrganisationID,
        project_id=asset.ProjectID,
        actor=actor,
        entity_type="TrustAsset",
        entity_id=asset.AssetID,
        metadata={
            "hostname": asset.Hostname,
            "method": asset.VerificationMethod,
            "expires_at": asset.VerificationExpiresAt.isoformat(),
        },
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return asset, {
        "Method": asset.VerificationMethod,
        "Evidence": evidence,
        "CheckedAt": now.isoformat(),
    }


def _token_matches(candidate, stored_hash):
    """Compare a published challenge value against the stored token hash."""
    if not candidate or not stored_hash:
        return False
    text = str(candidate).strip()
    if text.startswith(CHALLENGE_PREFIX):
        text = text[len(CHALLENGE_PREFIX):]
    return _hash_token(text.strip()) == stored_hash


def revoke_asset(actor, access, asset, reason=None, ip_address=None):
    asset.VerificationStatus = ASSET_REVOKED
    asset.RevokedAt = datetime.utcnow()
    asset.RevokedByUserID = actor.UserID
    asset.VerificationTokenHash = None
    asset.VerificationTokenExpiresAt = None
    asset.Version += 1
    audit.record(
        EVENT_ASSET_REVOKED,
        organisation_id=asset.OrganisationID,
        project_id=asset.ProjectID,
        actor=actor,
        entity_type="TrustAsset",
        entity_id=asset.AssetID,
        metadata={"hostname": asset.Hostname, "reason": (reason or "")[:200]},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return asset
