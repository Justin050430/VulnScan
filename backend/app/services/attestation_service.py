"""Authorisation attestation lifecycle (Trust Boundary Extension)."""
from datetime import datetime, timedelta

from flask import current_app

from app.extensions import db
from app.models import TrustAuthorizationAttestation
from app.services import trust_audit_service as audit
from app.trust.constants import (
    ATTESTATION_ACTIVE,
    ATTESTATION_EXPIRED,
    ATTESTATION_REVOKED,
    ATTESTATION_STATEMENT_VERSION,
    ERR_ATTESTATION_EXPIRED,
    ERR_ATTESTATION_MISMATCH,
    ERR_ATTESTATION_REQUIRED,
    ERR_ATTESTATION_REVOKED,
    ERR_VALIDATION,
    EVENT_ATTESTATION_CREATED,
    EVENT_ATTESTATION_REVOKED,
)
from app.trust.permissions import TrustError
from app.trust.statements import build_statement


def _default_days():
    return int(current_app.config.get("TRUST_ATTESTATION_DEFAULT_DAYS", 30))


def _max_days():
    return int(current_app.config.get("TRUST_ATTESTATION_MAX_DAYS", 90))


def expire_stale(asset, now=None):
    """Mark lapsed attestations of an asset as Expired."""
    now = now or datetime.utcnow()
    changed = False
    for attestation in TrustAuthorizationAttestation.query.filter_by(
        AssetID=asset.AssetID, Status=ATTESTATION_ACTIVE
    ).all():
        if attestation.ExpiresAt <= now:
            attestation.Status = ATTESTATION_EXPIRED
            changed = True
    if changed:
        db.session.commit()


def create_attestation(actor, access, asset, *, days=None, reference=None,
                       scope=None, version=None, ip_address=None,
                       user_agent_hash=None, statement_version=None):
    version = statement_version or version or ATTESTATION_STATEMENT_VERSION
    if version != ATTESTATION_STATEMENT_VERSION:
        raise TrustError(
            "Unknown attestation statement version.", ERR_VALIDATION, 400
        )
    if days is None:
        days = _default_days()
    try:
        days = int(days)
    except (TypeError, ValueError):
        raise TrustError("expires_in_days must be an integer.",
                         ERR_VALIDATION, 400) from None
    if days < 1 or days > _max_days():
        raise TrustError(
            f"expires_in_days must be between 1 and {_max_days()}.",
            ERR_VALIDATION,
            400,
        )

    now = datetime.utcnow()
    expires_at = now + timedelta(days=days)
    stmt_version, statement_text, stmt_hash = build_statement(version)

    # Only one active attestation per asset (a filtered unique index enforces
    # this too); supersede the previous one in the same transaction.
    for previous in TrustAuthorizationAttestation.query.filter_by(
        AssetID=asset.AssetID, Status=ATTESTATION_ACTIVE
    ).all():
        previous.Status = ATTESTATION_EXPIRED

    attestation = TrustAuthorizationAttestation(
        OrganisationID=asset.OrganisationID,
        ProjectID=asset.ProjectID,
        AssetID=asset.AssetID,
        AttestedByUserID=actor.UserID,
        StatementVersion=stmt_version,
        StatementText=statement_text,
        StatementHash=stmt_hash,
        ScopeJson=scope,
        Status=ATTESTATION_ACTIVE,
        AttestedAt=now,
        ExpiresAt=expires_at,
        IPAddress=ip_address,
        UserAgentHash=user_agent_hash,
        Reference=(reference or None),
    )
    db.session.add(attestation)
    db.session.flush()
    audit.record(
        EVENT_ATTESTATION_CREATED,
        organisation_id=asset.OrganisationID,
        project_id=asset.ProjectID,
        actor=actor,
        entity_type="TrustAuthorizationAttestation",
        entity_id=attestation.AttestationID,
        metadata={
            "asset_id": asset.AssetID,
            "hostname": asset.Hostname,
            "statement_version": stmt_version,
            "expires_at": expires_at.isoformat(),
            "reference": (reference or "")[:200],
        },
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return attestation


def list_attestations(asset_id):
    return (
        TrustAuthorizationAttestation.query.filter_by(AssetID=int(asset_id))
        .order_by(TrustAuthorizationAttestation.AttestationID.desc())
        .all()
    )


def active_for_asset(asset, now=None):
    now = now or datetime.utcnow()
    expire_stale(asset, now)
    return (
        TrustAuthorizationAttestation.query.filter_by(
            AssetID=asset.AssetID, Status=ATTESTATION_ACTIVE
        )
        .order_by(TrustAuthorizationAttestation.AttestationID.desc())
        .first()
    )


def resolve_valid(asset, attestation_id=None, now=None):
    """Return the attestation authorising a scan, or raise the precise denial."""
    now = now or datetime.utcnow()
    attestation = None
    if attestation_id:
        attestation = db.session.get(
            TrustAuthorizationAttestation, int(attestation_id)
        )
        if attestation is None or attestation.AssetID != asset.AssetID:
            raise TrustError(
                "The attestation does not belong to this asset.",
                ERR_ATTESTATION_MISMATCH,
                403,
            )
        if attestation.Status == ATTESTATION_REVOKED:
            raise TrustError(
                "This attestation has been revoked.", ERR_ATTESTATION_REVOKED, 403
            )
        if attestation.Status != ATTESTATION_ACTIVE or attestation.ExpiresAt <= now:
            raise TrustError(
                "This attestation has expired.", ERR_ATTESTATION_EXPIRED, 403
            )
        return attestation

    attestation = active_for_asset(asset, now)
    if attestation is None:
        raise TrustError(
            "An active authorisation attestation is required before scanning.",
            ERR_ATTESTATION_REQUIRED,
            403,
        )
    return attestation


def revoke_attestation(actor, access, attestation, reason=None, ip_address=None):
    if attestation.Status == ATTESTATION_REVOKED:
        return attestation
    attestation.Status = ATTESTATION_REVOKED
    attestation.RevokedAt = datetime.utcnow()
    attestation.RevokedByUserID = actor.UserID
    attestation.Version += 1
    audit.record(
        EVENT_ATTESTATION_REVOKED,
        organisation_id=attestation.OrganisationID,
        project_id=attestation.ProjectID,
        actor=actor,
        entity_type="TrustAuthorizationAttestation",
        entity_id=attestation.AttestationID,
        metadata={"asset_id": attestation.AssetID, "reason": (reason or "")[:200]},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return attestation
