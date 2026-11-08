"""Server-side scan gating, atomic credit reservation and scan creation.

A scan may start only when *all* of the following hold:
  * active project membership with ``scan.start``;
  * verified exact-host asset (not expired, not revoked);
  * active, unexpired authorisation attestation for that asset;
  * an available project credit;
  * the target URL host matches the verified asset exactly;
  * no other Pending/Running scan for the asset.
"""
import logging
import uuid
from datetime import datetime

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import (
    Scan,
    ScanProfile,
    TrustAsset,
    TrustCreditRedemption,
    TrustScanContext,
    TrustScanCredit,
)
from app.scanner.engine import ScanValidationError, validate_scan_request
from app.services import attestation_service, credit_service
from app.services import trust_audit_service as audit
from app.services.asset_verification_service import ensure_verified, refresh_status
from app.services.audit_service import write_audit
from app.utils.constants import (
    AUDIT_CATEGORY_SCAN,
    SCAN_STATUS_CANCELLED,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
)
from app.trust.constants import (
    CREDIT_AVAILABLE,
    ERR_ACTIVE_SCAN_EXISTS,
    ERR_CREDIT_NOT_AVAILABLE,
    ERR_CREDIT_REQUIRED,
    ERR_IDEMPOTENCY_CONFLICT,
    ERR_NOT_FOUND,
    ERR_PERMISSION_DENIED,
    ERR_TARGET_HOST_MISMATCH,
    ERR_VALIDATION,
    EVENT_CREDIT_RESERVED,
    EVENT_SCAN_DENIED,
    EVENT_SCAN_STARTED,
    OUTCOME_DENIED,
    PERM_SCAN_START,
    REDEMPTION_RESERVED,
)
from app.trust.hostnames import url_matches_asset
from app.trust.permissions import TrustError

logger = logging.getLogger("vulnscan.trust.gate")

ACTIVE_SCAN_STATUSES = (SCAN_STATUS_PENDING, SCAN_STATUS_RUNNING)


def _default_target_url(asset):
    return f"{(asset.Scheme or 'https')}://{asset.Hostname}/"


def _active_scan_for_asset(asset_id):
    return (
        db.session.query(Scan)
        .join(TrustScanContext, TrustScanContext.ScanID == Scan.ScanID)
        .filter(
            TrustScanContext.AssetID == int(asset_id),
            Scan.Status.in_(ACTIVE_SCAN_STATUSES),
        )
        .first()
    )


def evaluate(access, asset, attestation_id=None):
    """Read-only readiness evaluation used by the pre-scan checklist."""
    checks = {}

    checks["Permission"] = {
        "Ok": access.has(PERM_SCAN_START),
        "Code": None if access.has(PERM_SCAN_START) else ERR_PERMISSION_DENIED,
    }

    refresh_status(asset)
    if asset.OrganisationID != access.organisation_id or asset.ProjectID != access.project_id:
        raise TrustError("Asset not found.", ERR_NOT_FOUND, 404)

    asset_ok = asset.is_currently_verified()
    checks["Asset"] = {
        "Ok": asset_ok,
        "Status": asset.VerificationStatus,
        "ExpiresAt": (
            asset.VerificationExpiresAt.isoformat()
            if asset.VerificationExpiresAt else None
        ),
    }

    attestation = attestation_service.active_for_asset(asset)
    checks["Attestation"] = {
        "Ok": attestation is not None,
        "AttestationID": attestation.AttestationID if attestation else None,
        "ExpiresAt": attestation.ExpiresAt.isoformat() if attestation else None,
    }

    available = credit_service.available_credits(access.project_id)
    checks["Credit"] = {"Ok": bool(available), "AvailableCount": len(available)}

    active = _active_scan_for_asset(asset.AssetID)
    checks["ActiveScan"] = {
        "Ok": active is None,
        "ScanID": active.ScanID if active else None,
    }

    order = ["Permission", "Asset", "Attestation", "Credit", "ActiveScan"]
    next_action = None
    for name in order:
        if not checks[name]["Ok"]:
            next_action = {
                "Permission": "REQUEST_SCAN_ROLE",
                "Asset": "VERIFY_ASSET",
                "Attestation": "CREATE_ATTESTATION",
                "Credit": "BUY_CREDIT",
                "ActiveScan": "WAIT_FOR_ACTIVE_SCAN",
            }[name]
            break

    return {
        "Ready": all(checks[name]["Ok"] for name in order),
        "Checks": checks,
        "NextAction": next_action,
        "Asset": asset.to_dict(),
    }


def _deny(access, actor, asset, code, message, status=403, metadata=None,
          ip_address=None):
    audit.record(
        EVENT_SCAN_DENIED,
        outcome=OUTCOME_DENIED,
        organisation_id=access.organisation_id,
        project_id=access.project_id,
        actor=actor,
        reason_code=code,
        entity_type="TrustAsset",
        entity_id=asset.AssetID if asset else None,
        metadata=metadata or {},
        ip_address=ip_address,
    )
    return TrustError(message, code, status, metadata)


def start_gated_scan(access, actor, *, asset, scan_profile_id, scan_name=None,
                     attestation_id=None, credit_ref=None, idempotency_key=None,
                     target_url=None, ip_address=None, run_async=True):
    """Validate every gate, reserve one credit atomically and create the scan."""
    from app.services import scan_service

    if not access.has(PERM_SCAN_START):
        raise _deny(
            access, actor, asset, ERR_PERMISSION_DENIED,
            "Scanning requires an active PROJECT_OWNER or SCAN_OPERATOR role.",
            ip_address=ip_address,
        )

    if asset is None or asset.ProjectID != access.project_id:
        raise TrustError("Asset not found.", ERR_NOT_FOUND, 404)

    ensure_verified(asset)

    attestation = attestation_service.resolve_valid(asset, attestation_id)

    if not credit_ref:
        raise _deny(
            access, actor, asset, ERR_CREDIT_REQUIRED,
            "A scan credit is required to start a scan.",
            status=402,
            ip_address=ip_address,
        )
    credit = credit_service.find_credit(access.project_id, credit_ref)
    if credit is None:
        raise TrustError("Credit not found.", ERR_NOT_FOUND, 404)
    if not credit.is_available():
        raise _deny(
            access, actor, asset, ERR_CREDIT_NOT_AVAILABLE,
            "The selected credit is not available.",
            status=409,
            metadata={"credit_uuid": credit.CreditUUID, "status": credit.Status},
            ip_address=ip_address,
        )

    if target_url:
        if not url_matches_asset(target_url, asset.Hostname, asset.Scheme):
            raise _deny(
                access, actor, asset, ERR_TARGET_HOST_MISMATCH,
                "The target URL must match the verified asset exactly.",
                status=400,
                metadata={"expected_host": asset.Hostname},
                ip_address=ip_address,
            )
    else:
        target_url = _default_target_url(asset)

    profile = (
        db.session.get(ScanProfile, int(scan_profile_id)) if scan_profile_id else None
    )
    if profile is None:
        raise TrustError(
            "A valid scan profile is required.", ERR_VALIDATION, 400
        )
    try:
        normalised_target = validate_scan_request(target_url, profile)
    except ScanValidationError as exc:
        raise TrustError(str(exc), ERR_VALIDATION, 400) from exc

    active = _active_scan_for_asset(asset.AssetID)
    if active is not None:
        raise _deny(
            access, actor, asset, ERR_ACTIVE_SCAN_EXISTS,
            "An active scan already exists for this asset.",
            status=409,
            metadata={"scan_id": active.ScanID},
            ip_address=ip_address,
        )

    idempotency_key = str(idempotency_key or uuid.uuid4())[:64]
    replay = TrustCreditRedemption.query.filter_by(
        IdempotencyKey=idempotency_key
    ).first()
    if replay is not None:
        if replay.ProjectID != access.project_id:
            raise TrustError(
                "This idempotency key was used in another project.",
                ERR_IDEMPOTENCY_CONFLICT,
                409,
            )
        replay_scan = db.session.get(Scan, replay.ScanID) if replay.ScanID else None
        return {
            "Scan": replay_scan,
            "Credit": db.session.get(TrustScanCredit, replay.CreditID),
            "Redemption": replay,
            "IdempotentReplay": True,
        }

    scan = Scan(
        ScanName=(_scan_name(scan_name, normalised_target)),
        TargetURL=normalised_target,
        Status=SCAN_STATUS_PENDING,
        StartedAt=datetime.utcnow(),
        UserID=actor.UserID,
        ScanProfileID=profile.ScanProfileID,
    )

    # ------------------------------------------------------- atomic section
    try:
        credit, reserved_until = credit_service.reserve_credit(credit.CreditID, actor)
        redemption = TrustCreditRedemption(
            CreditID=credit.CreditID,
            ScanID=None,
            OrganisationID=access.organisation_id,
            ProjectID=access.project_id,
            UserID=actor.UserID,
            Status=REDEMPTION_RESERVED,
            IdempotencyKey=idempotency_key,
            ReservedAt=datetime.utcnow(),
        )
        db.session.add(redemption)
        db.session.flush()

        db.session.add(scan)
        db.session.flush()

        db.session.add(
            TrustScanContext(
                ScanID=scan.ScanID,
                OrganisationID=access.organisation_id,
                ProjectID=access.project_id,
                AssetID=asset.AssetID,
                AttestationID=attestation.AttestationID,
                CreditID=credit.CreditID,
                StartedByUserID=actor.UserID,
            )
        )
        redemption.ScanID = scan.ScanID
        db.session.flush()

        audit.record(
            EVENT_CREDIT_RESERVED,
            organisation_id=access.organisation_id,
            project_id=access.project_id,
            actor=actor,
            entity_type="TrustScanCredit",
            entity_id=credit.CreditID,
            metadata={
                "scan_id": scan.ScanID,
                "redemption_id": redemption.RedemptionID,
                "reserved_until": reserved_until.isoformat(),
            },
            ip_address=ip_address,
            commit=False,
        )
        audit.record(
            EVENT_SCAN_STARTED,
            organisation_id=access.organisation_id,
            project_id=access.project_id,
            actor=actor,
            entity_type="Scan",
            entity_id=scan.ScanID,
            metadata={
                "asset_id": asset.AssetID,
                "hostname": asset.Hostname,
                "attestation_id": attestation.AttestationID,
                "credit_id": credit.CreditID,
                "profile_id": profile.ScanProfileID,
            },
            ip_address=ip_address,
            commit=False,
        )
        write_audit(
            category=AUDIT_CATEGORY_SCAN,
            action="SCAN_CREATED",
            description=(
                f"Vulnerability scan '{scan.ScanName}' created for verified "
                f"asset {asset.Hostname} using profile '{profile.Name}'."
            ),
            user=actor,
            entity_type="Scan",
            entity_id=scan.ScanID,
            ip_address=ip_address,
            commit=False,
        )
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        existing = TrustCreditRedemption.query.filter_by(
            IdempotencyKey=idempotency_key
        ).first()
        if existing is not None:
            return {
                "Scan": db.session.get(Scan, existing.ScanID)
                if existing.ScanID else None,
                "Credit": db.session.get(TrustScanCredit, existing.CreditID),
                "Redemption": existing,
                "IdempotentReplay": True,
            }
        raise _deny(
            access, actor, asset, ERR_CREDIT_NOT_AVAILABLE,
            "The selected credit is not available.",
            status=409,
            ip_address=ip_address,
        )
    except TrustError:
        db.session.rollback()
        raise
    except Exception:
        db.session.rollback()
        logger.exception("Gated scan creation failed for asset %s", asset.AssetID)
        raise

    # ------------------------------------------------------- launch worker
    try:
        if run_async:
            scan_service.spawn_scan_worker(scan.ScanID)
        else:
            scan_service.execute_scan_sync(scan.ScanID)
            db.session.expire(scan)
    except Exception:
        logger.exception("Failed to launch scan %s; releasing credit", scan.ScanID)
        redemption = TrustCreditRedemption.query.filter_by(ScanID=scan.ScanID).first()
        credit_service.release_redemption(
            redemption, reason="Scan worker could not be started"
        )
        fresh = db.session.get(Scan, scan.ScanID)
        if fresh is not None:
            fresh.Status = SCAN_STATUS_FAILED
            fresh.FinishedAt = datetime.utcnow()
            db.session.commit()
        raise TrustError(
            "The scan could not be started; the credit was released.",
            ERR_CREDIT_NOT_AVAILABLE,
            503,
        )

    return {
        "Scan": scan,
        "Credit": credit,
        "Redemption": redemption,
        "IdempotentReplay": False,
    }


def _scan_name(name, target_url):
    from urllib.parse import urlparse

    if name and str(name).strip():
        return str(name).strip()[:100]
    host = urlparse(target_url).netloc
    return f"Vulnerability Scan - {host}"[:100]


def cancel_scan(access, actor, scan, ip_address=None):
    """Best-effort cancellation.  The worker stops between pages."""
    if scan.Status in (SCAN_STATUS_COMPLETED, SCAN_STATUS_CANCELLED):
        return scan
    scan.Status = SCAN_STATUS_CANCELLED
    scan.FinishedAt = datetime.utcnow()
    audit.record(
        "SCAN_CANCELLED",
        organisation_id=access.organisation_id,
        project_id=access.project_id,
        actor=actor,
        entity_type="Scan",
        entity_id=scan.ScanID,
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return scan


def scan_is_cancelled(scan_id):
    status = (
        db.session.query(Scan.Status).filter(Scan.ScanID == int(scan_id)).scalar()
    )
    return status == SCAN_STATUS_CANCELLED


def consume_credit_for_scan(scan_id):
    """Called when the engine transitions a scan to Running."""
    try:
        return credit_service.consume_for_scan(scan_id)
    except Exception:
        logger.exception("Failed to consume credit for scan %s", scan_id)
        return None


def release_if_never_started(scan_id, reason):
    redemption = TrustCreditRedemption.query.filter_by(
        ScanID=int(scan_id), Status=REDEMPTION_RESERVED
    ).first()
    if redemption is not None:
        credit_service.release_redemption(redemption, reason=reason)
