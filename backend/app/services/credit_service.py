"""Single-use scan-credit reservation, consumption and release."""
from datetime import datetime, timedelta

from flask import current_app

from app.extensions import db
from app.models import TrustCreditRedemption, TrustScanCredit
from app.services import trust_audit_service as audit
from app.trust.constants import (
    CREDIT_AVAILABLE,
    CREDIT_CONSUMED,
    CREDIT_EXPIRED,
    CREDIT_RESERVED,
    ERR_CREDIT_NOT_AVAILABLE,
    ERR_NOT_FOUND,
    EVENT_CREDIT_CONSUMED,
    EVENT_CREDIT_EXPIRED,
    EVENT_CREDIT_RELEASED,
    EVENT_CREDIT_RESERVED,
    OUTCOME_FAILURE,
    REDEMPTION_CONSUMED,
    REDEMPTION_RELEASED,
    REDEMPTION_RESERVED,
)
from app.trust.permissions import TrustError


def _reservation_minutes():
    return int(current_app.config.get("TRUST_CREDIT_RESERVATION_MINUTES", 15))


def list_credits(project_id, status=None):
    query = TrustScanCredit.query.filter_by(ProjectID=int(project_id))
    if status:
        query = query.filter_by(Status=status)
    return query.order_by(TrustScanCredit.CreditID.desc()).all()


def available_credits(project_id, now=None):
    now = now or datetime.utcnow()
    return TrustScanCredit.query.filter(
        TrustScanCredit.ProjectID == int(project_id),
        TrustScanCredit.Status == CREDIT_AVAILABLE,
        TrustScanCredit.ExpiresAt > now,
    ).all()


def expire_stale(project_id=None, now=None):
    now = now or datetime.utcnow()
    query = TrustScanCredit.query.filter(
        TrustScanCredit.Status == CREDIT_AVAILABLE,
        TrustScanCredit.ExpiresAt <= now,
    )
    if project_id is not None:
        query = query.filter(TrustScanCredit.ProjectID == int(project_id))
    expired = query.all()
    for credit in expired:
        credit.Status = CREDIT_EXPIRED
        audit.record(
            EVENT_CREDIT_EXPIRED,
            organisation_id=credit.OrganisationID,
            project_id=credit.ProjectID,
            entity_type="TrustScanCredit",
            entity_id=credit.CreditID,
            commit=False,
        )
    if expired:
        db.session.commit()
    return expired


def find_credit(project_id, credit_ref):
    """Resolve a credit by internal id or public UUID inside a project."""
    query = TrustScanCredit.query.filter_by(ProjectID=int(project_id))
    if isinstance(credit_ref, int) or str(credit_ref).isdigit():
        return query.filter_by(CreditID=int(credit_ref)).first()
    return query.filter_by(CreditUUID=str(credit_ref)).first()


def reserve_credit(credit_id, actor, now=None):
    """Atomically move one Available credit to Reserved.

    Uses a single conditional UPDATE so two concurrent scan starts can never
    both reserve the same credit.
    """
    now = now or datetime.utcnow()
    reserved_until = now + timedelta(minutes=_reservation_minutes())
    rows = (
        db.session.query(TrustScanCredit)
        .filter(
            TrustScanCredit.CreditID == int(credit_id),
            TrustScanCredit.Status == CREDIT_AVAILABLE,
            TrustScanCredit.ExpiresAt > now,
        )
        .update(
            {
                TrustScanCredit.Status: CREDIT_RESERVED,
                TrustScanCredit.ReservedAt: now,
                TrustScanCredit.ReservedUntil: reserved_until,
                TrustScanCredit.ReservedByUserID: actor.UserID,
                TrustScanCredit.Version: TrustScanCredit.Version + 1,
            },
            synchronize_session=False,
        )
    )
    if rows != 1:
        db.session.rollback()
        raise TrustError(
            "The selected credit is not available.", ERR_CREDIT_NOT_AVAILABLE, 409
        )
    db.session.flush()
    return db.session.get(TrustScanCredit, int(credit_id)), reserved_until


def create_redemption(credit, scan_id=None, user_id=None, idempotency_key=None,
                      project_id=None, now=None):
    now = now or datetime.utcnow()
    redemption = TrustCreditRedemption(
        CreditID=credit.CreditID,
        ScanID=scan_id,
        OrganisationID=credit.OrganisationID,
        ProjectID=project_id or credit.ProjectID,
        UserID=user_id,
        Status=REDEMPTION_RESERVED,
        IdempotencyKey=idempotency_key,
        ReservedAt=now,
    )
    db.session.add(redemption)
    db.session.flush()
    return redemption


def consume_for_scan(scan_id, now=None):
    """Mark the redemption and credit consumed when the scan actually starts."""
    redemption = TrustCreditRedemption.query.filter_by(
        ScanID=int(scan_id), Status=REDEMPTION_RESERVED
    ).first()
    if redemption is None:
        return None
    now = now or datetime.utcnow()
    redemption.Status = REDEMPTION_CONSUMED
    redemption.ConsumedAt = now
    redemption.Version += 1
    credit = db.session.get(TrustScanCredit, redemption.CreditID)
    if credit is not None:
        credit.Status = CREDIT_CONSUMED
        credit.ConsumedAt = now
        credit.Version += 1
    audit.record(
        EVENT_CREDIT_CONSUMED,
        organisation_id=redemption.OrganisationID,
        project_id=redemption.ProjectID,
        actor_user_id=redemption.UserID,
        entity_type="TrustScanCredit",
        entity_id=redemption.CreditID,
        metadata={"scan_id": int(scan_id), "redemption_id": redemption.RedemptionID},
        commit=False,
    )
    db.session.commit()
    return redemption


def release_redemption(redemption, reason="Reservation released", now=None,
                       mark_scan_failed=False):
    """Return a reserved credit to Available after a failed start/enqueue."""
    if redemption is None or redemption.Status != REDEMPTION_RESERVED:
        return None
    now = now or datetime.utcnow()
    redemption.Status = REDEMPTION_RELEASED
    redemption.ReleasedAt = now
    redemption.FailureReason = (reason or "")[:255]
    redemption.Version += 1
    credit = db.session.get(TrustScanCredit, redemption.CreditID)
    if credit is not None and credit.Status == CREDIT_RESERVED:
        credit.Status = CREDIT_AVAILABLE
        credit.ReservedAt = None
        credit.ReservedUntil = None
        credit.ReservedByUserID = None
        credit.Version += 1
    audit.record(
        EVENT_CREDIT_RELEASED,
        outcome=OUTCOME_FAILURE,
        organisation_id=redemption.OrganisationID,
        project_id=redemption.ProjectID,
        actor_user_id=redemption.UserID,
        entity_type="TrustScanCredit",
        entity_id=redemption.CreditID,
        reason_code="CREDIT_RELEASED",
        metadata={"redemption_id": redemption.RedemptionID, "reason": (reason or "")[:200]},
        commit=False,
    )
    db.session.commit()
    return redemption


def release_expired_reservations(now=None):
    """Release reservations whose worker never started before the timeout."""
    now = now or datetime.utcnow()
    stale = TrustCreditRedemption.query.filter(
        TrustCreditRedemption.Status == REDEMPTION_RESERVED,
        TrustCreditRedemption.ScanID.is_(None),
    ).all()
    released = []
    for redemption in stale:
        credit = db.session.get(TrustScanCredit, redemption.CreditID)
        if credit is None:
            continue
        if credit.ReservedUntil is not None and credit.ReservedUntil > now:
            continue
        release_redemption(
            redemption, reason="Reservation timed out before the scan started"
        )
        released.append(redemption.RedemptionID)
    return released
