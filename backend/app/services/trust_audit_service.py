"""Append-only Trust Boundary audit ledger.

Records are insert-only.  There is deliberately no update/delete helper and no
API route that mutates an existing event.  Metadata is redacted and truncated
before storage: raw tokens, secrets, credentials and payment data must never
reach this table.
"""
import hashlib
import json
import uuid
from datetime import datetime

from app.extensions import db
from app.models import TrustAuditEvent
from app.trust.constants import OUTCOME_SUCCESS

_REDACT_KEYS = (
    "token", "secret", "password", "authorization", "cookie", "signature",
    "card", "cvv", "pan", "credential",
)
_MAX_METADATA = 2000
_MAX_VALUE = 200


def _redact(value, depth=0):
    if depth > 3:
        return "[truncated]"
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if any(marker in str(key).lower() for marker in _REDACT_KEYS):
                cleaned[key] = "[redacted]"
            else:
                cleaned[key] = _redact(item, depth + 1)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [_redact(item, depth + 1) for item in value[:20]]
    if isinstance(value, str):
        return value[:_MAX_VALUE]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:_MAX_VALUE]


def _metadata_json(metadata):
    if not metadata:
        return None
    try:
        encoded = json.dumps(_redact(metadata), separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        return None
    return encoded[:_MAX_METADATA]


def _last_hash():
    row = (
        db.session.query(TrustAuditEvent.EventHash)
        .order_by(TrustAuditEvent.EventID.desc())
        .first()
    )
    return row[0] if row and row[0] else ""


def _event_hash(prev_hash, event_uuid, event_type, outcome, event_time,
                organisation_id, project_id, actor_user_id, metadata):
    payload = "|".join([
        prev_hash or "",
        event_uuid,
        event_type,
        outcome,
        event_time.isoformat(),
        str(organisation_id or ""),
        str(project_id or ""),
        str(actor_user_id or ""),
        metadata or "",
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record(
    event_type,
    *,
    outcome=OUTCOME_SUCCESS,
    organisation_id=None,
    project_id=None,
    actor=None,
    actor_user_id=None,
    reason_code=None,
    entity_type=None,
    entity_id=None,
    metadata=None,
    ip_address=None,
    correlation_id=None,
    commit=True,
):
    """Insert one immutable audit event and return it."""
    resolved_actor = actor_user_id
    if resolved_actor is None and actor is not None:
        resolved_actor = getattr(actor, "UserID", None)

    event_time = datetime.utcnow()
    event_uuid = str(uuid.uuid4())
    metadata_json = _metadata_json(metadata)
    prev_hash = _last_hash()
    event = TrustAuditEvent(
        EventUUID=event_uuid,
        EventTime=event_time,
        OrganisationID=organisation_id,
        ProjectID=project_id,
        ActorUserID=resolved_actor,
        EventType=event_type,
        Outcome=outcome,
        ReasonCode=reason_code,
        EntityType=entity_type,
        EntityID=entity_id,
        IPAddress=ip_address,
        CorrelationID=correlation_id,
        MetadataJson=metadata_json,
        PrevEventHash=prev_hash or None,
        EventHash=_event_hash(
            prev_hash, event_uuid, event_type, outcome, event_time,
            organisation_id, project_id, resolved_actor, metadata_json,
        ),
    )
    db.session.add(event)
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    return event


def query_events(project_id=None, organisation_id=None):
    query = TrustAuditEvent.query
    if project_id is not None:
        query = query.filter_by(ProjectID=project_id)
    elif organisation_id is not None:
        query = query.filter_by(OrganisationID=organisation_id)
    return query.order_by(TrustAuditEvent.EventID.desc())
