"""
Security audit logging service.

The Business Logic Layer records significant events (authentication, scans,
administrative operations, report generation) into SecurityAuditLog with the
event context: user, category, action, entity, IP address, timestamp.
"""
import logging
from datetime import datetime

from flask import current_app, request

from app.extensions import db
from app.models import SecurityAuditLog
from app.utils.constants import (
    AUDIT_CATEGORY_AUTHENTICATION,
    AUDIT_STATUS_SUCCESS,
)

logger = logging.getLogger("vulnscan.audit")


def _client_ip():
    try:
        return request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
    except Exception:
        return None


def write_audit(
    category=AUDIT_CATEGORY_AUTHENTICATION,
    action="",
    description="",
    user=None,
    user_id=None,
    entity_type=None,
    entity_id=None,
    status=AUDIT_STATUS_SUCCESS,
    ip_address=None,
    commit=True,
):
    """Create a SecurityAuditLog record."""
    if not current_app.config.get("AUDIT_LOG_ENABLED", True):
        return None

    resolved_user_id = user_id
    if resolved_user_id is None and user is not None:
        resolved_user_id = getattr(user, "UserID", None)

    entry = SecurityAuditLog(
        EventTime=datetime.utcnow(),
        Category=category,
        Action=action,
        EntityType=entity_type,
        EntityID=entity_id,
        Description=description,
        IPAddress=ip_address or _client_ip(),
        Status=status,
        UserID=resolved_user_id,
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    return entry
