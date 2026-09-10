"""Security audit log endpoints (Administrator)."""
from datetime import datetime

from flask import Blueprint, jsonify, request

from app.extensions import db
from app.models import SecurityAuditLog
from app.utils.security import admin_required

audit_logs_bp = Blueprint("audit_logs", __name__, url_prefix="/audit-logs")


def _parse_date(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@audit_logs_bp.get("")
@admin_required
def list_audit_logs():
    query = SecurityAuditLog.query
    category = request.args.get("category")
    search = request.args.get("search")
    status = request.args.get("status")
    date_from = _parse_date(request.args.get("date_from"))
    date_to = _parse_date(request.args.get("date_to"))

    if category:
        query = query.filter_by(Category=category)
    if status:
        query = query.filter_by(Status=status)
    if date_from:
        query = query.filter(SecurityAuditLog.EventTime >= date_from)
    if date_to:
        query = query.filter(SecurityAuditLog.EventTime <= date_to)
    if search:
        like = f"%{search.strip()}%"
        query = query.filter(
            db.or_(
                SecurityAuditLog.Description.ilike(like),
                SecurityAuditLog.Action.ilike(like),
            )
        )

    try:
        per_page = max(1, min(int(request.args.get("per_page", 25)), 200))
        page = max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        per_page, page = 25, 1

    total = query.count()
    items = (
        query.order_by(SecurityAuditLog.EventTime.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    categories = [
        r[0]
        for r in db.session.query(SecurityAuditLog.Category)
        .distinct().order_by(SecurityAuditLog.Category).all()
    ]
    return jsonify({
        "AuditLogs": [a.to_dict() for a in items],
        "Total": total,
        "Page": page,
        "PerPage": per_page,
        "Categories": categories,
    }), 200
