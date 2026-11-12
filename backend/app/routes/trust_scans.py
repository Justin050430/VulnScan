"""Gated, project-scoped scan creation, readiness and cancellation."""
from flask import Blueprint, current_app, jsonify, request

from app.extensions import db
from app.models import Scan, TrustAsset, TrustScanContext
from app.services import scan_gate_service, scan_service
from app.trust.constants import (
    PERM_SCAN_CANCEL,
    PERM_SCAN_READ,
    PERM_SCAN_START,
    PERM_TRUST_AUDIT_VIEW,
)
from app.trust.permissions import (
    client_ip,
    is_enforced,
    not_found,
    require_permission,
)
from app.utils.security import get_current_user

trust_scans_bp = Blueprint("trust_scans", __name__, url_prefix="/projects")


def _asset_in_project(project_id, asset_id):
    asset = db.session.get(TrustAsset, int(asset_id))
    if asset is None or asset.ProjectID != int(project_id):
        raise not_found("Asset")
    return asset


@trust_scans_bp.get("/<int:project_id>/scan-readiness")
@require_permission(PERM_SCAN_READ)
def scan_readiness(project_id, _access=None):
    asset_id = request.args.get("asset_id")
    if not asset_id:
        from app.trust.constants import ERR_VALIDATION
        from app.trust.permissions import TrustError

        raise TrustError("asset_id is required.", ERR_VALIDATION, 400)
    asset = _asset_in_project(project_id, asset_id)
    credential_id = request.args.get("credential_id")
    return jsonify({
        "Readiness": scan_gate_service.evaluate(
            _access, asset, credential_id=credential_id
        )
    }), 200


@trust_scans_bp.post("/<int:project_id>/scans")
@require_permission(PERM_SCAN_START)
def create_scan(project_id, _access=None):
    data = request.get_json(silent=True) or {}
    asset = _asset_in_project(project_id, data.get("asset_id"))
    result = scan_gate_service.start_gated_scan(
        _access,
        get_current_user(),
        asset=asset,
        scan_profile_id=data.get("scan_profile_id"),
        scan_name=data.get("scan_name"),
        attestation_id=data.get("attestation_id"),
        credit_ref=data.get("credit_id"),
        idempotency_key=data.get("idempotency_key"),
        target_url=data.get("target_url"),
        credential_id=data.get("credential_id"),
        ip_address=client_ip(),
        run_async=bool(current_app.config.get("SCAN_ASYNC", True)),
    )
    scan = result["Scan"]
    return jsonify({
        "Scan": scan.to_dict(include_relations=False) if scan else None,
        "Credit": result["Credit"].to_dict() if result["Credit"] else None,
        "Redemption": (
            result["Redemption"].to_dict() if result["Redemption"] else None
        ),
        "IdempotentReplay": result["IdempotentReplay"],
    }), 202


@trust_scans_bp.post("/<int:project_id>/scans/<int:scan_id>/cancel")
@require_permission(PERM_SCAN_CANCEL)
def cancel_scan(project_id, scan_id, _access=None):
    context = db.session.get(TrustScanContext, int(scan_id))
    scan = db.session.get(Scan, int(scan_id))
    if scan is None or context is None or context.ProjectID != int(project_id):
        raise not_found("Scan")
    scan_service.ensure_scan_accessible(get_current_user(), scan)
    scan_gate_service.cancel_scan(
        _access, get_current_user(), scan, ip_address=client_ip()
    )
    return jsonify({"Scan": scan.to_dict(include_relations=False)}), 200


@trust_scans_bp.get("/<int:project_id>/audit-events")
@require_permission(PERM_TRUST_AUDIT_VIEW)
def list_audit_events(project_id, _access=None):
    from app.services import trust_audit_service

    outcome = request.args.get("outcome")
    event_type = request.args.get("event_type")
    query = trust_audit_service.query_events(project_id=int(project_id))
    if outcome:
        query = query.filter_by(Outcome=outcome)
    if event_type:
        query = query.filter_by(EventType=event_type)
    try:
        limit = max(1, min(int(request.args.get("per_page", 50)), 200))
    except (TypeError, ValueError):
        limit = 50
    rows = query.limit(limit).all()
    return jsonify({
        "Events": [e.to_dict() for e in rows],
        "Total": len(rows),
    }), 200


@trust_scans_bp.get("/<int:project_id>/scans")
@require_permission(PERM_SCAN_READ)
def list_project_scans(project_id, _access=None):
    rows = (
        db.session.query(Scan)
        .join(TrustScanContext, TrustScanContext.ScanID == Scan.ScanID)
        .filter(TrustScanContext.ProjectID == int(project_id))
        .order_by(Scan.StartedAt.desc())
        .limit(200)
        .all()
    )
    return jsonify({
        "Scans": [s.to_dict(include_relations=False) for s in rows],
        "Total": len(rows),
        "Mode": "enforce" if is_enforced() else "legacy",
    }), 200
