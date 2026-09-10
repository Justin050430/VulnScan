"""Vulnerability knowledge-base endpoints."""
from flask import Blueprint, jsonify, request

from app.services import vulnerability_service
from app.services.audit_service import write_audit
from app.utils.constants import AUDIT_CATEGORY_VULNERABILITY_MANAGEMENT
from app.utils.security import admin_required, any_authenticated, get_current_user

vulnerabilities_bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")


@vulnerabilities_bp.get("")
@any_authenticated
def list_vulnerabilities():
    user = get_current_user()
    include_disabled = request.args.get("include_disabled", "").lower() == "true"
    if not user.is_administrator:
        include_disabled = False  # developers only see enabled definitions
    category = request.args.get("category")
    items = vulnerability_service.list_vulnerabilities(
        include_disabled=include_disabled, category=category
    )
    return jsonify({
        "Vulnerabilities": [v.to_dict() for v in items],
        "Total": len(items),
    }), 200


@vulnerabilities_bp.post("")
@admin_required
def create_vulnerability():
    data = request.get_json(silent=True) or {}
    actor = get_current_user()
    ip = request.remote_addr
    try:
        vuln = vulnerability_service.create_vulnerability(data)
    except vulnerability_service.VulnerabilityServiceError as exc:
        return jsonify({"message": str(exc)}), 400

    write_audit(
        category=AUDIT_CATEGORY_VULNERABILITY_MANAGEMENT,
        action="VULNERABILITY_CREATED",
        description=f"Vulnerability definition '{vuln.Name}' created.",
        user=actor,
        entity_type="Vulnerability",
        entity_id=vuln.VulnerabilityID,
        ip_address=ip,
    )
    return jsonify({"message": "Vulnerability created.", "Vulnerability": vuln.to_dict()}), 201


@vulnerabilities_bp.put("/<int:vulnerability_id>")
@admin_required
def update_vulnerability(vulnerability_id):
    data = request.get_json(silent=True) or {}
    actor = get_current_user()
    ip = request.remote_addr
    try:
        vuln = vulnerability_service.update_vulnerability(vulnerability_id, data)
    except vulnerability_service.VulnerabilityServiceError as exc:
        return jsonify({"message": str(exc)}), 400

    write_audit(
        category=AUDIT_CATEGORY_VULNERABILITY_MANAGEMENT,
        action="VULNERABILITY_UPDATED",
        description=f"Vulnerability definition '{vuln.Name}' updated.",
        user=actor,
        entity_type="Vulnerability",
        entity_id=vuln.VulnerabilityID,
        ip_address=ip,
    )
    return jsonify({"message": "Vulnerability updated.", "Vulnerability": vuln.to_dict()}), 200
