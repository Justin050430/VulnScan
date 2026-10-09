"""Scan profile endpoints."""
from flask import Blueprint, jsonify, request

from app.services import scan_profile_service
from app.services.audit_service import write_audit
from app.utils.constants import AUDIT_CATEGORY_PROFILE_MANAGEMENT
from app.utils.security import admin_required, any_authenticated, get_current_user

scan_profiles_bp = Blueprint("scan_profiles", __name__, url_prefix="/scan-profiles")


@scan_profiles_bp.get("")
@any_authenticated
def list_scan_profiles():
    items = scan_profile_service.list_profiles()
    return jsonify({
        "ScanProfiles": [p.to_dict() for p in items],
        "Total": len(items),
    }), 200


@scan_profiles_bp.get("/<int:profile_id>/preview")
@any_authenticated
def scan_profile_preview(profile_id):
    """Pre-scan summary: what the profile will and will not test (C3)."""
    try:
        preview = scan_profile_service.build_scan_preview(profile_id)
    except scan_profile_service.ScanProfileServiceError as exc:
        return jsonify({"message": str(exc)}), 404
    return jsonify({"Preview": preview}), 200


def _payload(request):
    data = request.get_json(silent=True) or {}
    return {
        "name": data.get("name"),
        "max_depth": data.get("max_depth"),
        "follow_external": data.get("follow_external"),
        "request_delay_ms": data.get("request_delay_ms"),
        "max_pages": data.get("max_pages"),
        "module_vuln_ids": data.get("module_vuln_ids"),
    }


@scan_profiles_bp.post("")
@admin_required
def create_scan_profile():
    actor = get_current_user()
    ip = request.remote_addr
    p = _payload(request)
    try:
        profile = scan_profile_service.create_profile(
            name=p["name"],
            max_depth=p["max_depth"] if p["max_depth"] is not None else 2,
            follow_external=bool(p["follow_external"]),
            request_delay_ms=p["request_delay_ms"] if p["request_delay_ms"] is not None else 200,
            max_pages=p["max_pages"] if p["max_pages"] is not None else 30,
            module_vuln_ids=p["module_vuln_ids"],
        )
    except scan_profile_service.ScanProfileServiceError as exc:
        return jsonify({"message": str(exc)}), 400

    write_audit(
        category=AUDIT_CATEGORY_PROFILE_MANAGEMENT,
        action="PROFILE_CREATED",
        description=f"Scan profile '{profile.Name}' created.",
        user=actor,
        entity_type="ScanProfile",
        entity_id=profile.ScanProfileID,
        ip_address=ip,
    )
    return jsonify({"message": "Scan profile created.", "ScanProfile": profile.to_dict()}), 201


@scan_profiles_bp.put("/<int:profile_id>")
@admin_required
def update_scan_profile(profile_id):
    actor = get_current_user()
    ip = request.remote_addr
    p = _payload(request)
    try:
        profile = scan_profile_service.update_profile(
            profile_id,
            name=p["name"],
            max_depth=p["max_depth"],
            follow_external=p["follow_external"],
            request_delay_ms=p["request_delay_ms"],
            max_pages=p["max_pages"],
            module_vuln_ids=p["module_vuln_ids"],
        )
    except scan_profile_service.ScanProfileServiceError as exc:
        return jsonify({"message": str(exc)}), 400

    write_audit(
        category=AUDIT_CATEGORY_PROFILE_MANAGEMENT,
        action="PROFILE_UPDATED",
        description=f"Scan profile '{profile.Name}' updated.",
        user=actor,
        entity_type="ScanProfile",
        entity_id=profile.ScanProfileID,
        ip_address=ip,
    )
    return jsonify({"message": "Scan profile updated.", "ScanProfile": profile.to_dict()}), 200


@scan_profiles_bp.delete("/<int:profile_id>")
@admin_required
def delete_scan_profile(profile_id):
    actor = get_current_user()
    ip = request.remote_addr
    try:
        scan_profile_service.delete_profile(profile_id)
    except scan_profile_service.ScanProfileServiceError as exc:
        return jsonify({"message": str(exc)}), 400

    write_audit(
        category=AUDIT_CATEGORY_PROFILE_MANAGEMENT,
        action="PROFILE_DELETED",
        description=f"Scan profile (id {profile_id}) deleted.",
        user=actor,
        entity_type="ScanProfile",
        entity_id=profile_id,
        ip_address=ip,
    )
    return jsonify({"message": "Scan profile deleted."}), 200
