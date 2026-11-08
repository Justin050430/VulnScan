"""Asset registration, verification and attestation endpoints."""
import hashlib

from flask import Blueprint, jsonify, request

from app.extensions import db
from app.models import TrustAsset, TrustAuthorizationAttestation
from app.services import asset_verification_service, attestation_service
from app.trust.constants import (
    PERM_ASSET_READ,
    PERM_ASSET_REGISTER,
    PERM_ASSET_REVOKE,
    PERM_ASSET_VERIFY,
    PERM_ATTESTATION_CREATE,
    PERM_ATTESTATION_READ,
    PERM_ATTESTATION_REVOKE,
)
from app.trust.permissions import client_ip, not_found, require_permission
from app.utils.security import get_current_user

assets_bp = Blueprint("trust_assets", __name__, url_prefix="/projects")


def _asset_or_404(project_id, asset_id):
    asset = db.session.get(TrustAsset, int(asset_id))
    if asset is None or asset.ProjectID != int(project_id):
        raise not_found("Asset")
    return asset


@assets_bp.get("/<int:project_id>/assets")
@require_permission(PERM_ASSET_READ)
def list_assets(project_id, _access=None):
    assets = asset_verification_service.list_assets(project_id)
    for asset in assets:
        asset_verification_service.refresh_status(asset)
    return jsonify({
        "Assets": [a.to_dict() for a in assets],
        "Total": len(assets),
    }), 200


@assets_bp.post("/<int:project_id>/assets")
@require_permission(PERM_ASSET_REGISTER)
def register_asset(project_id, _access=None):
    data = request.get_json(silent=True) or {}
    asset = asset_verification_service.register_asset(
        get_current_user(),
        _access,
        data.get("hostname"),
        scheme=data.get("scheme", "https"),
        ip_address=client_ip(),
    )
    return jsonify({"Asset": asset.to_dict()}), 201


@assets_bp.get("/<int:project_id>/assets/<int:asset_id>")
@require_permission(PERM_ASSET_READ)
def get_asset(project_id, asset_id, _access=None):
    asset = _asset_or_404(project_id, asset_id)
    asset_verification_service.refresh_status(asset)
    return jsonify({"Asset": asset.to_dict()}), 200


@assets_bp.post("/<int:project_id>/assets/<int:asset_id>/verification")
@require_permission(PERM_ASSET_VERIFY)
def start_verification(project_id, asset_id, _access=None):
    asset = _asset_or_404(project_id, asset_id)
    data = request.get_json(silent=True) or {}
    asset, challenge = asset_verification_service.start_verification(
        get_current_user(),
        _access,
        asset,
        data.get("method"),
        ip_address=client_ip(),
    )
    return jsonify({
        "Asset": asset.to_dict(),
        "Challenge": challenge,
    }), 200


@assets_bp.post("/<int:project_id>/assets/<int:asset_id>/verification/check")
@require_permission(PERM_ASSET_VERIFY)
def check_verification(project_id, asset_id, _access=None):
    asset = _asset_or_404(project_id, asset_id)
    asset, result = asset_verification_service.check_verification(
        get_current_user(), _access, asset, ip_address=client_ip()
    )
    return jsonify({"Asset": asset.to_dict(), "Verification": result}), 200


@assets_bp.post("/<int:project_id>/assets/<int:asset_id>/revoke")
@require_permission(PERM_ASSET_REVOKE)
def revoke_asset(project_id, asset_id, _access=None):
    asset = _asset_or_404(project_id, asset_id)
    data = request.get_json(silent=True) or {}
    asset_verification_service.revoke_asset(
        get_current_user(), _access, asset,
        reason=data.get("reason"), ip_address=client_ip(),
    )
    return jsonify({"Asset": asset.to_dict()}), 200


# ------------------------------------------------------------------ attestations
@assets_bp.get("/<int:project_id>/assets/<int:asset_id>/attestations")
@require_permission(PERM_ATTESTATION_READ)
def list_attestations(project_id, asset_id, _access=None):
    _asset_or_404(project_id, asset_id)
    rows = attestation_service.list_attestations(asset_id)
    return jsonify({
        "Attestations": [a.to_dict() for a in rows],
        "Total": len(rows),
    }), 200


@assets_bp.post("/<int:project_id>/assets/<int:asset_id>/attestations")
@require_permission(PERM_ATTESTATION_CREATE)
def create_attestation(project_id, asset_id, _access=None):
    from app.services.asset_verification_service import ensure_verified

    asset = _asset_or_404(project_id, asset_id)
    ensure_verified(asset)
    data = request.get_json(silent=True) or {}
    ua = hashlib.sha256(
        (request.headers.get("User-Agent") or "").encode("utf-8")
    ).hexdigest()
    attestation = attestation_service.create_attestation(
        get_current_user(),
        _access,
        asset,
        days=data.get("expires_in_days"),
        reference=data.get("reference"),
        scope=data.get("scope"),
        statement_version=data.get("statement_version"),
        ip_address=client_ip(),
        user_agent_hash=ua,
    )
    return jsonify({"Attestation": attestation.to_dict()}), 201


@assets_bp.post(
    "/<int:project_id>/assets/<int:asset_id>/attestations/<int:attestation_id>/revoke"
)
@require_permission(PERM_ATTESTATION_REVOKE)
def revoke_attestation(project_id, asset_id, attestation_id, _access=None):
    _asset_or_404(project_id, asset_id)
    attestation = db.session.get(TrustAuthorizationAttestation, attestation_id)
    if attestation is None or attestation.AssetID != int(asset_id):
        raise not_found("Attestation")
    data = request.get_json(silent=True) or {}
    attestation_service.revoke_attestation(
        get_current_user(), _access, attestation,
        reason=data.get("reason"), ip_address=client_ip(),
    )
    return jsonify({"Attestation": attestation.to_dict()}), 200
