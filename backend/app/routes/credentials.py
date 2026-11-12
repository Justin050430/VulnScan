"""Temporary authenticated-scan credential endpoints (project-scoped)."""
from flask import Blueprint, jsonify, request

from app.extensions import db
from app.models import TrustAsset
from app.services import credential_service
from app.trust.constants import (
    PERM_CREDENTIAL_APPROVE,
    PERM_CREDENTIAL_CREATE,
    PERM_CREDENTIAL_READ,
    PERM_CREDENTIAL_REVOKE,
)
from app.trust.permissions import client_ip, not_found, require_permission
from app.utils.security import get_current_user

credentials_bp = Blueprint("trust_credentials", __name__, url_prefix="/projects")


def _asset_or_404(project_id, asset_id):
    asset = db.session.get(TrustAsset, int(asset_id))
    if asset is None or asset.ProjectID != int(project_id):
        raise not_found("Asset")
    return asset


@credentials_bp.get("/<int:project_id>/credentials")
@require_permission(PERM_CREDENTIAL_READ)
def list_project_credentials(project_id, _access=None):
    asset_id = request.args.get("asset_id")
    rows = credential_service.list_credentials(_access, asset_id=asset_id)
    return jsonify({
        "Credentials": [c.to_dict() for c in rows],
        "Total": len(rows),
    }), 200


@credentials_bp.get("/<int:project_id>/assets/<int:asset_id>/credentials")
@require_permission(PERM_CREDENTIAL_READ)
def list_asset_credentials(project_id, asset_id, _access=None):
    _asset_or_404(project_id, asset_id)
    rows = credential_service.list_credentials(_access, asset_id=asset_id)
    return jsonify({
        "Credentials": [c.to_dict() for c in rows],
        "Total": len(rows),
    }), 200


@credentials_bp.post("/<int:project_id>/assets/<int:asset_id>/credentials")
@require_permission(PERM_CREDENTIAL_CREATE)
def create_credential(project_id, asset_id, _access=None):
    asset = _asset_or_404(project_id, asset_id)
    data = request.get_json(silent=True) or {}
    credential = credential_service.create_credential(
        get_current_user(), _access, asset, data, ip_address=client_ip()
    )
    return jsonify({"Credential": credential.to_dict()}), 201


@credentials_bp.get("/<int:project_id>/credentials/<int:credential_id>")
@require_permission(PERM_CREDENTIAL_READ)
def get_credential(project_id, credential_id, _access=None):
    credential = credential_service.get_project_credential(project_id, credential_id)
    if credential.OrganisationID != _access.organisation_id:
        raise not_found("Credential")
    return jsonify({"Credential": credential.to_dict()}), 200


@credentials_bp.post(
    "/<int:project_id>/credentials/<int:credential_id>/approve"
)
@require_permission(PERM_CREDENTIAL_APPROVE)
def approve_credential(project_id, credential_id, _access=None):
    credential = credential_service.get_project_credential(project_id, credential_id)
    data = request.get_json(silent=True) or {}
    credential = credential_service.approve_credential(
        get_current_user(), _access, credential,
        acknowledge=data.get("acknowledge") is True,
        ip_address=client_ip(),
    )
    return jsonify({"Credential": credential.to_dict()}), 200


@credentials_bp.post(
    "/<int:project_id>/credentials/<int:credential_id>/reject"
)
@require_permission(PERM_CREDENTIAL_APPROVE)
def reject_credential(project_id, credential_id, _access=None):
    credential = credential_service.get_project_credential(project_id, credential_id)
    data = request.get_json(silent=True) or {}
    credential = credential_service.reject_credential(
        get_current_user(), _access, credential,
        reason=data.get("reason"), ip_address=client_ip(),
    )
    return jsonify({"Credential": credential.to_dict()}), 200


@credentials_bp.post(
    "/<int:project_id>/credentials/<int:credential_id>/revoke"
)
@require_permission(PERM_CREDENTIAL_REVOKE)
def revoke_credential(project_id, credential_id, _access=None):
    credential = credential_service.get_project_credential(project_id, credential_id)
    data = request.get_json(silent=True) or {}
    credential = credential_service.revoke_credential(
        get_current_user(), _access, credential,
        reason=data.get("reason"), ip_address=client_ip(),
    )
    return jsonify({"Credential": credential.to_dict()}), 200


@credentials_bp.post(
    "/<int:project_id>/credentials/<int:credential_id>/test-login"
)
@require_permission(PERM_CREDENTIAL_CREATE)
def test_login(project_id, credential_id, _access=None):
    credential = credential_service.get_project_credential(project_id, credential_id)
    result = credential_service.test_login(
        get_current_user(), _access, credential, ip_address=client_ip()
    )
    return jsonify({
        "message": "Login succeeded.",
        "Login": result,
        "Credential": credential.to_dict(),
    }), 200
