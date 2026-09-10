"""User management endpoints (Administrator)."""
from flask import Blueprint, jsonify, request

from app.models import User
from app.services import user_service
from app.services.audit_service import write_audit
from app.utils.constants import AUDIT_CATEGORY_USER_MANAGEMENT
from app.utils.security import admin_required, get_current_user
from app.utils.validators import ValidationError

users_bp = Blueprint("users", __name__, url_prefix="/users")


@users_bp.get("")
@admin_required
def list_users():
    search = request.args.get("search")
    users = user_service.list_users(search=search)
    return jsonify({
        "Users": [u.to_dict() for u in users],
        "Total": len(users),
    }), 200


@users_bp.post("")
@admin_required
def create_user():
    data = request.get_json(silent=True) or {}
    actor = get_current_user()
    ip = request.remote_addr
    try:
        user = user_service.create_user(
            username=data.get("username"),
            email=data.get("email"),
            password=data.get("password"),
            role=data.get("role", "Developer"),
        )
    except (ValidationError, user_service.UserServiceError) as exc:
        return jsonify({"message": str(exc)}), 400

    write_audit(
        category=AUDIT_CATEGORY_USER_MANAGEMENT,
        action="USER_CREATED",
        description=f"User account created for {user.Email} with role {user.Role}.",
        user=actor,
        entity_type="User",
        entity_id=user.UserID,
        ip_address=ip,
    )
    return jsonify({"message": "User created.", "User": user.to_dict()}), 201


@users_bp.put("/<int:user_id>")
@admin_required
def update_user(user_id):
    data = request.get_json(silent=True) or {}
    actor = get_current_user()
    ip = request.remote_addr
    try:
        user = user_service.update_user(
            user_id,
            username=data.get("username"),
            email=data.get("email"),
            role=data.get("role"),
            password=data.get("password"),
            is_active=data.get("is_active"),
        )
    except user_service.UserServiceError as exc:
        return jsonify({"message": str(exc)}), 400
    except ValidationError as exc:
        return jsonify({"message": str(exc)}), 400

    write_audit(
        category=AUDIT_CATEGORY_USER_MANAGEMENT,
        action="USER_UPDATED",
        description=f"User account updated for {user.Email}.",
        user=actor,
        entity_type="User",
        entity_id=user.UserID,
        ip_address=ip,
    )
    return jsonify({"message": "User updated.", "User": user.to_dict()}), 200


@users_bp.delete("/<int:user_id>")
@admin_required
def disable_user(user_id):
    actor = get_current_user()
    ip = request.remote_addr
    target = User.query.get(user_id)
    try:
        user = user_service.disable_user(user_id)
    except user_service.UserServiceError as exc:
        return jsonify({"message": str(exc)}), 400

    write_audit(
        category=AUDIT_CATEGORY_USER_MANAGEMENT,
        action="USER_DISABLED",
        description=(
            f"User account disabled for {target.Email}."
            if target else f"User {user_id} disabled."
        ),
        user=actor,
        entity_type="User",
        entity_id=user_id,
        ip_address=ip,
    )
    return jsonify({"message": "User disabled.", "User": user.to_dict()}), 200
