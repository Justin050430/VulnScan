"""Organisation, project and membership endpoints (Trust Boundary)."""
from urllib.parse import quote

from flask import Blueprint, current_app, jsonify, request

from app.services import trust_service
from app.trust.constants import PERM_PROJECT_READ
from app.trust.permissions import (
    client_ip,
    require_permission,
    resolve_organisation,
    resolve_project,
    resolve_project_for_org,
)
from app.utils.security import any_authenticated, get_current_user

organisations_bp = Blueprint(
    "trust_organisations", __name__, url_prefix="/organisations"
)
projects_bp = Blueprint("trust_projects", __name__, url_prefix="/projects")
invitations_bp = Blueprint("trust_invitations", __name__, url_prefix="/invitations")


def _invite_payload(membership, token):
    """
    Invitation response shared by the organisation and project endpoints.

    `InviteURL` is the absolute, directly clickable link an inviter can share.
    The token lives in the URL fragment, so it is never sent to the server in a
    request line, never written to access logs and never leaked as a Referer.
    """
    base = (current_app.config.get("TRUST_INVITE_BASE_URL") or "").strip()
    base = base or request.url_root
    return {
        "Membership": membership.to_dict(),
        "InviteToken": token,
        "InviteURL": (
            f"{base.rstrip('/')}/#/invitations/accept?token={quote(token, safe='')}"
        ),
        "InviteEmail": membership.InviteEmail,
        "InviteExpiresAt": (
            membership.InviteExpiresAt.isoformat()
            if membership.InviteExpiresAt else None
        ),
    }


@organisations_bp.get("")
@any_authenticated
def list_organisations():
    user = get_current_user()
    organisations = trust_service.list_organisations(user)
    return jsonify({
        "Organisations": [o.to_dict() for o in organisations],
        "Total": len(organisations),
    }), 200


@organisations_bp.post("")
@any_authenticated
def create_organisation():
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    organisation, membership = trust_service.create_organisation(
        user,
        data.get("name"),
        slug=data.get("slug"),
        ip_address=client_ip(),
    )
    return jsonify({
        "Organisation": organisation.to_dict(),
        "Membership": membership.to_dict(),
    }), 201


@organisations_bp.get("/<int:organisation_id>")
@any_authenticated
def get_organisation(organisation_id):
    user = get_current_user()
    organisation, membership = resolve_organisation(user, organisation_id)
    return jsonify({
        "Organisation": organisation.to_dict(),
        "Membership": membership.to_dict(),
    }), 200


@organisations_bp.get("/<int:organisation_id>/members")
@any_authenticated
def list_organisation_members(organisation_id):
    user = get_current_user()
    resolve_project_for_org(user, organisation_id)
    members = trust_service.list_organisation_members(organisation_id)
    rows = trust_service.member_dicts(members)
    return jsonify({"Members": rows, "Total": len(rows)}), 200


@organisations_bp.post("/<int:organisation_id>/members")
@any_authenticated
def invite_organisation_member(organisation_id):
    user = get_current_user()
    resolve_project_for_org(user, organisation_id)
    data = request.get_json(silent=True) or {}
    membership, token = trust_service.invite_organisation_member(
        organisation_id,
        data.get("email"),
        data.get("role", "ORG_OWNER"),
        user,
        ip_address=client_ip(),
    )
    return jsonify(_invite_payload(membership, token)), 201


@organisations_bp.delete("/<int:organisation_id>/members/<int:membership_id>")
@any_authenticated
def revoke_organisation_member(organisation_id, membership_id):
    from app.extensions import db
    from app.models import TrustOrganisationMembership
    from app.trust.permissions import TrustError, not_found

    user = get_current_user()
    resolve_project_for_org(user, organisation_id)
    membership = db.session.get(TrustOrganisationMembership, membership_id)
    if membership is None or membership.OrganisationID != int(organisation_id):
        raise not_found("Membership")
    trust_service.revoke_organisation_member(
        organisation_id, membership, user, ip_address=client_ip()
    )
    return jsonify({"Membership": membership.to_dict()}), 200


# --------------------------------------------------------------------- projects
@projects_bp.get("")
@any_authenticated
def list_projects():
    user = get_current_user()
    organisation_id = request.args.get("organisation_id")
    rows = trust_service.my_projects(user)
    if organisation_id:
        rows = [
            row for row in rows
            if row["Project"]["OrganisationID"] == int(organisation_id)
        ]
    return jsonify({"Projects": rows, "Total": len(rows)}), 200


@projects_bp.post("")
@any_authenticated
def create_project():
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    organisation_id = data.get("organisation_id")
    project = trust_service.create_project(
        user,
        organisation_id,
        data.get("name"),
        slug=data.get("slug"),
        ip_address=client_ip(),
    )
    access = resolve_project(user, project.ProjectID)
    return jsonify({
        "Project": project.to_dict(),
        "Permissions": sorted(access.permissions),
    }), 201


@projects_bp.get("/<int:project_id>")
@require_permission(PERM_PROJECT_READ)
def get_project(project_id, _access=None):
    return jsonify({
        "Project": _access.project.to_dict(),
        "Organisation": _access.organisation.to_dict(),
        "OrgRole": _access.org_role,
        "ProjectRole": _access.project_role,
        "Permissions": sorted(_access.permissions),
    }), 200


@projects_bp.get("/<int:project_id>/members")
@require_permission(PERM_PROJECT_READ)
def list_project_members(project_id, _access=None):
    members = trust_service.list_project_members(project_id)
    rows = trust_service.member_dicts(members)
    return jsonify({"Members": rows, "Total": len(rows)}), 200


@projects_bp.post("/<int:project_id>/members")
@require_permission("project.members.manage")
def invite_project_member(project_id, _access=None):
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    membership, token = trust_service.invite_project_member(
        project_id,
        data.get("email"),
        data.get("role", "VIEWER"),
        user,
        ip_address=client_ip(),
    )
    return jsonify(_invite_payload(membership, token)), 201


@projects_bp.patch("/<int:project_id>/members/<int:membership_id>")
@require_permission("project.members.manage")
def change_project_member(project_id, membership_id, _access=None):
    from app.extensions import db
    from app.models import TrustProjectMembership
    from app.trust.permissions import not_found

    membership = db.session.get(TrustProjectMembership, membership_id)
    if membership is None or membership.ProjectID != int(project_id):
        raise not_found("Membership")
    data = request.get_json(silent=True) or {}
    trust_service.change_project_member_role(
        membership, data.get("role"), get_current_user(), ip_address=client_ip()
    )
    return jsonify({"Membership": membership.to_dict()}), 200


@projects_bp.delete("/<int:project_id>/members/<int:membership_id>")
@require_permission("project.members.manage")
def revoke_project_member(project_id, membership_id, _access=None):
    from app.extensions import db
    from app.models import TrustProjectMembership
    from app.trust.permissions import not_found

    membership = db.session.get(TrustProjectMembership, membership_id)
    if membership is None or membership.ProjectID != int(project_id):
        raise not_found("Membership")
    trust_service.revoke_project_member(
        membership, get_current_user(), ip_address=client_ip()
    )
    return jsonify({"Membership": membership.to_dict()}), 200


@projects_bp.get("/<int:project_id>/permissions")
@require_permission(PERM_PROJECT_READ)
def project_permissions(project_id, _access=None):
    return jsonify({
        "ProjectID": int(project_id),
        "OrgRole": _access.org_role,
        "ProjectRole": _access.project_role,
        "Permissions": sorted(_access.permissions),
        "CanStartScan": _access.can_start_scan,
    }), 200


@invitations_bp.post("/preview")
@any_authenticated
def preview_invitation():
    """
    Details of a pending invitation for the signed-in account.

    Authentication comes first: the endpoint proves that the caller owns the
    invited email address before disclosing what the invitation grants.
    """
    data = request.get_json(silent=True) or {}
    context = trust_service.preview_invitation(
        get_current_user(), data.get("token"), ip_address=client_ip()
    )
    return jsonify({"Invitation": context.to_dict()}), 200


@invitations_bp.post("/accept")
@any_authenticated
def accept_invitation():
    data = request.get_json(silent=True) or {}
    context = trust_service.accept_invitation(
        get_current_user(), data.get("token"), ip_address=client_ip()
    )
    payload = context.to_dict()
    return jsonify({
        "Membership": payload["Membership"],
        "Invitation": payload,
    }), 200
