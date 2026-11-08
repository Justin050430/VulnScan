"""Trust Boundary permission resolution and endpoint guards.

Server-side only: the UI hides actions, but every endpoint calls these
helpers.  Cross-tenant resources are reported as 404 so their existence is not
disclosed.
"""
import functools
from dataclasses import dataclass
from datetime import datetime

from flask import jsonify, request
from flask_jwt_extended import current_user, jwt_required

from app.extensions import db
from app.models import (
    TrustOrganisation,
    TrustOrganisationMembership,
    TrustProject,
    TrustProjectMembership,
)
from app.trust.constants import (
    ERR_NOT_FOUND,
    ERR_PERMISSION_DENIED,
    MEMBERSHIP_ACTIVE,
    PERM_SCAN_START,
    PROJECT_ROLE_OWNER,
    PROVIDER_MOCK,
    effective_permissions,
)


class TrustError(Exception):
    """An expected Trust Boundary failure with an HTTP status and code."""

    def __init__(self, message, code, status=400, details=None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.details = details or {}

    def to_response(self):
        payload = {"message": self.message, "code": self.code}
        if self.details:
            payload["details"] = self.details
        return jsonify(payload), self.status


def not_found(what="Resource"):
    return TrustError(f"{what} not found.", ERR_NOT_FOUND, 404)


@dataclass
class ProjectAccess:
    """Resolved membership and effective permissions for one project."""

    organisation: TrustOrganisation
    project: TrustProject
    org_membership: object
    project_membership: object
    org_role: str
    project_role: str
    permissions: frozenset

    @property
    def organisation_id(self):
        return self.organisation.OrganisationID

    @property
    def project_id(self):
        return self.project.ProjectID

    def has(self, permission):
        return permission in self.permissions

    def require(self, permission):
        if not self.has(permission):
            raise TrustError(
                "You do not have permission to perform this action.",
                ERR_PERMISSION_DENIED,
                403,
                {"required_permission": permission},
            )
        return permission

    @property
    def can_start_scan(self):
        return self.has(PERM_SCAN_START)


def active_org_membership(user, organisation_id):
    return (
        TrustOrganisationMembership.query.filter_by(
            OrganisationID=organisation_id,
            UserID=user.UserID,
            Status=MEMBERSHIP_ACTIVE,
        )
        .first()
    )


def active_project_membership(user, project_id):
    return (
        TrustProjectMembership.query.filter_by(
            ProjectID=project_id,
            UserID=user.UserID,
            Status=MEMBERSHIP_ACTIVE,
        )
        .first()
    )


def resolve_project(user, project_id, require_scan_permission=False):
    """Resolve a project the user may access, or raise TrustError."""
    project = db.session.get(TrustProject, int(project_id))
    if project is None:
        raise not_found("Project")

    project_membership = active_project_membership(user, project.ProjectID)
    org_membership = active_org_membership(user, project.OrganisationID)
    if project_membership is None and org_membership is None:
        # Cross-tenant: do not confirm that the project exists.
        raise not_found("Project")

    organisation = db.session.get(TrustOrganisation, project.OrganisationID)
    if organisation is None:
        raise not_found("Project")

    org_role = org_membership.Role if org_membership else None
    project_role = project_membership.Role if project_membership else None
    access = ProjectAccess(
        organisation=organisation,
        project=project,
        org_membership=org_membership,
        project_membership=project_membership,
        org_role=org_role,
        project_role=project_role,
        permissions=effective_permissions(org_role, project_role),
    )
    if require_scan_permission and not access.can_start_scan:
        raise TrustError(
            "Scanning requires an active PROJECT_OWNER or SCAN_OPERATOR "
            "project role.",
            ERR_PERMISSION_DENIED,
            403,
            {"required_permission": PERM_SCAN_START},
        )
    return access


def resolve_project_for_org(user, organisation_id):
    """Access to an organisation (org owner only in this slice)."""
    organisation = db.session.get(TrustOrganisation, int(organisation_id))
    if organisation is None:
        raise not_found("Organisation")
    membership = active_org_membership(user, organisation.OrganisationID)
    if membership is None:
        raise not_found("Organisation")
    return organisation, membership


def resolve_organisation(user, organisation_id):
    """Alias used by route modules: (organisation, membership)."""
    return resolve_project_for_org(user, organisation_id)


def project_of(obj):
    """Return the project id owning a trust resource."""
    return getattr(obj, "ProjectID", None)


def require_permission(permission):
    """Decorator for routes with a ``project_id`` URL argument."""

    def decorator(fn):
        @functools.wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            if current_user is None:
                return (
                    jsonify({"message": "Authentication required.",
                             "code": "token_invalid"}),
                    401,
                )
            try:
                access = resolve_project(
                    current_user,
                    kwargs.get("project_id"),
                    require_scan_permission=(permission == PERM_SCAN_START),
                )
                access.require(permission)
            except TrustError as exc:
                return exc.to_response()
            return fn(*args, _access=access, **kwargs)

        return wrapper

    return decorator


def trust_mode():
    from flask import current_app

    return (current_app.config.get("TRUST_BOUNDARY_MODE") or "enforce").lower()


def is_enforced():
    return trust_mode() != "legacy"


def mock_provider_enabled():
    from flask import current_app

    return (
        current_app.config.get("TRUST_PAYMENT_PROVIDER", PROVIDER_MOCK).upper()
        == PROVIDER_MOCK
    )


def client_ip():
    forwarded = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if request
        else ""
    )
    return forwarded or (request.remote_addr if request else None)


def now():
    return datetime.utcnow()


def is_org_owner(access):
    return access.org_role is not None


def is_project_owner(access):
    return access.project_role == PROJECT_ROLE_OWNER
