"""Organisation, project and membership services (Trust Boundary Extension)."""
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import (
    TrustOrganisation,
    TrustOrganisationMembership,
    TrustProject,
    TrustProjectMembership,
    User,
)
from app.services import trust_audit_service as audit
from app.trust.constants import (
    ERR_ALREADY_MEMBER,
    ERR_INVITATION_ALREADY_USED,
    ERR_INVITATION_EMAIL_MISMATCH,
    ERR_INVITATION_EXPIRED,
    ERR_NOT_FOUND,
    ERR_SLUG_CONFLICT,
    ERR_VALIDATION,
    EVENT_ORG_CREATED,
    EVENT_ORG_MEMBER_ACCEPTED,
    EVENT_ORG_MEMBER_INVITED,
    EVENT_ORG_MEMBER_INVITE_DENIED,
    EVENT_ORG_MEMBER_REVOKED,
    EVENT_PROJECT_CREATED,
    EVENT_PROJECT_MEMBER_ACCEPTED,
    EVENT_PROJECT_MEMBER_INVITED,
    EVENT_PROJECT_MEMBER_INVITE_DENIED,
    EVENT_PROJECT_MEMBER_REVOKED,
    MEMBERSHIP_ACTIVE,
    MEMBERSHIP_INVITED,
    MEMBERSHIP_REVOKED,
    ORG_ROLE_OWNER,
    OUTCOME_DENIED,
    PROJECT_ROLE_VIEWER,
    PROJECT_ROLES,
)
from app.trust.permissions import TrustError, resolve_project

INVITE_TTL_HOURS = 72

INVITATION_KIND_ORGANISATION = "Organisation"
INVITATION_KIND_PROJECT = "Project"


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _invite_ttl_hours():
    try:
        configured = int(current_app.config.get("TRUST_INVITATION_TTL_HOURS",
                                                INVITE_TTL_HOURS))
    except (TypeError, ValueError):
        configured = INVITE_TTL_HOURS
    return max(1, configured)


@dataclass
class InvitationContext:
    """A resolved, validated invitation (organisation or project membership)."""

    membership: object
    kind: str
    organisation: TrustOrganisation
    project: object
    email: str

    @property
    def role(self):
        return self.membership.Role

    @property
    def expires_at(self):
        return self.membership.InviteExpiresAt

    def to_dict(self):
        return {
            "Kind": self.kind,
            "Role": self.role,
            "Email": self.email,
            "ExpiresAt": (
                self.expires_at.isoformat() if self.expires_at else None
            ),
            "Organisation": self.organisation.to_dict(),
            "Project": self.project.to_dict() if self.project is not None else None,
            "Membership": self.membership.to_dict(),
        }


def slugify(value, max_length=60):
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    if not slug:
        raise TrustError("A name is required.", ERR_VALIDATION, 400)
    return slug[:max_length].strip("-")


def _unique_slug(model, base, scope_filter, max_length=60):
    slug = base
    suffix = 2
    while model.query.filter(scope_filter(slug)).first() is not None:
        tail = f"-{suffix}"
        slug = base[: max_length - len(tail)] + tail
        suffix += 1
    return slug


def create_organisation(user, name, slug=None, ip_address=None):
    if not name or not str(name).strip():
        raise TrustError("An organisation name is required.", ERR_VALIDATION, 400)
    base = slugify(slug or name)
    base = _unique_slug(
        TrustOrganisation, base, lambda s: TrustOrganisation.Slug == s
    )
    organisation = TrustOrganisation(
        Name=str(name).strip()[:120],
        Slug=base,
        CreatedByUserID=user.UserID,
    )
    db.session.add(organisation)
    db.session.flush()
    membership = TrustOrganisationMembership(
        OrganisationID=organisation.OrganisationID,
        UserID=user.UserID,
        Role=ORG_ROLE_OWNER,
        Status=MEMBERSHIP_ACTIVE,
        AcceptedAt=datetime.utcnow(),
        InvitedByUserID=user.UserID,
    )
    db.session.add(membership)
    audit.record(
        EVENT_ORG_CREATED,
        organisation_id=organisation.OrganisationID,
        actor=user,
        entity_type="TrustOrganisation",
        entity_id=organisation.OrganisationID,
        metadata={"name": organisation.Name, "slug": organisation.Slug},
        ip_address=ip_address,
        commit=False,
    )
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise TrustError(
            "An organisation with this slug already exists.", ERR_SLUG_CONFLICT, 409
        )
    return organisation, membership


def list_organisations(user):
    rows = (
        db.session.query(TrustOrganisation)
        .join(
            TrustOrganisationMembership,
            TrustOrganisationMembership.OrganisationID
            == TrustOrganisation.OrganisationID,
        )
        .filter(
            TrustOrganisationMembership.UserID == user.UserID,
            TrustOrganisationMembership.Status == MEMBERSHIP_ACTIVE,
        )
        .order_by(TrustOrganisation.Name.asc())
        .all()
    )
    return rows


def create_project(user, organisation_id, name, slug=None, ip_address=None):
    from app.trust.permissions import resolve_project_for_org

    organisation, _membership = resolve_project_for_org(user, organisation_id)
    if not name or not str(name).strip():
        raise TrustError("A project name is required.", ERR_VALIDATION, 400)
    base = slugify(slug or name)
    base = _unique_slug(
        TrustProject,
        base,
        lambda s: db.and_(
            TrustProject.OrganisationID == organisation.OrganisationID,
            TrustProject.Slug == s,
        ),
    )
    project = TrustProject(
        OrganisationID=organisation.OrganisationID,
        Name=str(name).strip()[:120],
        Slug=base,
        CreatedByUserID=user.UserID,
    )
    db.session.add(project)
    db.session.flush()
    db.session.add(
        TrustProjectMembership(
            OrganisationID=organisation.OrganisationID,
            ProjectID=project.ProjectID,
            UserID=user.UserID,
            Role="PROJECT_OWNER",
            Status=MEMBERSHIP_ACTIVE,
            AcceptedAt=datetime.utcnow(),
            InvitedByUserID=user.UserID,
        )
    )
    audit.record(
        EVENT_PROJECT_CREATED,
        organisation_id=organisation.OrganisationID,
        project_id=project.ProjectID,
        actor=user,
        entity_type="TrustProject",
        entity_id=project.ProjectID,
        metadata={"name": project.Name, "slug": project.Slug},
        ip_address=ip_address,
        commit=False,
    )
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise TrustError(
            "A project with this slug already exists.", ERR_SLUG_CONFLICT, 409
        )
    return project


def list_projects(user, organisation_id=None):
    project_ids = {
        row.ProjectID
        for row in TrustProjectMembership.query.filter_by(
            UserID=user.UserID, Status=MEMBERSHIP_ACTIVE
        ).all()
    }
    org_ids = {
        row.OrganisationID
        for row in TrustOrganisationMembership.query.filter_by(
            UserID=user.UserID, Status=MEMBERSHIP_ACTIVE
        ).all()
    }
    query = TrustProject.query
    if organisation_id is not None:
        query = query.filter_by(OrganisationID=int(organisation_id))
    projects = query.order_by(TrustProject.Name.asc()).all()
    return [
        project
        for project in projects
        if project.ProjectID in project_ids or project.OrganisationID in org_ids
    ]


def _find_user_by_email(email):
    return User.query.filter_by(Email=(email or "").strip().lower()).first()


def invite_organisation_member(access_or_org_id, email, role, inviter,
                               organisation_id=None, ip_address=None):
    organisation_id = organisation_id or access_or_org_id
    if role not in (ORG_ROLE_OWNER,):
        raise TrustError("Invalid organisation role.", ERR_VALIDATION, 400)
    invitee = _find_user_by_email(email)
    if invitee is None:
        raise TrustError(
            "The invitee must already have a VulnScan account.",
            "USER_NOT_FOUND",
            400,
        )
    existing = TrustOrganisationMembership.query.filter_by(
        OrganisationID=int(organisation_id), UserID=invitee.UserID
    ).first()
    if existing is not None and existing.Status == MEMBERSHIP_ACTIVE:
        raise TrustError(
            f"{invitee.Email} is already a member of this organisation.",
            ERR_ALREADY_MEMBER,
            409,
        )
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(hours=_invite_ttl_hours())
    if existing is None:
        existing = TrustOrganisationMembership(
            OrganisationID=int(organisation_id),
            UserID=invitee.UserID,
            Role=role,
            Status=MEMBERSHIP_INVITED,
            InvitedByUserID=inviter.UserID,
        )
        db.session.add(existing)
    else:
        existing.Role = role
        existing.Status = MEMBERSHIP_INVITED
        existing.AcceptedAt = None
        existing.InvitedByUserID = inviter.UserID
    existing.InviteTokenHash = _hash_token(token)
    existing.InviteEmail = invitee.Email
    existing.InviteExpiresAt = expires
    db.session.flush()
    audit.record(
        EVENT_ORG_MEMBER_INVITED,
        organisation_id=int(organisation_id),
        actor=inviter,
        entity_type="TrustOrganisationMembership",
        entity_id=existing.OrganisationMembershipID or 0,
        metadata={"invitee_user_id": invitee.UserID, "role": role},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return existing, token


def invite_project_member(project_id, email, role, inviter, ip_address=None):
    if role not in PROJECT_ROLES:
        raise TrustError("Invalid project role.", ERR_VALIDATION, 400)
    project = db.session.get(TrustProject, int(project_id))
    if project is None:
        raise TrustError("Project not found.", ERR_NOT_FOUND, 404)
    invitee = _find_user_by_email(email)
    if invitee is None:
        raise TrustError(
            "The invitee must already have a VulnScan account.",
            "USER_NOT_FOUND",
            400,
        )
    existing = TrustProjectMembership.query.filter_by(
        ProjectID=project.ProjectID, UserID=invitee.UserID
    ).first()
    if existing is not None and existing.Status == MEMBERSHIP_ACTIVE:
        raise TrustError(
            f"{invitee.Email} is already a member of this project.",
            ERR_ALREADY_MEMBER,
            409,
        )
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(hours=_invite_ttl_hours())
    if existing is None:
        existing = TrustProjectMembership(
            OrganisationID=project.OrganisationID,
            ProjectID=project.ProjectID,
            UserID=invitee.UserID,
            Role=role,
            Status=MEMBERSHIP_INVITED,
            InvitedByUserID=inviter.UserID,
        )
        db.session.add(existing)
    else:
        existing.Role = role
        existing.Status = MEMBERSHIP_INVITED
        existing.AcceptedAt = None
        existing.InvitedByUserID = inviter.UserID
    existing.InviteTokenHash = _hash_token(token)
    existing.InviteEmail = invitee.Email
    existing.InviteExpiresAt = expires
    db.session.flush()
    audit.record(
        EVENT_PROJECT_MEMBER_INVITED,
        organisation_id=project.OrganisationID,
        project_id=project.ProjectID,
        actor=inviter,
        entity_type="TrustProjectMembership",
        entity_id=existing.ProjectMembershipID or 0,
        metadata={"invitee_user_id": invitee.UserID, "role": role},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return existing, token


def _find_invitation(token):
    """Return the pending/used membership row addressed by a raw token."""
    token_hash = _hash_token(token)
    membership = TrustOrganisationMembership.query.filter_by(
        InviteTokenHash=token_hash
    ).first()
    if membership is not None:
        return membership, INVITATION_KIND_ORGANISATION
    membership = TrustProjectMembership.query.filter_by(
        InviteTokenHash=token_hash
    ).first()
    if membership is not None:
        return membership, INVITATION_KIND_PROJECT
    return None, None


def _invited_email(membership):
    """Email the invitation is bound to (falls back for pre-migration rows)."""
    if membership.InviteEmail:
        return membership.InviteEmail
    user = db.session.get(User, membership.UserID)
    return user.Email if user else None


def _deny_event(kind):
    return (
        EVENT_PROJECT_MEMBER_INVITE_DENIED
        if kind == INVITATION_KIND_PROJECT
        else EVENT_ORG_MEMBER_INVITE_DENIED
    )


def _record_denial(membership, kind, actor, reason_code, ip_address, message):
    audit.record(
        _deny_event(kind),
        outcome=OUTCOME_DENIED,
        organisation_id=membership.OrganisationID,
        project_id=getattr(membership, "ProjectID", None),
        actor=actor,
        reason_code=reason_code,
        entity_type=type(membership).__name__,
        entity_id=(
            membership.ProjectMembershipID
            if kind == INVITATION_KIND_PROJECT
            else membership.OrganisationMembershipID
        ),
        metadata={"reason": message},
        ip_address=ip_address,
        commit=True,
    )


def validate_invitation(token, user, ip_address=None):
    """
    Resolve and authorise an invitation for the authenticated `user`.

    Raises TrustError for an unknown, expired, revoked, already-accepted or
    email-mismatched invitation.  The email check is the authoritative control:
    holding the link is not enough, the signed-in account must own the address
    the invitation was issued to.
    """
    if not token or not str(token).strip():
        raise TrustError(
            "An invitation token is required.", ERR_VALIDATION, 400
        )
    membership, kind = _find_invitation(str(token).strip())
    if membership is None:
        raise TrustError(
            "This invitation link is not valid. Ask the inviter for a new one.",
            ERR_NOT_FOUND,
            404,
        )

    if membership.Status == MEMBERSHIP_ACTIVE:
        raise TrustError(
            "This invitation has already been used.",
            ERR_INVITATION_ALREADY_USED,
            409,
        )
    if membership.Status != MEMBERSHIP_INVITED:
        raise TrustError(
            "This invitation is no longer valid.",
            ERR_INVITATION_EXPIRED,
            409,
        )
    if (
        membership.InviteExpiresAt is not None
        and membership.InviteExpiresAt <= datetime.utcnow()
    ):
        raise TrustError(
            "This invitation has expired. Ask the inviter to send a new one.",
            ERR_INVITATION_EXPIRED,
            409,
        )

    invited_email = _invited_email(membership)
    account_email = (user.Email or "").strip().lower()
    if (
        membership.UserID != user.UserID
        or (invited_email or "").strip().lower() != account_email
    ):
        message = (
            "This invitation was issued to a different email address. "
            "Sign in with the invited account to accept it."
        )
        _record_denial(
            membership, kind, user, ERR_INVITATION_EMAIL_MISMATCH,
            ip_address, message,
        )
        raise TrustError(message, ERR_INVITATION_EMAIL_MISMATCH, 403)

    organisation = db.session.get(
        TrustOrganisation, membership.OrganisationID
    )
    project = (
        db.session.get(TrustProject, membership.ProjectID)
        if kind == INVITATION_KIND_PROJECT
        else None
    )
    return InvitationContext(
        membership=membership,
        kind=kind,
        organisation=organisation,
        project=project,
        email=invited_email,
    )


def preview_invitation(user, token, ip_address=None):
    """Return invitation details without accepting (read-only)."""
    return validate_invitation(token, user, ip_address=ip_address)


def accept_invitation(user, token, ip_address=None):
    """Accept a validated invitation and activate the membership."""
    context = validate_invitation(token, user, ip_address=ip_address)
    pending = context.membership
    if context.kind == INVITATION_KIND_PROJECT:
        model, pk_attr = TrustProjectMembership, "ProjectMembershipID"
    else:
        model, pk_attr = TrustOrganisationMembership, "OrganisationMembershipID"
    membership_id = getattr(pending, pk_attr)

    # Conditional UPDATE: two concurrent accepts of the same link cannot both
    # succeed, so the invitation is genuinely single-use.
    accepted = (
        db.session.query(model)
        .filter(
            getattr(model, pk_attr) == membership_id,
            model.Status == MEMBERSHIP_INVITED,
            model.InviteTokenHash == pending.InviteTokenHash,
        )
        .update(
            {
                model.Status: MEMBERSHIP_ACTIVE,
                model.AcceptedAt: datetime.utcnow(),
                model.Version: model.Version + 1,
            },
            synchronize_session=False,
        )
    )
    if not accepted:
        db.session.rollback()
        raise TrustError(
            "This invitation has already been used.",
            ERR_INVITATION_ALREADY_USED,
            409,
        )
    db.session.expire_all()
    membership = db.session.get(model, membership_id)

    audit.record(
        (
            EVENT_PROJECT_MEMBER_ACCEPTED
            if context.kind == INVITATION_KIND_PROJECT
            else EVENT_ORG_MEMBER_ACCEPTED
        ),
        organisation_id=membership.OrganisationID,
        project_id=getattr(membership, "ProjectID", None),
        actor=user,
        entity_type=type(membership).__name__,
        entity_id=membership_id,
        metadata={"role": membership.Role},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return InvitationContext(
        membership=membership,
        kind=context.kind,
        organisation=context.organisation,
        project=context.project,
        email=context.email,
    )


def list_project_members(project_id):
    return (
        TrustProjectMembership.query.filter_by(ProjectID=int(project_id))
        .order_by(TrustProjectMembership.ProjectMembershipID.asc())
        .all()
    )


def list_organisation_members(organisation_id):
    return (
        TrustOrganisationMembership.query.filter_by(
            OrganisationID=int(organisation_id)
        )
        .order_by(TrustOrganisationMembership.OrganisationMembershipID.asc())
        .all()
    )


def member_dicts(memberships):
    """Serialise memberships with the account email/username (one query)."""
    rows = list(memberships)
    if not rows:
        return []
    users = {
        user.UserID: user
        for user in User.query.filter(
            User.UserID.in_({row.UserID for row in rows})
        ).all()
    }
    output = []
    for row in rows:
        data = row.to_dict()
        user = users.get(row.UserID)
        data["Email"] = user.Email if user else None
        data["Username"] = user.Username if user else None
        data["InvitePending"] = row.Status == MEMBERSHIP_INVITED
        output.append(data)
    return output


def change_project_member_role(membership, role, actor, ip_address=None):
    if role not in PROJECT_ROLES:
        raise TrustError("Invalid project role.", ERR_VALIDATION, 400)
    previous = membership.Role
    membership.Role = role
    membership.Version += 1
    audit.record(
        EVENT_PROJECT_MEMBER_ROLE_CHANGED,
        organisation_id=membership.OrganisationID,
        project_id=membership.ProjectID,
        actor=actor,
        entity_type="TrustProjectMembership",
        entity_id=membership.ProjectMembershipID,
        metadata={"from": previous, "to": role},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return membership


def revoke_project_member(membership, actor, ip_address=None):
    if membership.Status == MEMBERSHIP_REVOKED:
        return membership
    membership.Status = MEMBERSHIP_REVOKED
    membership.InviteTokenHash = None
    membership.Version += 1
    audit.record(
        EVENT_PROJECT_MEMBER_REVOKED,
        organisation_id=membership.OrganisationID,
        project_id=membership.ProjectID,
        actor=actor,
        entity_type="TrustProjectMembership",
        entity_id=membership.ProjectMembershipID,
        metadata={"role": membership.Role},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return membership


def revoke_organisation_member(organisation_id, membership, actor, ip_address=None):
    if membership.Status == MEMBERSHIP_REVOKED:
        return membership
    if membership.Role == ORG_ROLE_OWNER:
        remaining = TrustOrganisationMembership.query.filter(
            TrustOrganisationMembership.OrganisationID == int(organisation_id),
            TrustOrganisationMembership.Role == ORG_ROLE_OWNER,
            TrustOrganisationMembership.Status == MEMBERSHIP_ACTIVE,
            TrustOrganisationMembership.OrganisationMembershipID
            != membership.OrganisationMembershipID,
        ).count()
        if remaining == 0:
            raise TrustError(
                "The last active organisation owner cannot be removed.",
                "LAST_ORG_OWNER",
                400,
            )
    membership.Status = MEMBERSHIP_REVOKED
    membership.InviteTokenHash = None
    membership.Version += 1
    audit.record(
        EVENT_ORG_MEMBER_REVOKED,
        organisation_id=int(organisation_id),
        actor=actor,
        entity_type="TrustOrganisationMembership",
        entity_id=membership.OrganisationMembershipID,
        metadata={"role": membership.Role},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return membership


def my_projects(user):
    """Projects visible to a user, with their effective project role."""
    rows = []
    for project in list_projects(user):
        access = None
        try:
            access = resolve_project(user, project.ProjectID)
        except TrustError:
            continue
        rows.append({
            "Project": project.to_dict(),
            "OrganisationSlug": access.organisation.Slug,
            "OrganisationName": access.organisation.Name,
            "OrgRole": access.org_role,
            "ProjectRole": access.project_role,
            "Permissions": sorted(access.permissions),
        })
    return rows
