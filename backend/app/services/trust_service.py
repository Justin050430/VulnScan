"""Organisation, project and membership services (Trust Boundary Extension)."""
import hashlib
import re
import secrets
from datetime import datetime, timedelta

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
    ERR_INVITATION_EXPIRED,
    ERR_NOT_FOUND,
    ERR_SLUG_CONFLICT,
    ERR_VALIDATION,
    EVENT_ORG_CREATED,
    EVENT_ORG_MEMBER_ACCEPTED,
    EVENT_ORG_MEMBER_INVITED,
    EVENT_ORG_MEMBER_REVOKED,
    EVENT_PROJECT_CREATED,
    EVENT_PROJECT_MEMBER_ACCEPTED,
    EVENT_PROJECT_MEMBER_INVITED,
    EVENT_PROJECT_MEMBER_REVOKED,
    MEMBERSHIP_ACTIVE,
    MEMBERSHIP_INVITED,
    MEMBERSHIP_REVOKED,
    ORG_ROLE_OWNER,
    PROJECT_ROLE_VIEWER,
    PROJECT_ROLES,
)
from app.trust.permissions import TrustError, resolve_project

INVITE_TTL_HOURS = 72


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(hours=INVITE_TTL_HOURS)
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
    existing.InviteExpiresAt = expires
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
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(hours=INVITE_TTL_HOURS)
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
    existing.InviteExpiresAt = expires
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


def accept_invitation(user, token, ip_address=None):
    if not token:
        raise TrustError("An invitation token is required.", ERR_VALIDATION, 400)
    token_hash = _hash_token(token)
    membership = TrustOrganisationMembership.query.filter_by(
        InviteTokenHash=token_hash
    ).first()
    if membership is not None:
        _validate_invite(membership, user)
        membership.Status = MEMBERSHIP_ACTIVE
        membership.AcceptedAt = datetime.utcnow()
        membership.InviteTokenHash = None
        membership.InviteExpiresAt = None
        membership.Version += 1
        audit.record(
            EVENT_ORG_MEMBER_ACCEPTED,
            organisation_id=membership.OrganisationID,
            actor=user,
            entity_type="TrustOrganisationMembership",
            entity_id=membership.OrganisationMembershipID,
            metadata={"role": membership.Role},
            ip_address=ip_address,
            commit=False,
        )
        db.session.commit()
        return membership

    project_membership = TrustProjectMembership.query.filter_by(
        InviteTokenHash=token_hash
    ).first()
    if project_membership is None:
        raise TrustError("Invitation not found or already used.", ERR_NOT_FOUND, 404)
    _validate_invite(project_membership, user)
    project_membership.Status = MEMBERSHIP_ACTIVE
    project_membership.AcceptedAt = datetime.utcnow()
    project_membership.InviteTokenHash = None
    project_membership.InviteExpiresAt = None
    project_membership.Version += 1
    audit.record(
        EVENT_PROJECT_MEMBER_ACCEPTED,
        organisation_id=project_membership.OrganisationID,
        project_id=project_membership.ProjectID,
        actor=user,
        entity_type="TrustProjectMembership",
        entity_id=project_membership.ProjectMembershipID,
        metadata={"role": project_membership.Role},
        ip_address=ip_address,
        commit=False,
    )
    db.session.commit()
    return project_membership


def _validate_invite(membership, user):
    if membership.UserID != user.UserID:
        raise TrustError("Invitation not found.", ERR_NOT_FOUND, 404)
    if membership.Status != MEMBERSHIP_INVITED:
        raise TrustError(
            "This invitation is no longer valid.", ERR_INVITATION_EXPIRED, 409
        )
    if (
        membership.InviteExpiresAt is not None
        and membership.InviteExpiresAt <= datetime.utcnow()
    ):
        raise TrustError("This invitation has expired.", ERR_INVITATION_EXPIRED, 409)


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
