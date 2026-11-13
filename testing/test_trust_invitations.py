"""
Invitation link flow tests.

The invitation is a direct, shareable URL bound to the invitee's email address.
Acceptance requires (1) authentication, (2) the signed-in account owning that
address, and (3) an unexpired, unused token.  Every rule is enforced server-side.
"""
from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import TrustAuditEvent, TrustOrganisationMembership
from app.models import TrustProjectMembership
from testing.trust_helpers import (
    bearer,
    create_org,
    create_project,
    create_user,
    invite_and_accept,
)


@pytest.fixture()
def trust_app(app):
    app.config["TRUST_BOUNDARY_MODE"] = "enforce"
    return app


def _org_invite(client, token, organisation_id, email, role="ORG_OWNER"):
    return client.post(
        f"/api/v1/organisations/{organisation_id}/members",
        json={"email": email, "role": role},
        headers=bearer(token),
    )


def _project_invite(client, token, project_id, email, role="VIEWER"):
    return client.post(
        f"/api/v1/projects/{project_id}/members",
        json={"email": email, "role": role},
        headers=bearer(token),
    )


def _preview(client, token, invite_token):
    return client.post(
        "/api/v1/invitations/preview",
        json={"token": invite_token},
        headers=bearer(token),
    )


def _accept(client, token, invite_token):
    return client.post(
        "/api/v1/invitations/accept",
        json={"token": invite_token},
        headers=bearer(token),
    )


def _token_from_url(invite_url):
    assert "#/invitations/accept?token=" in invite_url, invite_url
    return invite_url.split("token=", 1)[1]


# --------------------------------------------------------------------------
# Invitation link generation
# --------------------------------------------------------------------------
def test_invitation_returns_clickable_url_bound_to_email(
        trust_app, client, admin_token, dev_token):
    email, _invitee_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)

    response = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    )
    assert response.status_code == 201, response.get_json()
    body = response.get_json()

    invite_url = body["InviteURL"]
    assert invite_url.startswith("http"), invite_url
    token = _token_from_url(invite_url)
    assert token == body["InviteToken"]
    assert len(token) >= 32
    assert body["InviteEmail"] == email
    assert body["InviteExpiresAt"]
    assert body["Membership"]["Status"] == "Invited"


def test_invitation_token_is_rotated_on_reinvite(
        trust_app, client, admin_token, dev_token):
    email, _ = create_user(client, admin_token)
    organisation = create_org(client, dev_token)

    first = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()
    second = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()

    assert first["InviteToken"] != second["InviteToken"]
    assert len(first["InviteToken"]) >= 32


def test_inviting_an_active_member_is_rejected_without_demotion(
        trust_app, client, admin_token, dev_token):
    email, invitee_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    invite = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()
    assert _accept(client, invitee_token, invite["InviteToken"]).status_code == 200

    response = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    )
    assert response.status_code == 409
    assert response.get_json()["code"] == "ALREADY_MEMBER"

    with trust_app.app_context():
        still_active = TrustOrganisationMembership.query.filter_by(
            OrganisationID=organisation["OrganisationID"], Status="Active"
        ).count()
    assert still_active == 2  # inviter + accepted invitee, nobody demoted


# --------------------------------------------------------------------------
# Authentication and email ownership
# --------------------------------------------------------------------------
def test_preview_and_accept_require_authentication(
        trust_app, client, admin_token, dev_token):
    email, _ = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    token = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()["InviteToken"]

    assert client.post(
        "/api/v1/invitations/preview", json={"token": token}
    ).status_code == 401
    assert client.post(
        "/api/v1/invitations/accept", json={"token": token}
    ).status_code == 401


def test_preview_shows_the_invitation_to_the_invited_account(
        trust_app, client, admin_token, dev_token):
    email, invitee_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    invite = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()

    response = _preview(client, invitee_token, invite["InviteToken"])
    assert response.status_code == 200
    invitation = response.get_json()["Invitation"]
    assert invitation["Kind"] == "Organisation"
    assert invitation["Role"] == "ORG_OWNER"
    assert invitation["Email"] == email
    assert invitation["Organisation"]["OrganisationID"] == organisation["OrganisationID"]
    assert invitation["Project"] is None
    # The raw token is never echoed back by the API.
    assert invite["InviteToken"] not in response.get_data(as_text=True)


def test_wrong_account_cannot_accept_and_membership_stays_invited(
        trust_app, client, admin_token, dev_token):
    email, _ = create_user(client, admin_token)
    _other_email, other_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    token = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()["InviteToken"]

    for response in (
        _preview(client, other_token, token),
        _accept(client, other_token, token),
    ):
        assert response.status_code == 403
        body = response.get_json()
        assert body["code"] == "INVITATION_EMAIL_MISMATCH"
        assert "different email address" in body["message"]
        # The invited address is not disclosed to the wrong account.
        assert email not in response.get_data(as_text=True)

    with trust_app.app_context():
        pending = TrustOrganisationMembership.query.filter_by(
            OrganisationID=organisation["OrganisationID"], Status="Invited"
        ).all()
    assert len(pending) == 1


def test_email_mismatch_is_recorded_as_a_denied_audit_event(
        trust_app, client, admin_token, dev_token):
    email, _ = create_user(client, admin_token)
    _other_email, other_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    token = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()["InviteToken"]

    assert _accept(client, other_token, token).status_code == 403

    with trust_app.app_context():
        denied = TrustAuditEvent.query.filter_by(
            EventType="ORG_MEMBER_INVITE_DENIED"
        ).all()
        assert denied
        assert denied[-1].Outcome == "Denied"
        assert denied[-1].ReasonCode == "INVITATION_EMAIL_MISMATCH"
        # The token never reaches the audit trail.
        assert token not in (denied[-1].MetadataJson or "")


# --------------------------------------------------------------------------
# Single use and expiry
# --------------------------------------------------------------------------
def test_invitation_is_single_use(trust_app, client, admin_token, dev_token):
    email, invitee_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    invite = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()

    first = _accept(client, invitee_token, invite["InviteToken"])
    assert first.status_code == 200
    assert first.get_json()["Membership"]["Status"] == "Active"

    second = _accept(client, invitee_token, invite["InviteToken"])
    assert second.status_code == 409
    assert second.get_json()["code"] == "INVITATION_ALREADY_USED"
    assert "already been used" in second.get_json()["message"]


def test_expired_invitation_is_rejected(trust_app, client, admin_token, dev_token):
    email, invitee_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    token = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()["InviteToken"]

    with trust_app.app_context():
        membership = TrustOrganisationMembership.query.filter_by(
            OrganisationID=organisation["OrganisationID"], Status="Invited"
        ).first()
        membership.InviteExpiresAt = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()

    for response in (
        _preview(client, invitee_token, token),
        _accept(client, invitee_token, token),
    ):
        assert response.status_code == 409
        assert response.get_json()["code"] == "INVITATION_EXPIRED"
        assert "expired" in response.get_json()["message"]


def test_unknown_token_is_rejected(trust_app, client, dev_token):
    assert _accept(client, dev_token, "not-a-real-token").status_code == 404
    assert _preview(client, dev_token, "not-a-real-token").status_code == 404


def test_concurrent_accept_cannot_activate_twice(
        trust_app, client, admin_token, dev_token, monkeypatch):
    """
    A second accept that slipped past validation (concurrent request) must be
    refused by the conditional UPDATE rather than activating the row twice.
    """
    from app.services import trust_service as service

    email, invitee_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    token = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()["InviteToken"]

    original = service.validate_invitation

    def validate_then_lose_the_race(*args, **kwargs):
        context = original(*args, **kwargs)
        # Simulate the competing request winning between validation and update.
        with trust_app.app_context():
            row = TrustOrganisationMembership.query.filter_by(
                OrganisationID=organisation["OrganisationID"], Status="Invited"
            ).first()
            row.Status = "Active"
            db.session.commit()
        return context

    monkeypatch.setattr(service, "validate_invitation", validate_then_lose_the_race)

    response = _accept(client, invitee_token, token)
    assert response.status_code == 409
    assert response.get_json()["code"] == "INVITATION_ALREADY_USED"


def test_missing_token_is_a_validation_error(trust_app, client, dev_token):
    response = client.post(
        "/api/v1/invitations/accept", json={}, headers=bearer(dev_token)
    )
    assert response.status_code == 400
    assert response.get_json()["code"] == "VALIDATION_ERROR"


# --------------------------------------------------------------------------
# Project invitations share the same flow
# --------------------------------------------------------------------------
def test_project_invitation_link_flow(trust_app, client, admin_token, dev_token):
    email, invitee_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    invite = _project_invite(
        client, dev_token, project["ProjectID"], email, role="ANALYST"
    ).get_json()

    preview = _preview(client, invitee_token, invite["InviteToken"])
    assert preview.status_code == 200
    invitation = preview.get_json()["Invitation"]
    assert invitation["Kind"] == "Project"
    assert invitation["Role"] == "ANALYST"
    assert invitation["Project"]["ProjectID"] == project["ProjectID"]

    accepted = _accept(client, invitee_token, invite["InviteToken"])
    assert accepted.status_code == 200
    assert (
        accepted.get_json()["Invitation"]["Project"]["ProjectID"]
        == project["ProjectID"]
    )

    with trust_app.app_context():
        active = TrustProjectMembership.query.filter_by(
            ProjectID=project["ProjectID"], Status="Active"
        ).all()
    assert len(active) == 2


def test_reinvite_after_revocation_issues_a_new_working_link(
        trust_app, client, admin_token, dev_token):
    email, invitee_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    invite = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()
    assert _accept(client, invitee_token, invite["InviteToken"]).status_code == 200

    members = client.get(
        f"/api/v1/organisations/{organisation['OrganisationID']}/members",
        headers=bearer(dev_token),
    ).get_json()["Members"]
    membership_id = next(
        m["OrganisationMembershipID"] for m in members if m["Email"] == email
    )
    revoked = client.delete(
        f"/api/v1/organisations/{organisation['OrganisationID']}"
        f"/members/{membership_id}",
        headers=bearer(dev_token),
    )
    assert revoked.status_code == 200

    # The used link stops working as soon as the membership is revoked.
    assert _accept(client, invitee_token, invite["InviteToken"]).status_code == 404

    new_invite = _org_invite(
        client, dev_token, organisation["OrganisationID"], email
    ).get_json()
    assert new_invite["InviteToken"] != invite["InviteToken"]
    assert _accept(client, invitee_token, new_invite["InviteToken"]).status_code == 200


# --------------------------------------------------------------------------
# Supporting behaviour
# --------------------------------------------------------------------------
def test_member_list_exposes_email_and_pending_state(
        trust_app, client, admin_token, dev_token):
    email, _ = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    _org_invite(client, dev_token, organisation["OrganisationID"], email)

    members = client.get(
        f"/api/v1/organisations/{organisation['OrganisationID']}/members",
        headers=bearer(dev_token),
    ).get_json()["Members"]

    invited = next(m for m in members if m["Email"] == email)
    assert invited["InvitePending"] is True
    assert invited["InviteEmail"] == email
    assert invited["InviteExpiresAt"]


def test_invitation_ttl_is_configurable(trust_app, client, admin_token, dev_token):
    email, _ = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    trust_app.config["TRUST_INVITATION_TTL_HOURS"] = 5
    try:
        body = _org_invite(
            client, dev_token, organisation["OrganisationID"], email
        ).get_json()
    finally:
        trust_app.config["TRUST_INVITATION_TTL_HOURS"] = 72

    expires = datetime.fromisoformat(body["InviteExpiresAt"])
    remaining_hours = (expires - datetime.utcnow()).total_seconds() / 3600
    assert 4.5 < remaining_hours <= 5.1


def test_invite_url_can_use_a_configured_base_url(
        trust_app, client, admin_token, dev_token):
    email, _ = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    trust_app.config["TRUST_INVITE_BASE_URL"] = "https://vulnscan.example.com"
    try:
        body = _org_invite(
            client, dev_token, organisation["OrganisationID"], email
        ).get_json()
    finally:
        trust_app.config["TRUST_INVITE_BASE_URL"] = ""

    assert body["InviteURL"].startswith(
        "https://vulnscan.example.com/#/invitations/accept?token="
    )


def test_google_next_state_round_trip(trust_app, client):
    """A same-origin hash path survives the Google OAuth state round trip."""
    from app.routes.auth import _decode_next_state, _encode_next_state

    encoded = _encode_next_state("#/invitations/accept?token=abc-123")
    assert _decode_next_state(encoded) == "#/invitations/accept?token=abc-123"
    # Off-site or malformed destinations are dropped.
    assert _encode_next_state("https://evil.example.com") is None
    assert _decode_next_state("https://evil.example.com") is None
    assert _decode_next_state("!!!not-base64!!!") is None


def test_invite_and_accept_helper_still_works(
        trust_app, client, admin_token, dev_token):
    """The shared test helper (and therefore the documented API) is unchanged."""
    email, invitee_token = create_user(client, admin_token)
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    membership = invite_and_accept(
        client, dev_token, project["ProjectID"], invitee_token, email, "VIEWER"
    )
    assert membership["Status"] == "Active"
    assert membership["Role"] == "VIEWER"
