"""Shared helpers for the Trust Boundary Extension tests."""
import uuid
from datetime import datetime, timedelta

from app.extensions import db
from app.models import TrustAsset, TrustScanCredit

PASSWORD = "TrustBoundary!2026"


def unique(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def login(client, email, password=PASSWORD):
    response = client.post(
        "/api/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.get_json()
    return response.get_json()["access_token"]


def create_user(client, admin_token, role="Developer"):
    email = f"{unique('user')}@vulnscan.local"
    response = client.post(
        "/api/users",
        json={
            "username": unique("user")[:40],
            "email": email,
            "password": PASSWORD,
            "role": role,
        },
        headers=bearer(admin_token),
    )
    assert response.status_code == 201, response.get_json()
    return email, login(client, email)


def create_org(client, token, name=None):
    response = client.post(
        "/api/v1/organisations",
        json={"name": name or unique("Org")},
        headers=bearer(token),
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["Organisation"]


def create_project(client, token, organisation_id, name=None):
    response = client.post(
        "/api/v1/projects",
        json={"organisation_id": organisation_id, "name": name or unique("Project")},
        headers=bearer(token),
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["Project"]


def invite_and_accept(client, inviter_token, project_id, invitee_token,
                      invitee_email, role):
    response = client.post(
        f"/api/v1/projects/{project_id}/members",
        json={"email": invitee_email, "role": role},
        headers=bearer(inviter_token),
    )
    assert response.status_code == 201, response.get_json()
    token = response.get_json()["InviteToken"]
    accepted = client.post(
        "/api/v1/invitations/accept",
        json={"token": token},
        headers=bearer(invitee_token),
    )
    assert accepted.status_code == 200, accepted.get_json()
    return accepted.get_json()["Membership"]


def register_asset(client, token, project_id, hostname="localhost", scheme="http"):
    response = client.post(
        f"/api/v1/projects/{project_id}/assets",
        json={"hostname": hostname, "scheme": scheme},
        headers=bearer(token),
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["Asset"]


def verify_asset_directly(app, asset_id, days=90):
    """Mark an asset verified without the challenge (non-verification tests)."""
    with app.app_context():
        asset = db.session.get(TrustAsset, int(asset_id))
        asset.VerificationStatus = "Verified"
        asset.VerifiedAt = datetime.utcnow()
        asset.VerificationExpiresAt = datetime.utcnow() + timedelta(days=days)
        asset.VerificationEvidence = "test fixture verification"
        db.session.commit()


def create_attestation(client, token, project_id, asset_id, days=30):
    response = client.post(
        f"/api/v1/projects/{project_id}/assets/{asset_id}/attestations",
        json={"expires_in_days": days},
        headers=bearer(token),
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["Attestation"]


def buy_credit(client, token, project_id, product_code="SCAN_CREDIT_1",
               quantity=1):
    response = client.post(
        f"/api/v1/projects/{project_id}/payments/checkout",
        json={"product_code": product_code, "quantity": quantity},
        headers=bearer(token),
    )
    assert response.status_code == 201, response.get_json()
    payment = response.get_json()["Payment"]
    completed = client.post(
        f"/api/v1/projects/{project_id}/payments/{payment['PaymentUUID']}/mock-complete",
        json={"outcome": "success"},
        headers=bearer(token),
    )
    assert completed.status_code == 200, completed.get_json()
    credits = client.get(
        f"/api/v1/projects/{project_id}/credits?status=Available",
        headers=bearer(token),
    ).get_json()["Credits"]
    return credits[0]


def profile_id(client, token, name="OWASP Top 10 Full Scan"):
    profiles = client.get(
        "/api/scan-profiles", headers=bearer(token)
    ).get_json()["ScanProfiles"]
    return [p for p in profiles if p["Name"] == name][0]["ScanProfileID"]


def full_scenario(app, client, admin_token, owner_token, target_url=None,
                  role="PROJECT_OWNER", extra_member_role=None,
                  extra_member_token=None, extra_member_email=None,
                  verify=True, attest=True, credit=True):
    """Create org → project → (optional member) → asset → attestation → credit."""
    organisation = create_org(client, owner_token)
    project = create_project(client, owner_token, organisation["OrganisationID"])
    if extra_member_role and extra_member_token:
        invite_and_accept(
            client, owner_token, project["ProjectID"], extra_member_token,
            extra_member_email, extra_member_role,
        )
    asset = register_asset(client, owner_token, project["ProjectID"])
    if verify:
        verify_asset_directly(app, asset["AssetID"])
    attestation = (
        create_attestation(client, owner_token, project["ProjectID"], asset["AssetID"])
        if attest else None
    )
    credit_row = (
        buy_credit(client, owner_token, project["ProjectID"]) if credit else None
    )
    resolved_target = target_url or "http://localhost:5199/"
    # Assets are exact-host; the controlled target listens on 127.0.0.1 but is
    # registered under the hostname "localhost".
    resolved_target = resolved_target.replace("127.0.0.1", "localhost")
    return {
        "organisation": organisation,
        "project": project,
        "asset": asset,
        "attestation": attestation,
        "credit": credit_row,
        "target_url": resolved_target,
    }


def mark_credit_reserved(app, credit_uuid):
    with app.app_context():
        credit = TrustScanCredit.query.filter_by(CreditUUID=credit_uuid).first()
        credit.Status = "Reserved"
        credit.ReservedAt = datetime.utcnow()
        credit.ReservedUntil = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
