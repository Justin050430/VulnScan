"""Authorisation attestation tests."""
from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import TrustAuthorizationAttestation
from testing.trust_helpers import (
    bearer,
    buy_credit,
    create_attestation,
    create_org,
    create_project,
    full_scenario,
    profile_id,
    register_asset,
    verify_asset_directly,
)


@pytest.fixture()
def trust_app(app):
    app.config["TRUST_BOUNDARY_MODE"] = "enforce"
    return app


def _start(client, token, project_id, asset_id, profile, credit, attestation_id=None):
    body = {
        "asset_id": asset_id,
        "scan_profile_id": profile,
        "credit_id": credit["CreditUUID"],
        "target_url": "http://localhost:5199/",
    }
    if attestation_id:
        body["attestation_id"] = attestation_id
    return client.post(
        f"/api/v1/projects/{project_id}/scans", json=body, headers=bearer(token)
    )


def test_attestation_records_statement_and_hash(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    asset = register_asset(client, dev_token, project["ProjectID"])
    verify_asset_directly(trust_app, asset["AssetID"])

    attestation = create_attestation(
        client, dev_token, project["ProjectID"], asset["AssetID"], days=30
    )
    assert attestation["StatementVersion"] == "v1"
    assert len(attestation["StatementHash"]) == 64
    assert attestation["Status"] == "Active"

    with trust_app.app_context():
        row = db.session.get(TrustAuthorizationAttestation, attestation["AttestationID"])
        assert row.StatementText
        assert row.AttestedByUserID is not None
        assert row.ExpiresAt > datetime.utcnow()


def test_new_attestation_supersedes_previous(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    asset = register_asset(client, dev_token, project["ProjectID"])
    verify_asset_directly(trust_app, asset["AssetID"])

    first = create_attestation(client, dev_token, project["ProjectID"], asset["AssetID"])
    second = create_attestation(client, dev_token, project["ProjectID"], asset["AssetID"])

    rows = client.get(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/attestations",
        headers=bearer(dev_token),
    ).get_json()["Attestations"]
    active = [r for r in rows if r["Status"] == "Active"]
    assert len(active) == 1
    assert active[0]["AttestationID"] == second["AttestationID"]
    expired = [r for r in rows if r["AttestationID"] == first["AttestationID"]][0]
    assert expired["Status"] == "Expired"


def test_missing_attestation_blocks_scan(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    asset = register_asset(client, dev_token, project["ProjectID"])
    verify_asset_directly(trust_app, asset["AssetID"])
    credit = buy_credit(client, dev_token, project["ProjectID"])

    response = _start(client, dev_token, project["ProjectID"], asset["AssetID"],
                      profile_id(client, dev_token), credit)
    assert response.status_code == 403
    assert response.get_json()["code"] == "ATTESTATION_REQUIRED"


def test_expired_attestation_blocks_scan(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    asset = register_asset(client, dev_token, project["ProjectID"])
    verify_asset_directly(trust_app, asset["AssetID"])
    attestation = create_attestation(
        client, dev_token, project["ProjectID"], asset["AssetID"]
    )
    credit = buy_credit(client, dev_token, project["ProjectID"])

    with trust_app.app_context():
        row = db.session.get(
            TrustAuthorizationAttestation, attestation["AttestationID"]
        )
        row.ExpiresAt = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()

    explicit = _start(client, dev_token, project["ProjectID"], asset["AssetID"],
                      profile_id(client, dev_token), credit,
                      attestation_id=attestation["AttestationID"])
    assert explicit.status_code == 403
    assert explicit.get_json()["code"] == "ATTESTATION_EXPIRED"

    implicit = _start(client, dev_token, project["ProjectID"], asset["AssetID"],
                      profile_id(client, dev_token), credit)
    assert implicit.status_code == 403
    assert implicit.get_json()["code"] == "ATTESTATION_REQUIRED"


def test_revoked_attestation_blocks_scan(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    asset = register_asset(client, dev_token, project["ProjectID"])
    verify_asset_directly(trust_app, asset["AssetID"])
    attestation = create_attestation(
        client, dev_token, project["ProjectID"], asset["AssetID"]
    )
    credit = buy_credit(client, dev_token, project["ProjectID"])

    revoked = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}"
        f"/attestations/{attestation['AttestationID']}/revoke",
        json={"reason": "withdrawn"}, headers=bearer(dev_token),
    )
    assert revoked.status_code == 200

    response = _start(client, dev_token, project["ProjectID"], asset["AssetID"],
                      profile_id(client, dev_token), credit,
                      attestation_id=attestation["AttestationID"])
    assert response.status_code == 403
    assert response.get_json()["code"] == "ATTESTATION_REVOKED"


def test_attestation_from_another_asset_is_rejected(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    first = register_asset(client, dev_token, project["ProjectID"],
                           hostname="one.example.com")
    second = register_asset(client, dev_token, project["ProjectID"],
                            hostname="two.example.com")
    verify_asset_directly(trust_app, first["AssetID"])
    verify_asset_directly(trust_app, second["AssetID"])
    foreign = create_attestation(
        client, dev_token, project["ProjectID"], first["AssetID"]
    )
    create_attestation(client, dev_token, project["ProjectID"], second["AssetID"])
    credit = buy_credit(client, dev_token, project["ProjectID"])

    response = _start(client, dev_token, project["ProjectID"], second["AssetID"],
                      profile_id(client, dev_token), credit,
                      attestation_id=foreign["AttestationID"])
    assert response.status_code == 403
    assert response.get_json()["code"] == "ATTESTATION_ASSET_MISMATCH"


def test_attestation_expiry_bounds_validated(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    project = create_project(client, dev_token, organisation["OrganisationID"])
    asset = register_asset(client, dev_token, project["ProjectID"])
    verify_asset_directly(trust_app, asset["AssetID"])

    too_long = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/attestations",
        json={"expires_in_days": 365}, headers=bearer(dev_token),
    )
    assert too_long.status_code == 400
    assert too_long.get_json()["code"] == "VALIDATION_ERROR"

    unknown_version = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/attestations",
        json={"statement_version": "v99"}, headers=bearer(dev_token),
    )
    assert unknown_version.status_code == 400
