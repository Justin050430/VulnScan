"""Asset registration and ownership-verification tests."""
from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import TrustAsset
from testing.trust_helpers import (
    bearer,
    buy_credit,
    create_attestation,
    create_org,
    create_project,
    profile_id,
    register_asset,
    verify_asset_directly,
)


@pytest.fixture()
def trust_app(app):
    app.config["TRUST_BOUNDARY_MODE"] = "enforce"
    app.config["TRUST_WEBFILE_PORT"] = 5199
    return app


@pytest.fixture()
def project(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    return create_project(client, dev_token, organisation["OrganisationID"])


@pytest.mark.parametrize("hostname", [
    "127.0.0.1", "::1", "10.0.0.5", "*.example.com", "https://example.com",
    "example.com/path", "user@example.com", "example.com:8080", "-bad.example.com",
])
def test_invalid_hostnames_rejected(trust_app, client, dev_token, project, hostname):
    response = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets",
        json={"hostname": hostname},
        headers=bearer(dev_token),
    )
    assert response.status_code == 400
    assert response.get_json()["code"] == "HOSTNAME_INVALID"


def test_duplicate_hostname_rejected(trust_app, client, dev_token, project):
    register_asset(client, dev_token, project["ProjectID"], hostname="shop.example.com")
    response = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets",
        json={"hostname": "SHOP.example.com"},
        headers=bearer(dev_token),
    )
    assert response.status_code == 409
    assert response.get_json()["code"] == "DUPLICATE_ASSET"


def test_dns_txt_verification_success(trust_app, client, dev_token, project,
                                      monkeypatch):
    from app.services import asset_verification_service as avs

    asset = register_asset(client, dev_token, project["ProjectID"],
                           hostname="shop.example.com")
    started = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/verification",
        json={"method": "DNS_TXT"}, headers=bearer(dev_token),
    )
    assert started.status_code == 200
    challenge = started.get_json()["Challenge"]
    assert challenge["RecordName"] == "_vulnscan-challenge.shop.example.com"
    token = challenge["RecordValue"]

    monkeypatch.setattr(avs, "_resolve_txt", lambda name: [token])
    checked = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}"
        "/verification/check",
        json={}, headers=bearer(dev_token),
    )
    assert checked.status_code == 200, checked.get_json()
    body = checked.get_json()
    assert body["Asset"]["VerificationStatus"] == "Verified"
    assert body["Asset"]["VerificationExpiresAt"] is not None
    # The plaintext challenge token is never stored or echoed back as evidence.
    assert "vulnscan-verify=" not in body["Verification"]["Evidence"]

    events = client.get(
        f"/api/v1/projects/{project['ProjectID']}/audit-events",
        headers=bearer(dev_token),
    ).get_json()["Events"]
    assert any(e["EventType"] == "ASSET_VERIFIED" for e in events)


def test_dns_txt_verification_mismatch(trust_app, client, dev_token, project,
                                       monkeypatch):
    from app.services import asset_verification_service as avs

    asset = register_asset(client, dev_token, project["ProjectID"],
                           hostname="shop.example.com")
    client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/verification",
        json={"method": "DNS_TXT"}, headers=bearer(dev_token),
    )
    monkeypatch.setattr(avs, "_resolve_txt",
                        lambda name: ["vulnscan-verify=wrong-token"])
    checked = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}"
        "/verification/check",
        json={}, headers=bearer(dev_token),
    )
    assert checked.status_code == 409
    assert checked.get_json()["code"] == "VERIFICATION_MISMATCH"


def test_web_file_verification_success(trust_app, client, dev_token, project,
                                       target, vuln_target_module):
    asset = register_asset(client, dev_token, project["ProjectID"],
                           hostname="localhost", scheme="http")
    started = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/verification",
        json={"method": "WEB_FILE"}, headers=bearer(dev_token),
    )
    assert started.status_code == 200
    challenge = started.get_json()["Challenge"]
    assert challenge["FileURL"] == "http://localhost:5199/.well-known/vulnscan.txt"

    vuln_target_module.WELL_KNOWN["content"] = challenge["FileContent"] + "\n"
    checked = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}"
        "/verification/check",
        json={}, headers=bearer(dev_token),
    )
    assert checked.status_code == 200, checked.get_json()
    assert checked.get_json()["Asset"]["VerificationStatus"] == "Verified"


def test_web_file_verification_mismatch(trust_app, client, dev_token, project,
                                        target, vuln_target_module):
    asset = register_asset(client, dev_token, project["ProjectID"],
                           hostname="localhost", scheme="http")
    client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/verification",
        json={"method": "WEB_FILE"}, headers=bearer(dev_token),
    )
    vuln_target_module.WELL_KNOWN["content"] = "vulnscan-verify=not-the-token\n"
    checked = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}"
        "/verification/check",
        json={}, headers=bearer(dev_token),
    )
    assert checked.status_code == 409
    assert checked.get_json()["code"] == "VERIFICATION_MISMATCH"


def test_verification_challenge_expiry_blocks_check(trust_app, client, dev_token,
                                                    project):
    asset = register_asset(client, dev_token, project["ProjectID"],
                           hostname="shop.example.com")
    client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/verification",
        json={"method": "DNS_TXT"}, headers=bearer(dev_token),
    )
    with trust_app.app_context():
        row = db.session.get(TrustAsset, asset["AssetID"])
        row.VerificationTokenExpiresAt = datetime.utcnow() - timedelta(minutes=1)
        db.session.commit()
    checked = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}"
        "/verification/check",
        json={}, headers=bearer(dev_token),
    )
    assert checked.status_code == 409
    assert checked.get_json()["code"] == "VERIFICATION_TOKEN_EXPIRED"


def test_web_file_url_includes_configured_port(trust_app, client, dev_token,
                                              project):
    """Assets hold a hostname only; the verification port is configurable."""
    trust_app.config["TRUST_WEBFILE_PORT"] = 5001
    asset = register_asset(client, dev_token, project["ProjectID"],
                           hostname="localhost", scheme="http")
    started = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/verification",
        json={"method": "WEB_FILE"}, headers=bearer(dev_token),
    )
    assert started.status_code == 200
    assert started.get_json()["Challenge"]["FileURL"] == \
        "http://localhost:5001/.well-known/vulnscan.txt"


def test_local_helper_page_publishes_challenge(trust_app, client, dev_token,
                                               project, target):
    """The local-only helper page can publish the runtime challenge value."""
    import requests

    trust_app.config["TRUST_WEBFILE_PORT"] = 5199
    asset = register_asset(client, dev_token, project["ProjectID"],
                           hostname="localhost", scheme="http")
    started = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/verification",
        json={"method": "WEB_FILE"}, headers=bearer(dev_token),
    )
    challenge = started.get_json()["Challenge"]
    published = requests.post(
        "http://localhost:5199/__test__/verification",
        data={"content": challenge["FileContent"]}, timeout=10,
    )
    assert published.status_code == 200

    checked = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}"
        "/verification/check",
        json={}, headers=bearer(dev_token),
    )
    assert checked.status_code == 200, checked.get_json()
    assert checked.get_json()["Asset"]["VerificationStatus"] == "Verified"


def _scan_body(scenario_asset, profile, credit):
    return {
        "asset_id": scenario_asset["AssetID"],
        "scan_profile_id": profile,
        "credit_id": credit["CreditUUID"],
        "target_url": "http://localhost:5199/",
    }


def test_expired_verification_blocks_scan(trust_app, client, dev_token, project,
                                          target):
    asset = register_asset(client, dev_token, project["ProjectID"])
    verify_asset_directly(trust_app, asset["AssetID"])
    create_attestation(client, dev_token, project["ProjectID"], asset["AssetID"])
    credit = buy_credit(client, dev_token, project["ProjectID"])
    with trust_app.app_context():
        row = db.session.get(TrustAsset, asset["AssetID"])
        row.VerificationExpiresAt = datetime.utcnow() - timedelta(days=1)
        db.session.commit()

    response = client.post(
        f"/api/v1/projects/{project['ProjectID']}/scans",
        json=_scan_body(asset, profile_id(client, dev_token), credit),
        headers=bearer(dev_token),
    )
    assert response.status_code == 403
    assert response.get_json()["code"] == "ASSET_VERIFICATION_EXPIRED"


def test_revoked_asset_blocks_scan(trust_app, client, dev_token, project, target):
    asset = register_asset(client, dev_token, project["ProjectID"])
    verify_asset_directly(trust_app, asset["AssetID"])
    create_attestation(client, dev_token, project["ProjectID"], asset["AssetID"])
    credit = buy_credit(client, dev_token, project["ProjectID"])

    revoked = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/revoke",
        json={"reason": "ownership changed"}, headers=bearer(dev_token),
    )
    assert revoked.status_code == 200

    response = client.post(
        f"/api/v1/projects/{project['ProjectID']}/scans",
        json=_scan_body(asset, profile_id(client, dev_token), credit),
        headers=bearer(dev_token),
    )
    assert response.status_code == 403
    assert response.get_json()["code"] == "ASSET_REVOKED"


def test_unverified_asset_blocks_scan(trust_app, client, dev_token, project,
                                      target):
    asset = register_asset(client, dev_token, project["ProjectID"])
    credit = buy_credit(client, dev_token, project["ProjectID"])

    attestation_response = client.post(
        f"/api/v1/projects/{project['ProjectID']}/assets/{asset['AssetID']}/attestations",
        json={"expires_in_days": 30}, headers=bearer(dev_token),
    )
    assert attestation_response.status_code == 403
    assert attestation_response.get_json()["code"] == "ASSET_NOT_VERIFIED"

    response = client.post(
        f"/api/v1/projects/{project['ProjectID']}/scans",
        json=_scan_body(asset, profile_id(client, dev_token), credit),
        headers=bearer(dev_token),
    )
    assert response.status_code == 403
    assert response.get_json()["code"] == "ASSET_NOT_VERIFIED"
