"""End-to-end gated scan tests: denial reasons, legacy disable and cancellation."""
from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import Scan, TrustScanContext, TrustScanCredit
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


@pytest.fixture()
def project(trust_app, client, dev_token):
    organisation = create_org(client, dev_token)
    return create_project(client, dev_token, organisation["OrganisationID"])


def _scan_body(asset, profile, credit, target_url="http://localhost:5199/",
               **extra):
    body = {
        "asset_id": asset["AssetID"],
        "scan_profile_id": profile,
        "credit_id": credit["CreditUUID"],
        "target_url": target_url,
    }
    body.update(extra)
    return body


def test_gated_scan_happy_path(trust_app, client, dev_token, target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=_scan_body(scenario["asset"], profile_id(client, dev_token),
                        scenario["credit"], scenario["target_url"]),
        headers=bearer(dev_token),
    )
    assert response.status_code == 202, response.get_json()
    body = response.get_json()
    scan_id = body["Scan"]["ScanID"]
    assert body["Scan"]["Status"] in ("Completed", "Pending", "Running")
    assert body["Credit"]["Status"] in ("Reserved", "Consumed")

    with trust_app.app_context():
        context = db.session.get(TrustScanContext, scan_id)
        assert context is not None
        assert context.ProjectID == scenario["project"]["ProjectID"]
        assert context.AttestationID == scenario["attestation"]["AttestationID"]
        credit = db.session.get(TrustScanCredit, context.CreditID)
        assert credit.Status == "Consumed"
        scan = db.session.get(Scan, scan_id)
        assert scan.Status == "Completed"

    detail = client.get(f"/api/scans/{scan_id}", headers=bearer(dev_token))
    assert detail.status_code == 200
    findings = detail.get_json()["Scan"]["Findings"]
    assert findings, "the gated scan should still detect the controlled findings"


def test_scan_without_credit_is_rejected(trust_app, client, dev_token, target):
    scenario = full_scenario(trust_app, client, None, dev_token,
                             target_url=target, credit=False)
    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json={
            "asset_id": scenario["asset"]["AssetID"],
            "scan_profile_id": profile_id(client, dev_token),
            "target_url": scenario["target_url"],
        },
        headers=bearer(dev_token),
    )
    assert response.status_code == 402
    assert response.get_json()["code"] == "CREDIT_REQUIRED"


def test_scan_with_unknown_credit_is_rejected(trust_app, client, dev_token,
                                              target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json={
            "asset_id": scenario["asset"]["AssetID"],
            "scan_profile_id": profile_id(client, dev_token),
            "credit_id": "00000000-0000-0000-0000-000000000000",
            "target_url": scenario["target_url"],
        },
        headers=bearer(dev_token),
    )
    assert response.status_code == 404


def test_target_host_must_match_asset(trust_app, client, dev_token, target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=_scan_body(scenario["asset"], profile_id(client, dev_token),
                        scenario["credit"], "http://127.0.0.1:5199/"),
        headers=bearer(dev_token),
    )
    assert response.status_code == 400
    assert response.get_json()["code"] == "TARGET_HOST_MISMATCH"


def test_active_scan_for_asset_blocks_second_scan(trust_app, client, dev_token,
                                                  target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    second_credit = buy_credit(client, dev_token, scenario["project"]["ProjectID"])
    # Simulate an already-running scan for the asset.
    with trust_app.app_context():
        scan = Scan(
            ScanName="already running",
            TargetURL=scenario["target_url"],
            Status="Running",
            StartedAt=datetime.utcnow(),
            UserID=1,
            ScanProfileID=profile_id(client, dev_token),
        )
        db.session.add(scan)
        db.session.flush()
        db.session.add(
            TrustScanContext(
                ScanID=scan.ScanID,
                OrganisationID=scenario["project"]["OrganisationID"],
                ProjectID=scenario["project"]["ProjectID"],
                AssetID=scenario["asset"]["AssetID"],
                AttestationID=scenario["attestation"]["AttestationID"],
                CreditID=second_credit["CreditID"],
                StartedByUserID=1,
            )
        )
        db.session.commit()

    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=_scan_body(scenario["asset"], profile_id(client, dev_token),
                        second_credit, scenario["target_url"]),
        headers=bearer(dev_token),
    )
    assert response.status_code == 409
    assert response.get_json()["code"] == "ACTIVE_SCAN_EXISTS"


def test_idempotent_replay_returns_same_scan(trust_app, client, dev_token, target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    body = _scan_body(scenario["asset"], profile_id(client, dev_token),
                      scenario["credit"], scenario["target_url"],
                      idempotency_key="gated-idempotency-1")
    first = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=body, headers=bearer(dev_token),
    )
    second = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=body, headers=bearer(dev_token),
    )
    assert first.status_code == 202
    assert second.status_code == 202
    assert second.get_json()["IdempotentReplay"] is True
    assert first.get_json()["Scan"]["ScanID"] == second.get_json()["Scan"]["ScanID"]


def test_legacy_scan_endpoint_disabled_in_enforce_mode(trust_app, client,
                                                       dev_token):
    response = client.post(
        "/api/scans",
        json={"target_url": "http://localhost:5199/", "scan_profile_id": 1},
        headers=bearer(dev_token),
    )
    assert response.status_code == 410
    assert response.get_json()["code"] == "LEGACY_SCAN_ENDPOINT_DISABLED"


def test_legacy_endpoint_available_in_legacy_mode(app, client, dev_token):
    app.config["TRUST_BOUNDARY_MODE"] = "legacy"
    response = client.post(
        "/api/scans",
        json={"target_url": "http://localhost:5999/", "scan_profile_id": 1},
        headers=bearer(dev_token),
    )
    # Validation still applies; the point is that it is not 410.
    assert response.status_code in (202, 400)


def test_readiness_reports_blocking_reasons(trust_app, client, dev_token,
                                            project):
    asset = register_asset(client, dev_token, project["ProjectID"])
    body = client.get(
        f"/api/v1/projects/{project['ProjectID']}/scan-readiness"
        f"?asset_id={asset['AssetID']}",
        headers=bearer(dev_token),
    ).get_json()["Readiness"]
    assert body["Ready"] is False
    assert body["Checks"]["Asset"]["Ok"] is False
    assert body["NextAction"] == "VERIFY_ASSET"


def test_cancel_scan(trust_app, client, dev_token, target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    # A synchronous scan finishes before it can be cancelled, so model a
    # still-running trust scan exactly as the worker would leave it.
    with trust_app.app_context():
        scan = Scan(
            ScanName="cancel me",
            TargetURL=scenario["target_url"],
            Status="Running",
            StartedAt=datetime.utcnow(),
            UserID=2,
            ScanProfileID=profile_id(client, dev_token),
        )
        db.session.add(scan)
        db.session.flush()
        db.session.add(
            TrustScanContext(
                ScanID=scan.ScanID,
                OrganisationID=scenario["project"]["OrganisationID"],
                ProjectID=scenario["project"]["ProjectID"],
                AssetID=scenario["asset"]["AssetID"],
                AttestationID=scenario["attestation"]["AttestationID"],
                CreditID=scenario["credit"]["CreditID"],
                StartedByUserID=2,
            )
        )
        db.session.commit()
        scan_id = scan.ScanID

    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans/{scan_id}/cancel",
        json={}, headers=bearer(dev_token),
    )
    assert response.status_code == 200
    assert response.get_json()["Scan"]["Status"] == "Cancelled"


def test_cancelled_scan_cannot_be_cancelled_by_outsider(trust_app, client,
                                                        admin_token, dev_token,
                                                        target):
    from testing.trust_helpers import create_user

    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    _email, outsider_token = create_user(client, admin_token)
    with trust_app.app_context():
        scan = Scan(
            ScanName="other",
            TargetURL=scenario["target_url"],
            Status="Running",
            StartedAt=datetime.utcnow(),
            UserID=2,
            ScanProfileID=profile_id(client, dev_token),
        )
        db.session.add(scan)
        db.session.flush()
        db.session.add(
            TrustScanContext(
                ScanID=scan.ScanID,
                OrganisationID=scenario["project"]["OrganisationID"],
                ProjectID=scenario["project"]["ProjectID"],
                AssetID=scenario["asset"]["AssetID"],
                AttestationID=scenario["attestation"]["AttestationID"],
                CreditID=scenario["credit"]["CreditID"],
                StartedByUserID=2,
            )
        )
        db.session.commit()
        scan_id = scan.ScanID

    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans/{scan_id}/cancel",
        json={}, headers=bearer(outsider_token),
    )
    assert response.status_code == 404
