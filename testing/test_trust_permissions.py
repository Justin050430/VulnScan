"""Permission-matrix and tenant-isolation tests for the Trust Boundary."""
import pytest

from testing.trust_helpers import (
    bearer,
    buy_credit,
    create_attestation,
    create_org,
    create_project,
    create_user,
    full_scenario,
    invite_and_accept,
    login,
    profile_id,
    register_asset,
    verify_asset_directly,
)


@pytest.fixture()
def trust_app(app):
    app.config["TRUST_BOUNDARY_MODE"] = "enforce"
    return app


def _scan_payload(scenario, profile, credit=None, target_url=None):
    return {
        "asset_id": scenario["asset"]["AssetID"],
        "scan_profile_id": profile,
        "credit_id": (credit or scenario["credit"])["CreditUUID"],
        "target_url": target_url or scenario["target_url"],
    }


def test_org_owner_without_project_role_cannot_start_scan(trust_app, client,
                                                          admin_token, dev_token):
    from app.extensions import db
    from app.models import TrustOrganisation, TrustProject

    organisation = create_org(client, dev_token, name="Owner Only Org")
    project = create_project(client, dev_token, organisation["OrganisationID"])
    asset = register_asset(client, dev_token, project["ProjectID"])
    verify_asset_directly(trust_app, asset["AssetID"])
    create_attestation(client, dev_token, project["ProjectID"], asset["AssetID"])
    credit = buy_credit(client, dev_token, project["ProjectID"])

    # Remove the automatic PROJECT_OWNER membership so only ORG_OWNER remains.
    with trust_app.app_context():
        from app.models import TrustProjectMembership

        TrustProjectMembership.query.filter_by(
            ProjectID=project["ProjectID"]
        ).delete()
        db.session.commit()

    response = client.post(
        f"/api/v1/projects/{project['ProjectID']}/scans",
        json={
            "asset_id": asset["AssetID"],
            "scan_profile_id": profile_id(client, dev_token),
            "credit_id": credit["CreditUUID"],
            "target_url": "http://localhost:5199/",
        },
        headers=bearer(dev_token),
    )
    assert response.status_code == 403
    assert response.get_json()["code"] == "PERMISSION_DENIED"


@pytest.mark.parametrize("role", ["VIEWER", "ANALYST"])
def test_viewer_and_analyst_cannot_start_scans(trust_app, client, admin_token,
                                               dev_token, role):
    email, member_token = create_user(client, admin_token)
    scenario = full_scenario(
        trust_app, client, admin_token, dev_token,
        extra_member_role=role, extra_member_token=member_token,
        extra_member_email=email,
    )
    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=_scan_payload(scenario, profile_id(client, dev_token)),
        headers=bearer(member_token),
    )
    assert response.status_code == 403
    assert response.get_json()["code"] == "PERMISSION_DENIED"


def test_viewer_can_read_results_but_not_start(trust_app, client, admin_token,
                                               dev_token, target):
    email, viewer_token = create_user(client, admin_token)
    scenario = full_scenario(
        trust_app, client, admin_token, dev_token, target_url=target,
        extra_member_role="VIEWER", extra_member_token=viewer_token,
        extra_member_email=email,
    )
    started = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=_scan_payload(scenario, profile_id(client, dev_token)),
        headers=bearer(dev_token),
    )
    assert started.status_code == 202, started.get_json()
    scan_id = started.get_json()["Scan"]["ScanID"]

    detail = client.get(f"/api/scans/{scan_id}", headers=bearer(viewer_token))
    assert detail.status_code == 200

    progress = client.get(
        f"/api/scans/{scan_id}/progress", headers=bearer(viewer_token)
    )
    assert progress.status_code == 200

    report = client.get(
        f"/api/scans/{scan_id}/report?format=csv", headers=bearer(viewer_token)
    )
    assert report.status_code == 200

    retest = client.post(
        f"/api/scans/{scan_id}/findings/1/retest",
        json={}, headers=bearer(viewer_token),
    )
    assert retest.status_code == 403


def test_scan_operator_can_start_scan(trust_app, client, admin_token,
                                      dev_token, target):
    email, operator_token = create_user(client, admin_token)
    scenario = full_scenario(
        trust_app, client, admin_token, dev_token, target_url=target,
        extra_member_role="SCAN_OPERATOR", extra_member_token=operator_token,
        extra_member_email=email,
    )
    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=_scan_payload(scenario, profile_id(client, dev_token)),
        headers=bearer(operator_token),
    )
    assert response.status_code == 202, response.get_json()


def test_analyst_can_retest_but_not_start(trust_app, client, admin_token,
                                          dev_token, target):
    email, analyst_token = create_user(client, admin_token)
    scenario = full_scenario(
        trust_app, client, admin_token, dev_token, target_url=target,
        extra_member_role="ANALYST", extra_member_token=analyst_token,
        extra_member_email=email,
    )
    started = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=_scan_payload(scenario, profile_id(client, dev_token)),
        headers=bearer(dev_token),
    )
    scan_id = started.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}", headers=bearer(analyst_token))
    finding_id = detail.get_json()["Scan"]["Findings"][0]["FindingID"]
    retest = client.post(
        f"/api/scans/{scan_id}/findings/{finding_id}/retest",
        json={}, headers=bearer(analyst_token),
    )
    assert retest.status_code == 200, retest.get_json()


def test_cross_project_access_is_denied(trust_app, client, admin_token,
                                        dev_token, target):
    email, outsider_token = create_user(client, admin_token)
    scenario = full_scenario(trust_app, client, admin_token, dev_token,
                             target_url=target)
    other_org = create_org(client, outsider_token, name="Other Org")
    other_project = create_project(client, outsider_token,
                                   other_org["OrganisationID"])

    started = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=_scan_payload(scenario, profile_id(client, dev_token)),
        headers=bearer(dev_token),
    )
    scan_id = started.get_json()["Scan"]["ScanID"]

    # Cross-tenant reads look like "not found", never confirming existence.
    assert client.get(
        f"/api/v1/projects/{scenario['project']['ProjectID']}",
        headers=bearer(outsider_token),
    ).status_code == 404
    assert client.get(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/assets",
        headers=bearer(outsider_token),
    ).status_code == 404
    assert client.get(
        f"/api/scans/{scan_id}", headers=bearer(outsider_token)
    ).status_code == 403
    assert client.get(
        f"/api/scans/{scan_id}/report?format=csv", headers=bearer(outsider_token)
    ).status_code == 403
    assert client.post(
        f"/api/v1/projects/{other_project['ProjectID']}/scans",
        json={
            "asset_id": scenario["asset"]["AssetID"],
            "scan_profile_id": profile_id(client, dev_token),
            "credit_id": scenario["credit"]["CreditUUID"],
        },
        headers=bearer(outsider_token),
    ).status_code == 404


def test_platform_admin_does_not_bypass_tenant_isolation(trust_app, client,
                                                         admin_token, dev_token,
                                                         target):
    scenario = full_scenario(trust_app, client, admin_token, dev_token,
                             target_url=target)
    started = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=_scan_payload(scenario, profile_id(client, dev_token)),
        headers=bearer(dev_token),
    )
    scan_id = started.get_json()["Scan"]["ScanID"]
    response = client.get(f"/api/scans/{scan_id}", headers=bearer(admin_token))
    assert response.status_code == 403


def test_membership_revocation_takes_effect_immediately(trust_app, client,
                                                        admin_token, dev_token,
                                                        target):
    email, member_token = create_user(client, admin_token)
    scenario = full_scenario(
        trust_app, client, admin_token, dev_token, target_url=target,
        extra_member_role="SCAN_OPERATOR", extra_member_token=member_token,
        extra_member_email=email,
    )
    members = client.get(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/members",
        headers=bearer(dev_token),
    ).get_json()["Members"]
    member_row = [m for m in members if m["Role"] == "SCAN_OPERATOR"][0]

    revoke = client.delete(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/members/"
        f"{member_row['ProjectMembershipID']}",
        headers=bearer(dev_token),
    )
    assert revoke.status_code == 200

    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json=_scan_payload(scenario, profile_id(client, dev_token)),
        headers=bearer(member_token),
    )
    assert response.status_code == 404


def test_permission_listing_matches_role(trust_app, client, admin_token,
                                         dev_token):
    email, viewer_token = create_user(client, admin_token)
    scenario = full_scenario(
        trust_app, client, admin_token, dev_token,
        extra_member_role="VIEWER", extra_member_token=viewer_token,
        extra_member_email=email,
    )
    body = client.get(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/permissions",
        headers=bearer(viewer_token),
    ).get_json()
    assert body["ProjectRole"] == "VIEWER"
    assert body["CanStartScan"] is False
    assert "scan.start" not in body["Permissions"]
    assert "report.download" in body["Permissions"]
