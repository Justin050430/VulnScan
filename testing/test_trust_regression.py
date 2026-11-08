"""Regression protection: the existing scanner still works through the gate."""
import pytest

from app.extensions import db
from app.models import Scan
from testing.trust_helpers import (
    bearer,
    create_user,
    full_scenario,
    login,
    profile_id,
)


@pytest.fixture()
def trust_app(app):
    app.config["TRUST_BOUNDARY_MODE"] = "enforce"
    return app


def _start_gated(client, token, scenario):
    response = client.post(
        f"/api/v1/projects/{scenario['project']['ProjectID']}/scans",
        json={
            "asset_id": scenario["asset"]["AssetID"],
            "scan_profile_id": profile_id(client, token),
            "credit_id": scenario["credit"]["CreditUUID"],
            "target_url": scenario["target_url"],
        },
        headers=bearer(token),
    )
    assert response.status_code == 202, response.get_json()
    return response.get_json()["Scan"]["ScanID"]


def test_gated_scan_detects_sqli_xss_and_headers(trust_app, client, dev_token,
                                                 target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    scan_id = _start_gated(client, dev_token, scenario)

    detail = client.get(f"/api/scans/{scan_id}", headers=bearer(dev_token)).get_json()
    scan = detail["Scan"]
    names = {f["VulnerabilityName"] for f in scan["Findings"]}
    assert "SQL Injection" in names
    assert "Cross-Site Scripting (XSS)" in names
    assert "Missing HTTP Security Headers" in names
    assert scan["Status"] == "Completed"
    assert scan["FindingCount"] == len(scan["Findings"])
    assert scan["OverallRisk"] in ("Critical", "High", "Medium", "Low", "None")
    assert scan["AnalysedPages"] >= 1
    assert "CoverageNote" in scan
    assert scan["TestedParameters"]


def test_gated_scan_keeps_false_positive_controls(trust_app, client, dev_token,
                                                  target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    scan_id = _start_gated(client, dev_token, scenario)
    detail = client.get(f"/api/scans/{scan_id}", headers=bearer(dev_token)).get_json()
    xss_urls = {
        f["URL"] for f in detail["Scan"]["Findings"]
        if f["VulnerabilityName"].startswith("Cross-Site")
    }
    assert not any("safe_search" in url for url in xss_urls)
    assert not any("comment_reflect" in url for url in xss_urls)


def test_exports_still_contain_findings(trust_app, client, dev_token, target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    scan_id = _start_gated(client, dev_token, scenario)

    csv_response = client.get(
        f"/api/scans/{scan_id}/report?format=csv", headers=bearer(dev_token)
    )
    assert csv_response.status_code == 200
    csv_text = csv_response.data.decode("utf-8-sig")
    assert "FINDINGS" in csv_text
    assert "SQL Injection" in csv_text

    pdf_response = client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=bearer(dev_token)
    )
    assert pdf_response.status_code == 200
    assert pdf_response.data[:4] == b"%PDF"


def test_progress_and_retest_still_work(trust_app, client, dev_token, target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    scan_id = _start_gated(client, dev_token, scenario)

    progress = client.get(
        f"/api/scans/{scan_id}/progress", headers=bearer(dev_token)
    ).get_json()["Progress"]
    assert progress["Status"] in ("Completed", "Running", "Pending")
    assert progress["PageCount"] >= 1

    detail = client.get(f"/api/scans/{scan_id}", headers=bearer(dev_token)).get_json()
    finding_id = detail["Scan"]["Findings"][0]["FindingID"]
    retest = client.post(
        f"/api/scans/{scan_id}/findings/{finding_id}/retest",
        json={}, headers=bearer(dev_token),
    )
    assert retest.status_code == 200, retest.get_json()
    assert retest.get_json()["Retest"]["Verdict"] in (
        "Resolved", "Still Detected", "Inconclusive", "Unable to Verify"
    )


def test_finding_triage_still_works(trust_app, client, dev_token, target):
    scenario = full_scenario(trust_app, client, None, dev_token, target_url=target)
    scan_id = _start_gated(client, dev_token, scenario)
    detail = client.get(f"/api/scans/{scan_id}", headers=bearer(dev_token)).get_json()
    finding_id = detail["Scan"]["Findings"][0]["FindingID"]
    updated = client.put(
        f"/api/scans/{scan_id}/findings/{finding_id}",
        json={"status": "False Positive"}, headers=bearer(dev_token),
    )
    assert updated.status_code == 200
    assert updated.get_json()["Finding"]["Status"] == "False Positive"


def test_legacy_mode_scans_are_unaffected(app, client, dev_token, target):
    """The extension must not change legacy scan behaviour or isolation."""
    app.config["TRUST_BOUNDARY_MODE"] = "legacy"
    profiles = client.get(
        "/api/scan-profiles", headers=bearer(dev_token)
    ).get_json()["ScanProfiles"]
    profile = [p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan"][0]

    created = client.post(
        "/api/scans",
        json={"target_url": target, "scan_profile_id": profile["ScanProfileID"]},
        headers=bearer(dev_token),
    )
    assert created.status_code == 202
    scan_id = created.get_json()["Scan"]["ScanID"]

    detail = client.get(f"/api/scans/{scan_id}", headers=bearer(dev_token))
    assert detail.status_code == 200
    assert detail.get_json()["Scan"]["FindingCount"] >= 1

    other_email = f"legacy-other-{scan_id}@vulnscan.local"
    admin = login(client, "admin@vulnscan.local", "Admin@VulnScan2025")
    client.post(
        "/api/users",
        json={"username": f"legacyother{scan_id}", "email": other_email,
              "password": "LegacyOther!23", "role": "Developer"},
        headers=bearer(admin),
    )
    other_token = login(client, other_email, "LegacyOther!23")
    denied = client.get(f"/api/scans/{scan_id}", headers=bearer(other_token))
    assert denied.status_code == 403

    with app.app_context():
        assert db.session.get(Scan, scan_id) is not None
