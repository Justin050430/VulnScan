"""
Core scanner + scan-API tests.

Scans are run against the controlled vulnerable target (127.0.0.1:5199)
defined in conftest; no public hosts are contacted.
"""
import pytest

from conftest import auth, TARGET_URL


def _full_scan_profile_id(client, token):
    profiles = client.get("/api/scan-profiles", headers=auth(token)).get_json()["ScanProfiles"]
    return next(p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]


def _run_scan(client, token, name="Automated test scan", profile_name="OWASP Top 10 Full Scan"):
    profiles = client.get("/api/scan-profiles", headers=auth(token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == profile_name)["ScanProfileID"]
    resp = client.post("/api/scans", headers=auth(token), json={
        "target_url": TARGET_URL, "scan_profile_id": pid, "scan_name": name})
    assert resp.status_code == 202
    scan_id = resp.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}", headers=auth(token)).get_json()["Scan"]
    return scan_id, detail


def test_invalid_target_rejected(client, dev_token):
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": "ftp://example.com", "scan_profile_id": 1})
    assert resp.status_code == 400


def test_missing_profile_rejected(client, dev_token):
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": TARGET_URL})
    assert resp.status_code == 400


def test_unknown_profile_rejected(client, dev_token):
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": TARGET_URL, "scan_profile_id": 999999})
    assert resp.status_code == 400


def test_scan_detects_real_vulnerabilities(client, dev_token, target):
    scan_id, detail = _run_scan(client, dev_token)

    assert detail["Status"] == "Completed"
    assert detail["FinishedAt"] is not None
    assert detail["PageCount"] >= 5

    findings = detail["Findings"]
    names = {f["VulnerabilityName"] for f in findings}
    assert {"SQL Injection", "Cross-Site Scripting (XSS)",
            "Missing HTTP Security Headers"}.issubset(names)

    # Findings must carry concrete, non-placeholder evidence and a page.
    for f in findings:
        assert f["URL"].startswith(TARGET_URL.rstrip("/"))
        assert f["Evidence"]
        assert f["RiskScore"] is not None
        assert f["Classification"] in ("Confirmed", "Suspected")


def test_scan_records_pages_and_findings_in_database(client, dev_token, target, app):
    from app.extensions import db
    from app.models import DiscoveredPage, Finding

    scan_id, detail = _run_scan(client, dev_token, name="DB persistence scan")
    with app.app_context():
        pages = db.session.query(DiscoveredPage).filter_by(ScanID=scan_id).count()
        rows = (db.session.query(Finding)
                .join(DiscoveredPage, Finding.PageID == DiscoveredPage.PageID)
                .filter(DiscoveredPage.ScanID == scan_id).count())
    assert pages == detail["PageCount"]
    assert rows == detail["FindingCount"]


def test_scan_report_pdf_and_csv(client, dev_token, target):
    scan_id, _ = _run_scan(client, dev_token, name="Report test")
    pdf = client.get(f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token))
    assert pdf.status_code == 200
    assert pdf.data[:4] == b"%PDF"
    csv = client.get(f"/api/scans/{scan_id}/report?format=csv", headers=auth(dev_token))
    assert csv.status_code == 200
    assert "FINDINGS" in csv.data.decode("utf-8-sig")


def test_finding_status_update_and_access_control(client, admin_token, dev_token, target):
    scan_id, detail = _run_scan(client, dev_token, name="Status test")
    fid = detail["Findings"][0]["FindingID"]

    r = client.put(f"/api/scans/{scan_id}/findings/{fid}",
                   headers=auth(dev_token), json={"status": "Resolved"})
    assert r.status_code == 200
    assert r.get_json()["Finding"]["Status"] == "Resolved"

    r = client.put(f"/api/scans/{scan_id}/findings/{fid}",
                   headers=auth(dev_token), json={"status": "Banana"})
    assert r.status_code == 400

    # admin can read any scan
    assert client.get(f"/api/scans/{scan_id}", headers=auth(admin_token)).status_code == 200

    # another developer must not see this scan
    client.post("/api/users", headers=auth(admin_token), json={
        "username": "outsider", "email": "outsider@vulnscan.local",
        "password": "Outsider@2025", "role": "Developer"})
    other_token = client.post("/api/auth/login", json={
        "email": "outsider@vulnscan.local", "password": "Outsider@2025"}).get_json()["access_token"]
    assert client.get(f"/api/scans/{scan_id}", headers=auth(other_token)).status_code == 403
    # ... and must not be able to triage its findings
    assert client.put(f"/api/scans/{scan_id}/findings/{fid}",
                      headers=auth(other_token), json={"status": "Open"}).status_code == 403


def test_scan_list_isolated_per_developer(client, admin_token, dev_token, target):
    _run_scan(client, dev_token, name="Isolation scan")
    client.post("/api/users", headers=auth(admin_token), json={
        "username": "otherdev", "email": "otherdev@vulnscan.local",
        "password": "Otherdev@2025", "role": "Developer"})
    other_token = client.post("/api/auth/login", json={
        "email": "otherdev@vulnscan.local", "password": "Otherdev@2025"}).get_json()["access_token"]

    dev_scans = client.get("/api/scans", headers=auth(dev_token)).get_json()
    other_scans = client.get("/api/scans", headers=auth(other_token)).get_json()
    assert dev_scans["Total"] >= 1
    assert other_scans["Total"] == 0
    # admin sees all
    admin_scans = client.get("/api/scans", headers=auth(admin_token)).get_json()
    assert admin_scans["Total"] >= dev_scans["Total"]
