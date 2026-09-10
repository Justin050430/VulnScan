"""Security audit logging tests for significant system events."""
from conftest import auth

UNREACHABLE = "http://127.0.0.1:5197/"


def _actions(client, admin_token, search=None):
    params = {"per_page": 200}
    if search:
        params["search"] = search
    logs = client.get("/api/audit-logs", headers=auth(admin_token),
                      query_string=params).get_json()["AuditLogs"]
    return logs


def test_login_logout_are_audited(client, admin_token):
    # fresh token to produce its own logout event
    token = client.post("/api/auth/login", json={
        "email": "developer@vulnscan.local", "password": "Developer@VulnScan2025"}).get_json()["access_token"]
    client.post("/api/auth/logout", headers=auth(token))
    actions = [l["Action"] for l in _actions(client, admin_token)]
    assert "LOGIN_SUCCESS" in actions
    assert "LOGOUT" in actions


def test_failed_login_is_audited(client, admin_token):
    client.post("/api/auth/login", json={
        "email": "developer@vulnscan.local", "password": "definitely-wrong"})
    logs = _actions(client, admin_token, search="Failed sign-in")
    assert any(l["Action"] == "LOGIN_FAILED" and l["Status"] == "Failure" for l in logs)


def test_scan_lifecycle_is_audited(client, admin_token, dev_token, target):
    profiles = client.get("/api/scan-profiles", headers=auth(dev_token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == "Basic Security Headers")["ScanProfileID"]
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target, "scan_profile_id": pid, "scan_name": "Audited scan"})
    scan_id = resp.get_json()["Scan"]["ScanID"]

    actions = [l["Action"] for l in _actions(client, admin_token)]
    assert "SCAN_CREATED" in actions
    assert "SCAN_STARTED" in actions
    assert "SCAN_COMPLETED" in actions

    # the completion record is linked to the scan entity
    completed = [l for l in _actions(client, admin_token) if l["Action"] == "SCAN_COMPLETED"]
    assert any(l["EntityType"] == "Scan" and l["EntityID"] == scan_id for l in completed)


def test_failed_scan_is_audited(client, admin_token, dev_token, target):
    profiles = client.get("/api/scan-profiles", headers=auth(dev_token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == "Basic Security Headers")["ScanProfileID"]
    client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": UNREACHABLE, "scan_profile_id": pid, "scan_name": "Audited failure"})

    failed = [l for l in _actions(client, admin_token) if l["Action"] == "SCAN_FAILED"]
    assert failed
    assert failed[0]["Status"] == "Failure"
    assert "could not be reached" in failed[0]["Description"].lower()


def test_report_generation_is_audited(client, admin_token, dev_token, target):
    profiles = client.get("/api/scan-profiles", headers=auth(dev_token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == "Basic Security Headers")["ScanProfileID"]
    scan_id = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target, "scan_profile_id": pid}).get_json()["Scan"]["ScanID"]
    client.get(f"/api/scans/{scan_id}/report?format=csv", headers=auth(dev_token))
    exports = [l for l in _actions(client, admin_token) if l["Action"] == "REPORT_EXPORTED"]
    assert any(l["EntityID"] == scan_id for l in exports)


def test_administrative_and_vulnerability_changes_are_audited(client, admin_token):
    client.post("/api/users", headers=auth(admin_token), json={
        "username": "audituser", "email": "audituser@vulnscan.local",
        "password": "Audit@12345", "role": "Developer"})
    client.post("/api/vulnerabilities", headers=auth(admin_token), json={
        "Name": "Audit Test Vuln", "OWASPCategory": "Test"})
    actions = [l["Action"] for l in _actions(client, admin_token)]
    assert "USER_CREATED" in actions
    assert "VULNERABILITY_CREATED" in actions
