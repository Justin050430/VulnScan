"""
Error-handling tests.

The application must fail safely with meaningful errors (never a stack trace
or an unhandled exception) for invalid input, missing resources, database
failures and malformed scan targets.
"""
import pytest

from conftest import auth


# --------------------------------------------------------------------------
# Invalid input / invalid targets
# --------------------------------------------------------------------------
@pytest.mark.parametrize("bad_url", [
    "",
    "not-a-url",
    "ftp://example.com",
    "javascript:alert(1)",
    "data:text/html,<h1>x</h1>",
    "http://",
    "http://:8080/",
    "file:///etc/passwd",
])
def test_invalid_target_urls_rejected(client, dev_token, bad_url):
    profiles = client.get("/api/scan-profiles", headers=auth(dev_token)).get_json()["ScanProfiles"]
    pid = profiles[0]["ScanProfileID"]
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": bad_url, "scan_profile_id": pid, "scan_name": "Bad target"})
    assert resp.status_code == 400
    assert resp.get_json().get("message")


# --------------------------------------------------------------------------
# Missing resources
# --------------------------------------------------------------------------
def test_missing_scan_returns_404(client, admin_token):
    assert client.get("/api/scans/999999", headers=auth(admin_token)).status_code == 404


def test_missing_finding_update_returns_error(client, dev_token, target):
    profiles = client.get("/api/scan-profiles", headers=auth(dev_token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == "Basic Security Headers")["ScanProfileID"]
    scan_id = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target, "scan_profile_id": pid}).get_json()["Scan"]["ScanID"]
    resp = client.put(f"/api/scans/{scan_id}/findings/999999",
                      headers=auth(dev_token), json={"status": "Open"})
    assert resp.status_code in (400, 404)
    assert resp.get_json().get("message")


def test_missing_vulnerability_update_returns_400(client, admin_token):
    resp = client.put("/api/vulnerabilities/999999", headers=auth(admin_token),
                      json={"Description": "x"})
    assert resp.status_code == 400


def test_missing_profile_update_returns_400(client, admin_token):
    resp = client.put("/api/scan-profiles/999999", headers=auth(admin_token),
                      json={"name": "x"})
    assert resp.status_code == 400


def test_missing_user_disable_returns_400(client, admin_token):
    assert client.delete("/api/users/999999", headers=auth(admin_token)).status_code == 400


# --------------------------------------------------------------------------
# Database failure
# --------------------------------------------------------------------------
def test_database_failure_returns_generic_500(app, client, monkeypatch):
    from sqlalchemy.exc import OperationalError

    import app.services.auth_service as auth_service

    def boom(*args, **kwargs):
        raise OperationalError("SELECT 1", {}, Exception("database unavailable"))

    monkeypatch.setattr(auth_service, "authenticate_user", boom)
    original = app.config.get("PROPAGATE_EXCEPTIONS")
    app.config["PROPAGATE_EXCEPTIONS"] = False  # let the error handler respond
    try:
        resp = client.post("/api/auth/login", json={
            "email": "developer@vulnscan.local", "password": "Developer@VulnScan2025"})
    finally:
        app.config["PROPAGATE_EXCEPTIONS"] = original
    assert resp.status_code == 500
    body = resp.get_json()
    assert body and "message" in body
    raw = resp.get_data(as_text=True)
    assert "Traceback" not in raw
    assert "database unavailable" not in raw  # internals not leaked


# --------------------------------------------------------------------------
# Malformed / unexpected target responses
# --------------------------------------------------------------------------
def _run_basic_scan(client, token, url):
    profiles = client.get("/api/scan-profiles", headers=auth(token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]
    resp = client.post("/api/scans", headers=auth(token), json={
        "target_url": url, "scan_profile_id": pid, "scan_name": "Robustness"})
    assert resp.status_code == 202
    scan_id = resp.get_json()["Scan"]["ScanID"]
    return client.get(f"/api/scans/{scan_id}", headers=auth(token)).get_json()["Scan"]


def test_malformed_html_target_handled(client, dev_token, target):
    detail = _run_basic_scan(client, dev_token, target + "malformed")
    assert detail["Status"] in ("Completed", "Failed")
    assert isinstance(detail["Findings"], list)


def test_binary_response_target_handled(client, dev_token, target):
    detail = _run_basic_scan(client, dev_token, target + "binary")
    assert detail["Status"] in ("Completed", "Failed")
    assert isinstance(detail["Pages"], list)
