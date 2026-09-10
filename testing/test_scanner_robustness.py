"""
Scanner robustness tests: timeout handling and protection against
false positives on pages that legitimately contain SQL-error-like text.
"""
from conftest import auth


def _headers_profile(client, token):
    profiles = client.get("/api/scan-profiles", headers=auth(token)).get_json()["ScanProfiles"]
    return next(p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]


def test_slow_target_times_out_and_fails_gracefully(app, client, dev_token, target):
    """A target that exceeds the timeout must not hang the scanner."""
    app.config["SCANNER_DEFAULT_TIMEOUT"] = 0.5
    try:
        pid = _headers_profile(client, dev_token)
        resp = client.post("/api/scans", headers=auth(dev_token), json={
            "target_url": target + "slow", "scan_profile_id": pid,
            "scan_name": "Timeout scan"})
        assert resp.status_code == 202
        scan_id = resp.get_json()["Scan"]["ScanID"]
        detail = client.get(f"/api/scans/{scan_id}", headers=auth(dev_token)).get_json()["Scan"]
        # The unreachable/slow start page means the scan cannot proceed.
        assert detail["Status"] == "Failed"
        assert detail["FinishedAt"] is not None
    finally:
        app.config["SCANNER_DEFAULT_TIMEOUT"] = 10


def test_sql_like_text_in_normal_page_is_not_reported(client, dev_token, target):
    """
    A page containing SQL-error-like text as ordinary content must NOT produce
    an SQL Injection finding (the signature is present in the baseline).
    """
    pid = _headers_profile(client, dev_token)
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target + "docs?q=test", "scan_profile_id": pid,
        "scan_name": "SQL text control"})
    scan_id = resp.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}", headers=auth(dev_token)).get_json()["Scan"]

    sqli = [f for f in detail["Findings"] if f["VulnerabilityName"] == "SQL Injection"]
    assert not sqli, "page with SQL-like text wrongly flagged as SQL injection"
