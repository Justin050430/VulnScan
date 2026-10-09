"""
Finding retest / verification tests (D1).

A retest synchronously re-runs the finding's original detection module
against its exact page and classifies the outcome:

  * Still Detected    - the module re-detects the same parameter,
  * Resolved          - the module runs cleanly and finds no signal
                        (verified absence; the finding is auto-resolved),
  * Unable to Verify  - the page is unreachable / no longer analysable,
  * access control    - owner/admin only, findings must belong to the scan.
"""
from conftest import auth


def _full_scan(client, token, url):
    profiles = client.get("/api/scan-profiles",
                          headers=auth(token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles
               if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]
    resp = client.post("/api/scans", headers=auth(token), json={
        "target_url": url, "scan_profile_id": pid, "scan_name": "Retest fixture"})
    assert resp.status_code == 202
    sid = resp.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{sid}",
                        headers=auth(token)).get_json()["Scan"]
    return sid, detail


def _sqli_finding(detail):
    return next(f for f in detail["Findings"]
                if f["VulnerabilityName"] == "SQL Injection"
                and "/product" in f["URL"])


def _retest(client, token, sid, fid):
    return client.post(f"/api/scans/{sid}/findings/{fid}/retest",
                       headers=auth(token), json={})


def test_retest_still_detected(client, dev_token, target):
    """An unfixed page re-detects the same parameter -> Still Detected."""
    sid, detail = _full_scan(client, dev_token, target)
    finding = _sqli_finding(detail)
    resp = _retest(client, dev_token, sid, finding["FindingID"])
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["Retest"]["Verdict"] == "Still Detected"
    assert body["Retest"]["RequestsIssued"] > 0
    updated = body["Finding"]
    assert updated["Status"] == "Open"
    assert "RETEST" in updated["Evidence"]
    assert "re-opened" in updated["Evidence"]
    # additive API keys expose the verification history (with parsed detail)
    assert updated["Retests"] and updated["Retests"][-1]["Verdict"] == "Still Detected"
    entry = updated["Retests"][-1]
    assert entry["At"].endswith("UTC")
    assert entry["Message"]
    assert entry["Confidence"] is not None
    assert entry["RequestsIssued"] > 0
    assert entry["Technique"]
    assert updated["LatestRetestVerdict"] == "Still Detected"


def test_retest_resolved_after_remediation(client, dev_token, target, app):
    """A remediated page yields Resolved and the finding is auto-closed."""
    sid, detail = _full_scan(client, dev_token, target)
    finding = _sqli_finding(detail)
    # Simulate remediation: point the discovered page at the safe variant.
    with app.app_context():
        from app.extensions import db
        from app.models import DiscoveredPage
        page = db.session.get(DiscoveredPage, finding["PageID"])
        page.URL = page.URL.replace("/product", "/safe_search")
        db.session.commit()

    resp = _retest(client, dev_token, sid, finding["FindingID"])
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["Retest"]["Verdict"] == "Resolved"
    updated = body["Finding"]
    assert updated["Status"] == "Resolved"
    assert "verified absence" in updated["Evidence"]
    assert updated["LatestRetestVerdict"] == "Resolved"


def test_retest_unable_when_page_unreachable(client, dev_token, target, app):
    """A page that no longer responds is reported honestly, not guessed."""
    sid, detail = _full_scan(client, dev_token, target)
    finding = _sqli_finding(detail)
    with app.app_context():
        from app.extensions import db
        from app.models import DiscoveredPage
        page = db.session.get(DiscoveredPage, finding["PageID"])
        page.URL = page.URL.replace("/product", "/missing_page")
        db.session.commit()

    resp = _retest(client, dev_token, sid, finding["FindingID"])
    body = resp.get_json()
    assert body["Retest"]["Verdict"] == "Unable to Verify"
    assert "HTTP 404" in body["Retest"]["Message"]
    # status is unchanged (manual review recommended)
    assert body["Finding"]["Status"] == finding["Status"]
    assert "manual review" in body["Finding"]["Evidence"]


def test_retest_access_control(client, admin_token, dev_token, target):
    sid, detail = _full_scan(client, dev_token, target)
    finding = _sqli_finding(detail)
    fid = finding["FindingID"]
    # unauthenticated -> 401
    assert client.post(f"/api/scans/{sid}/findings/{fid}/retest").status_code == 401
    # unknown finding -> 400
    assert _retest(client, dev_token, sid, 999999).status_code == 400
    # unknown scan -> 404
    assert _retest(client, admin_token, 999999, fid).status_code == 404
    # another developer's scan -> 403
    client.post("/api/users", headers=auth(admin_token), json={
        "username": "retestoutsider", "email": "retestoutsider@vulnscan.local",
        "password": "Outsider@2025", "role": "Developer"})
    other_token = client.post("/api/auth/login", json={
        "email": "retestoutsider@vulnscan.local",
        "password": "Outsider@2025"}).get_json()["access_token"]
    assert _retest(client, other_token, sid, fid).status_code == 403
    # administrator may retest any scan
    assert _retest(client, admin_token, sid, fid).status_code == 200
