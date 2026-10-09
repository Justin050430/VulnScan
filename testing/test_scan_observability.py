"""
Observability tests (enhancement B1/B2).

Verifies the live progress endpoint and the coverage-transparency fields on
scan detail, including the skip path (pages that returned a non-success
status are stored but not analysed) and the access-control rules.
"""
from conftest import auth


def _full_scan(client, token, target_url, name="Observability scan"):
    profiles = client.get("/api/scan-profiles",
                          headers=auth(token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles
               if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]
    resp = client.post("/api/scans", headers=auth(token), json={
        "target_url": target_url, "scan_profile_id": pid, "scan_name": name})
    assert resp.status_code == 202
    sid = resp.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{sid}",
                        headers=auth(token)).get_json()["Scan"]
    return sid, detail


def test_progress_endpoint_reports_live_stage(client, dev_token, target):
    """After a completed scan the live snapshot reports real counters."""
    sid, _ = _full_scan(client, dev_token, target)
    resp = client.get(f"/api/scans/{sid}/progress", headers=auth(dev_token))
    assert resp.status_code == 200
    progress = resp.get_json()["Progress"]
    assert progress["ScanID"] == sid
    assert progress["Status"] == "Completed"
    assert progress["Stage"] == "completed"
    assert progress["LiveAvailable"] is True
    assert progress["PagesFound"] >= 5
    assert progress["PagesAnalysed"] == progress["PagesFound"]
    assert progress["FindingCount"] >= 1
    assert isinstance(progress["RequestsIssued"], int)
    assert progress["RequestsIssued"] > 0
    assert progress["Errors"] == []
    modules = {m["Name"] for m in progress["FindingsByModule"]}
    assert "SQL Injection" in modules
    assert progress["ElapsedSeconds"] is not None


def test_progress_endpoint_access_control(client, admin_token, dev_token,
                                          target):
    sid, _ = _full_scan(client, dev_token, target)
    # unauthenticated -> 401
    assert client.get(f"/api/scans/{sid}/progress").status_code == 401
    # unknown scan -> 404
    assert client.get("/api/scans/999999/progress",
                      headers=auth(admin_token)).status_code == 404
    # administrator may observe any scan
    assert client.get(f"/api/scans/{sid}/progress",
                      headers=auth(admin_token)).status_code == 200


def test_scan_detail_reports_coverage(client, dev_token, target):
    sid, detail = _full_scan(client, dev_token, target)
    assert detail["AnalysedPages"] >= 5
    assert detail["SkippedPages"] == []
    assert "q" in detail["TestedParameters"]
    assert "id" in detail["TestedParameters"]
    assert "Only GET query-string parameters are tested" in detail["CoverageNote"]
    assert "non-success HTTP status" in detail["CoverageNote"]


def test_skipped_pages_are_reported(client, dev_token, target):
    """A 404 start page is stored, skipped by modules and disclosed."""
    sid, detail = _full_scan(client, dev_token, target + "missing_page",
                             name="Skip path scan")
    assert detail["Status"] == "Completed"
    assert detail["AnalysedPages"] == 0
    assert len(detail["SkippedPages"]) == 1
    assert detail["SkippedPages"][0]["HTTPStatus"] == 404
    assert detail["FindingCount"] == 0
    assert "0 of 1 discovered page(s) were analysed" in detail["CoverageNote"]
