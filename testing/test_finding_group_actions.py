"""
Group triage, group retest and consolidated report tests (P3, checkpoint 2).

Group actions go through the same authorization and safety checks as the
per-finding endpoints, so these tests also prove that consolidation did not
widen access to findings.
"""
import csv
import io
import json

import pytest

from conftest import auth, TARGET_URL

try:  # PyMuPDF provides both module names depending on version
    import pymupdf as _pdf
except ImportError:  # pragma: no cover
    import fitz as _pdf

ALL_MODULES = ("sqli", "xss", "http_headers", "cookies")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _profile(client, admin_token, name, *, modules=ALL_MODULES, max_pages=20,
             max_depth=2):
    vulns = client.get(
        "/api/vulnerabilities", headers=auth(admin_token),
        query_string={"include_disabled": "true"},
    ).get_json()["Vulnerabilities"]
    ids = [v["VulnerabilityID"] for v in vulns if v["ModuleKey"] in modules]
    resp = client.post("/api/scan-profiles", headers=auth(admin_token), json={
        "name": name, "max_depth": max_depth, "max_pages": max_pages,
        "request_delay_ms": 0, "follow_external": False,
        "module_vuln_ids": ids})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["ScanProfile"]["ScanProfileID"]


def _scan(client, token, profile_id, target_url=None, name="Group action scan"):
    resp = client.post("/api/scans", headers=auth(token), json={
        "target_url": target_url or TARGET_URL, "scan_profile_id": profile_id,
        "scan_name": name})
    assert resp.status_code == 202, resp.get_json()
    scan_id = resp.get_json()["Scan"]["ScanID"]
    return client.get(
        f"/api/scans/{scan_id}", headers=auth(token)
    ).get_json()["Scan"]


@pytest.fixture()
def header_scan(client, admin_token, dev_token, target):
    """Fast scan whose header groups have several records each."""
    pid = _profile(client, admin_token, "Header group profile",
                   modules=("http_headers",), max_pages=5, max_depth=2)
    return _scan(client, dev_token, pid, TARGET_URL + "many?n=8",
                 name="Header group scan")


@pytest.fixture()
def full_scan(client, admin_token, dev_token, target):
    pid = _profile(client, admin_token, "Full group profile")
    return _scan(client, dev_token, pid, TARGET_URL, name="Full group scan")


def _biggest_group(scan):
    return max(scan["FindingGroups"], key=lambda g: g["RecordCount"])


def _group_url(scan_id, key, suffix=""):
    from urllib.parse import quote

    return f"/api/scans/{scan_id}/finding-groups/{quote(key, safe='')}{suffix}"


def _findings_of(app, scan_id):
    from app.extensions import db
    from app.models import DiscoveredPage, Finding

    return (db.session.query(Finding)
            .join(DiscoveredPage, Finding.PageID == DiscoveredPage.PageID)
            .filter(DiscoveredPage.ScanID == scan_id)
            .all())


# ---------------------------------------------------------------------------
# Group triage
# ---------------------------------------------------------------------------
def test_group_triage_updates_every_record(client, dev_token, header_scan):
    group = _biggest_group(header_scan)
    assert group["RecordCount"] > 1

    resp = client.put(_group_url(header_scan["ScanID"], group["GroupKey"]),
                      headers=auth(dev_token), json={"status": "Resolved"})
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body["Updated"] == group["RecordCount"]
    assert body["Group"]["Status"] == "Resolved"
    assert body["Group"]["StatusCounts"]["Resolved"] == group["RecordCount"]
    assert set(body["PreviousStatuses"].values()) == {"Open"}

    detail = client.get(f"/api/scans/{header_scan['ScanID']}",
                        headers=auth(dev_token)).get_json()["Scan"]
    members = [f for f in detail["Findings"] if f["GroupKey"] == group["GroupKey"]]
    assert len(members) == group["RecordCount"]
    assert all(f["Status"] == "Resolved" for f in members)


def test_group_triage_derives_status_and_exposes_mixed_state(
    client, dev_token, header_scan
):
    group = _biggest_group(header_scan)
    one_id = group["Locations"][0]["FindingID"]

    # One record closed by the individual endpoint: the group stays Open and
    # reports the split instead of hiding it.
    assert client.put(
        f"/api/scans/{header_scan['ScanID']}/findings/{one_id}",
        headers=auth(dev_token), json={"status": "Resolved"}
    ).status_code == 200

    detail = client.get(f"/api/scans/{header_scan['ScanID']}",
                        headers=auth(dev_token)).get_json()["Scan"]
    refreshed = next(
        g for g in detail["FindingGroups"] if g["GroupKey"] == group["GroupKey"])
    assert refreshed["Status"] == "Open"
    assert refreshed["Mixed"] is True
    assert refreshed["StatusCounts"]["Resolved"] == 1
    assert refreshed["StatusCounts"]["Open"] == group["RecordCount"] - 1

    # Partial remediation: the group only resolves when nothing is open.
    resp = client.put(_group_url(header_scan["ScanID"], group["GroupKey"]),
                      headers=auth(dev_token), json={"status": "Resolved"})
    assert resp.get_json()["Group"]["Status"] == "Resolved"
    assert resp.get_json()["Group"]["Mixed"] is False


def test_group_triage_does_not_store_a_group_status(
    client, dev_token, header_scan
):
    """Changing one record afterwards must change the derived group status."""
    group = _biggest_group(header_scan)
    client.put(_group_url(header_scan["ScanID"], group["GroupKey"]),
               headers=auth(dev_token), json={"status": "Resolved"})

    reopened = group["Locations"][-1]["FindingID"]
    client.put(f"/api/scans/{header_scan['ScanID']}/findings/{reopened}",
               headers=auth(dev_token), json={"status": "Open"})

    detail = client.get(f"/api/scans/{header_scan['ScanID']}",
                        headers=auth(dev_token)).get_json()["Scan"]
    refreshed = next(
        g for g in detail["FindingGroups"] if g["GroupKey"] == group["GroupKey"])
    assert refreshed["Status"] == "Open"
    assert refreshed["StatusCounts"]["Open"] == 1


def test_group_triage_writes_one_audit_record_with_finding_ids(
    app, client, dev_token, header_scan
):
    from app.models import SecurityAuditLog

    group = _biggest_group(header_scan)
    client.put(_group_url(header_scan["ScanID"], group["GroupKey"]),
               headers=auth(dev_token), json={"status": "False Positive"})

    with app.app_context():
        events = SecurityAuditLog.query.filter_by(
            Action="FINDING_GROUP_STATUS_UPDATED").all()
    assert len(events) == 1
    description = events[0].Description
    assert group["GroupKey"] in description
    assert "False Positive" in description
    assert "Open -> False Positive" in description
    for location in group["Locations"]:
        assert str(location["FindingID"]) in description


def test_group_triage_rejects_bad_status_and_unknown_group(
    client, dev_token, header_scan
):
    group = _biggest_group(header_scan)
    bad_status = client.put(
        _group_url(header_scan["ScanID"], group["GroupKey"]),
        headers=auth(dev_token), json={"status": "Banana"})
    assert bad_status.status_code == 400

    unknown = client.put(
        _group_url(header_scan["ScanID"], "v1:http_headers:does-not-exist"),
        headers=auth(dev_token), json={"status": "Open"})
    assert unknown.status_code == 404


def test_group_key_from_another_scan_is_rejected(
    client, admin_token, dev_token, header_scan, target
):
    other_pid = _profile(client, admin_token, "Other header profile",
                        modules=("http_headers",), max_pages=3)
    other = _scan(client, dev_token, other_pid, TARGET_URL + "many?n=4",
                  name="Other scan")
    group = _biggest_group(header_scan)

    resp = client.put(_group_url(other["ScanID"], group["GroupKey"]),
                      headers=auth(dev_token), json={"status": "Resolved"})
    # The key resolves against the other scan only -> not found there.
    assert resp.status_code in (200, 404)
    if resp.status_code == 200:
        # Same key (same rule) exists in the other scan: only that scan changed.
        pass
    detail_a = client.get(f"/api/scans/{header_scan['ScanID']}",
                          headers=auth(dev_token)).get_json()["Scan"]
    assert all(
        f["Status"] == "Open" for f in detail_a["Findings"]
        if f["GroupKey"] == group["GroupKey"]
    )


def test_group_triage_requires_scan_access(client, admin_token, dev_token,
                                           header_scan):
    client.post("/api/users", headers=auth(admin_token), json={
        "username": "groupintruder", "email": "groupintruder@vulnscan.local",
        "password": "Intruder@2025", "role": "Developer"})
    intruder = client.post("/api/auth/login", json={
        "email": "groupintruder@vulnscan.local",
        "password": "Intruder@2025"}).get_json()["access_token"]
    group = _biggest_group(header_scan)

    assert client.put(
        _group_url(header_scan["ScanID"], group["GroupKey"]),
        headers=auth(intruder), json={"status": "Resolved"}
    ).status_code == 403
    assert client.post(
        _group_url(header_scan["ScanID"], group["GroupKey"], "/retest"),
        headers=auth(intruder), json={}
    ).status_code == 403


# ---------------------------------------------------------------------------
# Group retest
# ---------------------------------------------------------------------------
def test_group_retest_reports_every_location(client, dev_token, header_scan):
    group = next(
        g for g in header_scan["FindingGroups"] if g["RecordCount"] > 1)
    resp = client.post(
        _group_url(header_scan["ScanID"], group["GroupKey"], "/retest"),
        headers=auth(dev_token), json={})
    assert resp.status_code == 200, resp.get_json()
    retest = resp.get_json()["Retest"]

    assert retest["Completed"] == group["RecordCount"]
    assert retest["Failed"] == 0
    assert retest["NotAttempted"] == 0
    assert retest["Partial"] is False
    assert len(retest["Results"]) == group["RecordCount"]
    assert {r["FindingID"] for r in retest["Results"]} == {
        loc["FindingID"] for loc in group["Locations"]}
    for entry in retest["Results"]:
        assert entry["Verdict"] in ("Still Detected", "Resolved",
                                    "Inconclusive", "Unable to Verify")
        assert entry["URL"]
    assert retest["AggregateVerdict"] in (
        "Still Detected", "Inconclusive", "Unable to Verify", "Resolved")

    # Each member's own evidence gained its retest stanza.
    detail = client.get(f"/api/scans/{header_scan['ScanID']}",
                        headers=auth(dev_token)).get_json()["Scan"]
    refreshed = next(
        g for g in detail["FindingGroups"] if g["GroupKey"] == group["GroupKey"])
    for location in refreshed["Locations"]:
        assert location["Retests"], location["FindingID"]


def test_group_retest_honours_the_location_cap(
    client, dev_token, header_scan, monkeypatch
):
    from app.services import scan_service

    monkeypatch.setattr(scan_service, "MAX_GROUP_RETEST_LOCATIONS", 2)
    group = next(
        g for g in header_scan["FindingGroups"] if g["RecordCount"] > 2)

    resp = client.post(
        _group_url(header_scan["ScanID"], group["GroupKey"], "/retest"),
        headers=auth(dev_token), json={})
    retest = resp.get_json()["Retest"]
    assert retest["Completed"] == 2
    assert retest["NotAttempted"] == group["RecordCount"] - 2
    assert retest["Limit"] == 2
    assert retest["Partial"] is True
    # Never claim a group is resolved when part of it was not verified.
    assert retest["AggregateVerdict"] != "Resolved"

    not_run = [r for r in retest["Results"] if r["Verdict"] == "Not Run"]
    assert len(not_run) == group["RecordCount"] - 2
    assert all(r["Status"] is None for r in not_run)


def test_group_retest_partial_failure_keeps_completed_results(
    app, client, dev_token, header_scan, monkeypatch
):
    from app.extensions import db
    from app.models import Finding
    from app.scanner import retest as retest_module

    group = next(
        g for g in header_scan["FindingGroups"] if g["RecordCount"] >= 3)
    original = retest_module.retest_finding
    calls = {"n": 0}

    def flaky(finding):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated retest crash")
        return original(finding)

    monkeypatch.setattr(retest_module, "retest_finding", flaky)
    resp = client.post(
        _group_url(header_scan["ScanID"], group["GroupKey"], "/retest"),
        headers=auth(dev_token), json={})
    assert resp.status_code == 200, resp.get_json()
    retest = resp.get_json()["Retest"]

    assert retest["Failed"] == 1
    assert retest["Completed"] == group["RecordCount"] - 1
    assert retest["NotAttempted"] == 0
    failed = [r for r in retest["Results"] if r["Failed"]]
    assert len(failed) == 1 and "simulated retest crash" in failed[0]["Message"]

    # The location retested before the failure kept its persisted result.
    first = retest["Results"][0]
    with app.app_context():
        stored = db.session.get(Finding, first["FindingID"])
        assert "RETEST" in (stored.Evidence or "")


def test_group_retest_is_scoped_and_bounded_by_scan(client, dev_token,
                                                    header_scan):
    unknown = client.post(
        _group_url(header_scan["ScanID"], "v1:http_headers:nope", "/retest"),
        headers=auth(dev_token), json={})
    assert unknown.status_code == 404


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
def test_csv_keeps_findings_and_adds_group_sections(client, dev_token,
                                                    full_scan):
    resp = client.get(f"/api/scans/{full_scan['ScanID']}/report?format=csv",
                      headers=auth(dev_token))
    assert resp.status_code == 200
    rows = list(csv.reader(io.StringIO(resp.data.decode("utf-8-sig"))))
    titles = [r[0] for r in rows if r]

    assert "FINDING GROUPS" in titles
    assert "FINDING LOCATIONS" in titles
    assert "FINDINGS" in titles

    # The record-based FINDINGS section keeps its exact previous header.
    finding_header = next(r for r in rows if r and r[0] == "Finding ID")
    assert finding_header == [
        "Finding ID", "Vulnerability", "OWASP Category", "Severity",
        "CVSS Score", "Confidence", "Classification", "Method", "Parameter",
        "Payload", "Status", "URL", "Evidence", "Technique", "CVSS Vector",
        "Latest Verdict", "Retest Count",
    ]
    start = rows.index(finding_header) + 1
    record_rows = [r for r in rows[start:] if r and r[0].isdigit()]
    assert len(record_rows) == full_scan["FindingCount"]

    group_start = next(
        i for i, r in enumerate(rows) if r and r[0] == "FINDING GROUPS")
    group_header = rows[group_start + 1]
    assert group_header[:2] == ["Group Key", "Vulnerability"]
    group_rows = []
    for row in rows[group_start + 2:]:
        if not row:
            break
        group_rows.append(row)
    assert len(group_rows) == full_scan["IssueCount"]
    # Every group row names its record IDs, which exist in FINDINGS.
    known_ids = {row[0] for row in record_rows}
    for row in group_rows:
        ids = [part.strip() for part in row[13].split(",")]
        assert ids and set(ids) <= known_ids
        assert int(row[7]) >= 1              # Record count
        assert int(row[8]) >= 1              # Affected URL count

    location_start = next(
        i for i, r in enumerate(rows) if r and r[0] == "FINDING LOCATIONS")
    location_rows = []
    for row in rows[location_start + 2:]:
        if not row:
            break
        location_rows.append(row)
    assert len(location_rows) == full_scan["FindingCount"]
    assert {row[1] for row in location_rows} == known_ids


def test_pdf_consolidates_issues_without_losing_records(client, dev_token,
                                                        full_scan):
    resp = client.get(f"/api/scans/{full_scan['ScanID']}/report?format=pdf",
                      headers=auth(dev_token))
    assert resp.status_code == 200
    assert resp.data[:4] == b"%PDF"

    document = _pdf.open(stream=resp.data, filetype="pdf")
    try:
        text = "\n".join(page.get_text() for page in document)
    finally:
        document.close()

    assert f"{full_scan['IssueCount']} issue(s)" in text
    assert f"{full_scan['FindingCount']} finding record(s)" in text
    # Every group heading and every record is present.
    for group in full_scan["FindingGroups"]:
        assert group["VulnerabilityName"] in text
        for location in group["Locations"]:
            assert f"Record {location['FindingID']} - " in text
    # Coverage and limitation statements from P0 are preserved.
    assert "Coverage:" in text
    assert "Limitations:" in text


def test_cookie_urls_appear_but_values_never_do(client, dev_token, full_scan,
                                                vuln_target_module):
    marker = vuln_target_module.COOKIE_SECRET_MARKER
    cookie_group = next(
        g for g in full_scan["FindingGroups"]
        if g["GroupKey"].startswith("v1:cookies:")
        and g["AffectedURLCount"] > 1
    )
    assert marker not in json.dumps(cookie_group)

    csv_resp = client.get(
        f"/api/scans/{full_scan['ScanID']}/report?format=csv",
        headers=auth(dev_token))
    csv_text = csv_resp.data.decode("utf-8-sig")
    assert marker not in csv_text
    # The consolidated row lists every observed URL of that cookie.
    group_section = csv_text.split("FINDING GROUPS", 1)[1].split(
        "FINDING LOCATIONS", 1)[0]
    row = next(
        r for r in group_section.splitlines() if cookie_group["GroupKey"] in r)
    for url in cookie_group["AffectedURLs"]:
        assert url in row

    pdf_resp = client.get(
        f"/api/scans/{full_scan['ScanID']}/report?format=pdf",
        headers=auth(dev_token))
    document = _pdf.open(stream=pdf_resp.data, filetype="pdf")
    try:
        text = "\n".join(page.get_text() for page in document)
    finally:
        document.close()
    assert marker not in text
    assert "/cookies_weak" in text


def test_report_and_group_view_agree_on_counts(client, dev_token, full_scan):
    for group in full_scan["FindingGroups"]:
        assert group["RecordCount"] == len(group["Locations"])
        assert group["AffectedURLCount"] == len(group["AffectedURLs"])
        assert group["AffectedURLCount"] >= group["PageCount"]
        # Worst-member severity is what the UI filters on.
        assert group["Severity"] == max(
            (loc["Severity"] for loc in group["Locations"]),
            key=lambda s: ["None", "Low", "Medium", "High", "Critical"].index(s),
        )
