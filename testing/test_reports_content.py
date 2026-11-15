"""
Report content tests.

The PDF and CSV reports must be generated from the scan's real database
records (pages, findings, severities, remediation), not placeholder text.
"""
import csv
import io

from conftest import auth

try:  # PyMuPDF provides both module names depending on version
    import pymupdf as _pdf
except ImportError:  # pragma: no cover
    import fitz as _pdf


def _run_scan(client, token, target):
    profiles = client.get("/api/scan-profiles", headers=auth(token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]
    resp = client.post("/api/scans", headers=auth(token), json={
        "target_url": target, "scan_profile_id": pid, "scan_name": "Report content scan"})
    scan_id = resp.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}", headers=auth(token)).get_json()["Scan"]
    return scan_id, detail


def test_csv_contains_real_findings(client, dev_token, target):
    scan_id, detail = _run_scan(client, dev_token, target)
    resp = client.get(f"/api/scans/{scan_id}/report?format=csv", headers=auth(dev_token))
    text = resp.data.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))

    flat = "\n".join(",".join(r) for r in rows)
    assert "Report content scan" in flat
    assert detail["TargetURL"] in flat

    # The FINDINGS section must have exactly one row per finding.
    finding_header = next(i for i, r in enumerate(rows) if r and r[0] == "Finding ID")
    section_start = finding_header + 1
    section_end = next(
        (i for i, r in enumerate(rows[section_start:], start=section_start)
         if r and r[0] == "VERIFICATION (RETESTS)"),
        len(rows),
    )
    finding_rows = [r for r in rows[section_start:section_end]
                    if r and r[0].strip().isdigit()]
    assert len(finding_rows) == detail["FindingCount"] >= 1

    # Real finding content: a vulnerability name and its location appear.
    sample = detail["Findings"][0]
    assert any(sample["VulnerabilityName"] in r for r in rows if len(r) > 1)
    assert sample["URL"] in flat
    assert sample["Severity"] in flat

    # CVSS, classification, OWASP category and the enhancement columns.
    header = rows[finding_header]
    assert "CVSS Score" in header
    assert "Classification" in header
    assert "OWASP Category" in header
    assert "Technique" in header
    assert "CVSS Vector" in header
    assert "Latest Verdict" in header
    assert "Retest Count" in header
    assert sample["Classification"] in flat
    assert str(sample["RiskScore"]) in flat
    # the enhancement evidence fields are exported per finding
    assert sample["Technique"] in flat
    assert sample["CVSSVector"] in flat

    # Discovered pages are also reported.
    assert any(p["URL"] in flat for p in detail["Pages"])

    # A verification section exists (empty until a retest happens).
    assert section_end < len(rows), "VERIFICATION (RETESTS) section missing"


def test_reports_include_retest_results(client, dev_token, target):
    """After a retest, both reports carry the verification outcome (E1/D2)."""
    scan_id, detail = _run_scan(client, dev_token, target)
    sqli = next(f for f in detail["Findings"]
                if f["VulnerabilityName"] == "SQL Injection"
                and "/product" in f["URL"])
    retest = client.post(
        f"/api/scans/{scan_id}/findings/{sqli['FindingID']}/retest",
        headers=auth(dev_token), json={})
    assert retest.status_code == 200
    verdict = retest.get_json()["Retest"]["Verdict"]
    assert verdict == "Still Detected"

    # CSV: per-finding verdict column + a verification row
    resp = client.get(f"/api/scans/{scan_id}/report?format=csv", headers=auth(dev_token))
    rows = list(csv.reader(io.StringIO(resp.data.decode("utf-8-sig"))))
    vh = next(i for i, r in enumerate(rows) if r and r[0] == "VERIFICATION (RETESTS)")
    vrows = [r for r in rows[vh + 1:] if r and r[0].strip().isdigit()]
    assert len(vrows) == 1
    assert vrows[0][4] == "Still Detected"

    # PDF: verification + methodology sections and the verdict text
    resp = client.get(f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token))
    doc = _pdf.open(stream=resp.data, filetype="pdf")
    try:
        text = "\n".join(page.get_text() for page in doc)
    finally:
        doc.close()
    assert "Risk Overview" in text
    assert "Methodology and Coverage" in text
    assert "Verification (Retests)" in text
    assert "Still Detected" in text
    assert "CVSS Vector:" in text


def test_pdf_contains_real_scan_data(client, dev_token, target):
    scan_id, detail = _run_scan(client, dev_token, target)
    resp = client.get(f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token))
    assert resp.status_code == 200
    assert resp.data[:4] == b"%PDF"

    doc = _pdf.open(stream=resp.data, filetype="pdf")
    try:
        text = "\n".join(page.get_text() for page in doc)
    finally:
        doc.close()

    assert "VulnScan" in text
    assert "Report content scan" in text
    assert detail["TargetURL"] in text
    # Real detected content appears (short strings are wrap-safe).
    assert "SQL Injection" in text
    assert "Remediation:" in text
    assert "Evidence class:" in text
    assert f"#{scan_id}" in text


def test_unknown_report_format_rejected(client, dev_token, target):
    scan_id, _ = _run_scan(client, dev_token, target)
    resp = client.get(f"/api/scans/{scan_id}/report?format=xml", headers=auth(dev_token))
    assert resp.status_code == 400


# --------------------------------------------------------------------------
# Coverage and limitation accuracy (P0)
#
# The PDF and CSV must describe what this scan actually did - not a fixed
# paragraph that can contradict the coverage section next to it.
# --------------------------------------------------------------------------
def _pdf_text(response):
    doc = _pdf.open(stream=response.data, filetype="pdf")
    try:
        return "\n".join(page.get_text() for page in doc)
    finally:
        doc.close()


def _csv_rows(response):
    return list(csv.reader(io.StringIO(response.data.decode("utf-8-sig"))))


def _profile_with(client, token, name, vuln_names, **overrides):
    """Create a scan profile through the API, returning its id."""
    vulnerabilities = client.get(
        "/api/vulnerabilities", headers=auth(token)
    ).get_json()["Vulnerabilities"]
    ids = [v["VulnerabilityID"] for v in vulnerabilities
           if v["Name"] in vuln_names]
    assert len(ids) == len(vuln_names), (ids, vuln_names)
    payload = {"name": name, "module_vuln_ids": ids}
    payload.update(overrides)
    response = client.post("/api/scan-profiles", headers=auth(token),
                           json=payload)
    assert response.status_code == 201, response.get_json()
    return response.get_json()["ScanProfile"]["ScanProfileID"]


def _scan_with_profile(client, token, target, profile_id, name="Coverage scan",
                       url_suffix=""):
    response = client.post("/api/scans", headers=auth(token), json={
        "target_url": target + url_suffix, "scan_profile_id": profile_id,
        "scan_name": name})
    assert response.status_code == 202, response.get_json()
    scan_id = response.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}",
                        headers=auth(token)).get_json()["Scan"]
    return scan_id, detail


def test_pdf_does_not_claim_authenticated_coverage_for_anonymous_scan(
        client, dev_token, target):
    scan_id, detail = _run_scan(client, dev_token, target)
    assert detail["Coverage"]["Authentication"]["Mode"] == "Anonymous"

    text = _pdf_text(client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token)))

    assert "No temporary scan credential was used" in text
    assert "Authentication:" in text
    # The old blanket statement must be gone.
    assert "Authenticated or login-protected pages are not tested." not in text
    # An anonymous scan must never describe authenticated coverage.
    assert "reachable by the approved temporary test account" not in text


def test_pdf_limitations_are_accurate_and_not_contradictory(
        client, dev_token, target):
    scan_id, _ = _run_scan(client, dev_token, target)
    text = _pdf_text(client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token)))

    # The two contradictory/duplicated statements are gone.
    assert "PUT/PATCH/DELETE bodies, JSON/XML payloads, headers and cookies " \
           "are not tested." not in text
    assert "Query-string parameters and HTML form fields are fuzzed " \
           "(no headers, cookies or JSON bodies)." not in text

    # Replaced by precise statements that do not contradict each other.
    assert "PUT/PATCH/DELETE request bodies and JSON/XML payloads are not tested." in text
    assert "are not used as injection points" in text
    assert "JavaScript is not executed" in text
    # Headers were assessed as a policy, so the report must not claim otherwise.
    assert "Missing HTTP Security Headers" in text


def test_pdf_reports_enabled_and_executed_modules(
        client, dev_token, target):
    scan_id, detail = _run_scan(client, dev_token, target)
    coverage = detail["Coverage"]

    assert coverage["ModulesExecuted"], coverage
    assert coverage["ModulesNotExecuted"] == []
    text = _pdf_text(client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token)))
    assert "Detection modules enabled:" in text
    assert "Detection modules executed:" in text
    for name in coverage["ModulesExecuted"]:
        assert name in text


def test_disabled_module_is_not_presented_as_tested(
        client, admin_token, dev_token, target):
    profile_id = _profile_with(
        client, admin_token, "Headers only coverage profile",
        ["Missing HTTP Security Headers"],
    )
    scan_id, detail = _scan_with_profile(
        client, dev_token, target, profile_id, "Headers only scan")

    assert detail["Coverage"]["ModulesEnabled"] == [
        "Missing HTTP Security Headers"
    ]
    assert detail["Coverage"]["ModulesExecuted"] == [
        "Missing HTTP Security Headers"
    ]
    text = _pdf_text(client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token)))
    enabled_line = next(
        line for line in text.splitlines() if "Detection modules enabled:" in line
    )
    assert "SQL Injection" not in enabled_line
    assert "Cross-Site Scripting" not in enabled_line


def test_unimplemented_kb_entry_is_not_presented_as_tested(
        client, admin_token, dev_token, target):
    """A profile can reference KB entries that have no detection module."""
    profile_id = _profile_with(
        client, admin_token, "Unimplemented modules profile",
        ["Missing HTTP Security Headers", "Cross-Site Request Forgery (CSRF)"],
    )
    scan_id, detail = _scan_with_profile(
        client, dev_token, target, profile_id, "Unimplemented module scan")

    coverage = detail["Coverage"]
    assert coverage["ModulesNotImplemented"] == [
        "Cross-Site Request Forgery (CSRF)"
    ]
    assert "Cross-Site Request Forgery (CSRF)" not in coverage["ModulesExecuted"]

    text = _pdf_text(client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token)))
    assert "Enabled but not tested:" in text
    assert "Cross-Site Request Forgery (CSRF)" in text
    assert "no detection module is implemented" in text


def test_no_analysed_page_states_that_no_module_ran(
        client, admin_token, dev_token, target):
    scan_id, detail = _scan_with_profile(
        client, dev_token, target,
        _profile_with(client, admin_token, "Empty coverage profile",
                      ["Missing HTTP Security Headers"]),
        "No page scan", url_suffix="missing_page",
    )
    coverage = detail["Coverage"]
    assert coverage["AnalysedPages"] == 0
    assert coverage["ModulesExecuted"] == []
    assert coverage["NotExecutedReason"] == "no page could be analysed"

    note = detail["CoverageNote"]
    assert "0 of 1 discovered page(s) were analysed" in note
    assert "No detection module ran because no page could be analysed." in note
    # The reason must not be duplicated inside the sentence.
    assert "because no page could be analysed, so no detection module ran" not in note

    text = _pdf_text(client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token)))
    assert "No page could be analysed, so no vulnerability was confirmed" in text
    assert "Detection modules executed: none" in text
    # No form can have been submitted when no page was analysed.
    assert "GET and POST HTML forms are submitted" not in text
    assert "No HTML form was submitted" in text


def test_forms_disabled_limitation_says_forms_are_not_tested(
        app, client, dev_token, target):
    # The flag is a server capability; keep it off while the report is
    # generated so the statement reflects the configuration in force.
    app.config["SCANNER_ENABLE_FORM_TESTING"] = False
    try:
        scan_id, detail = _run_scan(client, dev_token, target)
        assert detail["Coverage"]["FormsTested"] is False
        text = _pdf_text(client.get(
            f"/api/scans/{scan_id}/report?format=pdf",
            headers=auth(dev_token)))
        assert "HTML form fields are not tested because form-field testing is " \
               "disabled" in text
        assert any(
            statement.startswith("HTML form fields are not tested")
            for statement in detail["Coverage"]["Limitations"]
        )
        assert "GET and POST HTML forms are submitted with read-only payloads" \
               not in text
    finally:
        app.config["SCANNER_ENABLE_FORM_TESTING"] = True


def test_csv_and_pdf_coverage_match_the_scan_record(
        client, dev_token, target):
    scan_id, detail = _run_scan(client, dev_token, target)
    coverage = detail["Coverage"]

    rows = _csv_rows(client.get(
        f"/api/scans/{scan_id}/report?format=csv", headers=auth(dev_token)))
    values = {row[0]: row[1] for row in rows if len(row) == 2}
    assert int(values["Analysed Pages"]) == coverage["AnalysedPages"]
    assert int(values["Discovered Pages"]) == coverage["DiscoveredPages"]
    assert values["Authentication Mode"] == coverage["Authentication"]["Mode"]
    assert values["Detection Modules Executed"] == ", ".join(
        coverage["ModulesExecuted"])

    text = _pdf_text(client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token)))
    flat = " ".join(text.split())
    assert (f"{coverage['AnalysedPages']} of "
            f"{coverage['DiscoveredPages']} discovered page(s) analysed") in flat

    limitations = [row[0] for row in rows if row and len(row) == 1
                   and len(row[0]) > 60]
    assert limitations, "CSV limitations section missing"
    for limitation in coverage["Limitations"]:
        assert limitation in limitations
