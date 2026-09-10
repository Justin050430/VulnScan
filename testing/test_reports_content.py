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
    finding_rows = [r for r in rows[finding_header + 1:] if r and r[0].strip().isdigit()]
    assert len(finding_rows) == detail["FindingCount"] >= 1

    # Real finding content: a vulnerability name and its location appear.
    sample = detail["Findings"][0]
    assert any(sample["VulnerabilityName"] in r for r in rows if len(r) > 1)
    assert sample["URL"] in flat
    assert sample["Severity"] in flat

    # CVSS, classification and OWASP category are reported.
    header = rows[finding_header]
    assert "CVSS Score" in header
    assert "Classification" in header
    assert "OWASP Category" in header
    assert sample["Classification"] in flat
    assert str(sample["RiskScore"]) in flat

    # Discovered pages are also reported.
    assert any(p["URL"] in flat for p in detail["Pages"])


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
