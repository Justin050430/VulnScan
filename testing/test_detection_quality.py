"""
Detection quality tests.

Verifies that:
  * RiskScore/Severity come from a spec-correct CVSS v3.1 base score,
  * findings are classified as Confirmed vs Suspected based on real evidence,
  * deliberately safe control pages do NOT produce findings (false-positive
    control), and vulnerable pages DO.
"""
import pytest

from conftest import auth
from app.scanner.cvss import CvssError, base_score, severity_for_score


# --------------------------------------------------------------------------
# CVSS v3.1 calculator
# --------------------------------------------------------------------------
@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # SQLi error-based
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),   # blind SQLi suspected
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),   # reference value
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),   # low reference
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),   # no impact
])
def test_cvss_base_scores(vector, expected):
    assert base_score(vector) == expected


def test_cvss_severity_bands_match_table_2_2():
    assert severity_for_score(0.0) == "None"
    assert severity_for_score(3.9) == "Low"
    assert severity_for_score(4.0) == "Medium"
    assert severity_for_score(6.9) == "Medium"
    assert severity_for_score(7.0) == "High"
    assert severity_for_score(8.9) == "High"
    assert severity_for_score(9.0) == "Critical"
    assert severity_for_score(10.0) == "Critical"


def test_cvss_rejects_invalid_vectors():
    with pytest.raises(CvssError):
        base_score("not-a-vector")
    with pytest.raises(CvssError):
        base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


# --------------------------------------------------------------------------
# Evidence classification and false-positive control
# --------------------------------------------------------------------------
@pytest.fixture()
def full_scan(client, dev_token, target):
    profiles = client.get("/api/scan-profiles", headers=auth(dev_token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target, "scan_profile_id": pid, "scan_name": "Detection quality"})
    scan_id = resp.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}", headers=auth(dev_token)).get_json()["Scan"]
    return detail


def _by_url(findings, fragment):
    return [f for f in findings if fragment in (f["URL"] or "")]


def test_error_based_sqli_is_confirmed_critical(full_scan):
    sqli = [f for f in full_scan["Findings"]
            if f["VulnerabilityName"] == "SQL Injection" and "/product" in f["URL"]]
    assert sqli, "error-based SQLi should be detected on /product"
    for f in sqli:
        assert f["Severity"] == "Critical"
        assert f["RiskScore"] == 9.8
        assert f["Classification"] == "Confirmed"
        assert f["Confidence"] >= 0.9
        assert "CONFIRMED" in f["Evidence"]
        assert f["Parameter"] == "id"
        assert f["Payload"]


def test_boolean_sqli_is_suspected_not_confirmed(full_scan):
    sqli = [f for f in full_scan["Findings"]
            if f["VulnerabilityName"] == "SQL Injection" and "/blind" in f["URL"]]
    # The blind differential technique should produce a suspected finding.
    assert sqli, "blind boolean SQLi should be detected on /blind"
    for f in sqli:
        assert f["Classification"] == "Suspected"
        assert f["Confidence"] < 0.8
        assert f["Severity"] == "Medium"      # CVSS 5.9 (AC:H)
        assert f["RiskScore"] == 5.9
        assert "SUSPECTED" in f["Evidence"]


def test_no_sqli_false_positive_on_safe_pages(full_scan):
    for fragment in ("/safe_search", "/boolean_safe", "/headers_ok"):
        flagged = [f for f in _by_url(full_scan["Findings"], fragment)
                   if f["VulnerabilityName"] == "SQL Injection"]
        assert not flagged, f"false-positive SQLi on {fragment}"


def test_reflected_xss_confirmed_and_control_pages_clean(full_scan):
    xss = [f for f in full_scan["Findings"]
           if f["VulnerabilityName"] == "Cross-Site Scripting (XSS)"]
    assert any("/search" in f["URL"] for f in xss), "reflected XSS should be found on /search"
    for f in xss:
        assert f["Classification"] == "Confirmed"
        assert f["RiskScore"] == 6.1
        assert f["Severity"] == "Medium"
    # safe pages must not be flagged (escaped output)
    assert not _by_url(xss, "/safe_search")
    assert not _by_url(xss, "/boolean_safe")


def test_header_detection_confirmed_with_control_page(full_scan):
    headers = [f for f in full_scan["Findings"]
               if f["VulnerabilityName"] == "Missing HTTP Security Headers"]
    assert headers, "missing-header findings expected on unprotected pages"
    for f in headers:
        assert f["Classification"] == "Confirmed"
        assert f["RiskScore"] == 5.4
    # the header-safe page must not be flagged
    assert not _by_url(headers, "/headers_ok")


def test_findings_have_remediation_guidance(full_scan):
    """Findings surface the knowledge-base remediation content."""
    for f in full_scan["Findings"]:
        assert f.get("Description")
        assert f.get("Recommendation")
        assert f.get("OWASPCategory")


def _scan_target(client, token, url, profile_name="Basic Security Headers"):
    profiles = client.get("/api/scan-profiles", headers=auth(token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles if p["Name"] == profile_name)["ScanProfileID"]
    resp = client.post("/api/scans", headers=auth(token), json={
        "target_url": url, "scan_profile_id": pid, "scan_name": "Quality check"})
    sid = resp.get_json()["Scan"]["ScanID"]
    return client.get(f"/api/scans/{sid}", headers=auth(token)).get_json()["Scan"]


def test_weak_header_values_are_reported(client, dev_token, target):
    """Headers present but with insecure values must be reported."""
    detail = _scan_target(client, dev_token, target + "weak_headers")
    headers = [f for f in detail["Findings"]
               if f["VulnerabilityName"] == "Missing HTTP Security Headers"]
    assert headers, "insecure header values were not reported"
    evidence = headers[0]["Evidence"]
    assert "Improperly configured" in evidence
    for name in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
        assert name in evidence
    assert headers[0]["RiskScore"] == 5.4
    assert headers[0]["Classification"] == "Confirmed"


def test_no_xss_false_positive_in_non_executable_contexts(client, dev_token, target):
    """Un-encoded reflection inside a comment/textarea is not executable XSS."""
    for path in ("comment_reflect?q=x", "textarea_reflect?q=x"):
        detail = _scan_target(client, dev_token, target + path, "Quick Scan")
        xss = [f for f in detail["Findings"]
               if f["VulnerabilityName"] == "Cross-Site Scripting (XSS)"]
        assert not xss, f"false-positive XSS reported for {path}"
