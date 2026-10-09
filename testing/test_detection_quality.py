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
        # Per-rule severity (A5): CSP 5.4 / framing 4.3 / MIME 4.3 /
        # HSTS 4.2 / privacy rules 3.1.
        assert f["RiskScore"] in (5.4, 4.3, 4.2, 3.1)
        assert f["Parameter"] in (
            "Content-Security-Policy", "X-Frame-Options",
            "X-Content-Type-Options", "Referrer-Policy",
            "Strict-Transport-Security", "Permissions-Policy",
        )
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
    """Headers present with insecure values are reported per rule (A5)."""
    detail = _scan_target(client, dev_token, target + "weak_headers")
    headers = [f for f in detail["Findings"]
               if f["VulnerabilityName"] == "Missing HTTP Security Headers"]
    by_param = {f["Parameter"]: f for f in headers}
    assert set(by_param) == {
        "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
    }, sorted(by_param)
    assert by_param["X-Frame-Options"]["Payload"] == "ALLOWALL"
    assert by_param["X-Content-Type-Options"]["Payload"] == "sniff"
    assert by_param["Referrer-Policy"]["Payload"] == "unsafe-url"
    assert by_param["X-Frame-Options"]["RiskScore"] == 4.3
    assert by_param["Referrer-Policy"]["RiskScore"] == 3.1
    for f in headers:
        assert f["Classification"] == "Confirmed"
        assert "CURRENT VALUE:" in f["Evidence"]


def test_weak_csp_directives_are_reported(client, dev_token, target):
    """A CSP that permits inline scripts / wildcards is weak, not 'present'."""
    detail = _scan_target(client, dev_token, target + "csp_weak")
    headers = [f for f in detail["Findings"]
               if f["VulnerabilityName"] == "Missing HTTP Security Headers"]
    assert len(headers) == 1, [f["Parameter"] for f in headers]
    finding = headers[0]
    assert finding["Parameter"] == "Content-Security-Policy"
    assert "unsafe-inline" in finding["Payload"]
    assert "unsafe-inline" in finding["Evidence"]
    assert finding["RiskScore"] == 5.4
    assert finding["Classification"] == "Confirmed"


def test_xfo_mitigated_by_frame_ancestors(client, dev_token, target):
    """CSP frame-ancestors replaces X-Frame-Options (no finding expected)."""
    detail = _scan_target(client, dev_token, target + "frame_ok")
    headers = [f for f in detail["Findings"]
               if f["VulnerabilityName"] == "Missing HTTP Security Headers"]
    assert not headers, [f["Parameter"] for f in headers]


def test_header_findings_carry_technique_and_vector(full_scan):
    headers = [f for f in full_scan["Findings"]
               if f["VulnerabilityName"] == "Missing HTTP Security Headers"]
    assert headers
    for f in headers:
        assert f["Technique"] == "HTTP security header policy evaluation"
        assert f["CVSSVector"].startswith("CVSS:3.1/")


def test_no_xss_false_positive_in_non_executable_contexts(client, dev_token, target):
    """Un-encoded reflection inside a comment/textarea is not executable XSS."""
    for path in ("comment_reflect?q=x", "textarea_reflect?q=x"):
        detail = _scan_target(client, dev_token, target + path, "Quick Scan")
        xss = [f for f in detail["Findings"]
               if f["VulnerabilityName"] == "Cross-Site Scripting (XSS)"]
        assert not xss, f"false-positive XSS reported for {path}"


# --------------------------------------------------------------------------
# A1 (enhancement): structured SQLi evidence, reproducibility and CVSS vector
# --------------------------------------------------------------------------
def test_error_based_evidence_contains_reproducibility_and_vector(full_scan):
    """Confirmed error-based findings carry structured evidence and the vector."""
    sqli = [f for f in full_scan["Findings"]
            if f["VulnerabilityName"] == "SQL Injection" and "/product" in f["URL"]]
    assert sqli, "error-based SQLi should be detected on /product"
    finding = sqli[0]
    evidence = finding["Evidence"]
    assert "REPRODUCIBILITY: signature reproduced on 2/2 identical requests" in evidence
    assert "BASELINE REQUEST:" in evidence
    assert "REMEDIATION:" in evidence
    assert "REFERENCES:" in evidence
    assert "VERIFICATION: Not retested yet." in evidence
    assert finding["CVSSVector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert finding["Technique"] and "error-based" in finding["Technique"]


def test_unreproduced_error_signature_is_suspected(client, dev_token, target):
    """A one-shot (non-reproducible) error page must be SUSPECTED, not Confirmed."""
    profiles = client.get("/api/scan-profiles",
                          headers=auth(dev_token)).get_json()["ScanProfiles"]
    pid = next(p for p in profiles
               if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target + "flaky_error?id=1",
        "scan_profile_id": pid, "scan_name": "Flaky error control"})
    assert resp.status_code == 202
    sid = resp.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{sid}",
                        headers=auth(dev_token)).get_json()["Scan"]
    sqli = [f for f in detail["Findings"]
            if f["VulnerabilityName"] == "SQL Injection"]
    assert sqli, "the one-shot error page should produce an SQLi observation"
    finding = sqli[0]
    assert finding["Classification"] == "Suspected"
    assert finding["Confidence"] < 0.8
    assert "did NOT reproduce" in finding["Evidence"]
    assert finding["CVSSVector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


# --------------------------------------------------------------------------
# A2 (enhancement): conditional-error SQLi probe
# --------------------------------------------------------------------------
def test_conditional_error_sqli_is_confirmed(client, dev_token, target):
    """An error that occurs only for the true condition proves SQL evaluation."""
    detail = _scan_target(client, dev_token, target + "error_cond?id=1",
                          "OWASP Top 10 Full Scan")
    sqli = [f for f in detail["Findings"]
            if f["VulnerabilityName"] == "SQL Injection"]
    assert sqli, "conditional-error SQLi should be detected"
    finding = sqli[0]
    assert finding["Classification"] == "Confirmed"
    assert finding["Confidence"] >= 0.8
    assert "conditional error" in (finding["Technique"] or "")
    assert "TRUE CONDITION:" in finding["Evidence"]
    assert "FALSE CONDITION:" in finding["Evidence"]
    assert "reproduced on 2/2 identical requests" in finding["Evidence"]


# --------------------------------------------------------------------------
# A4 (enhancement): XSS context-aware reflection analysis
# --------------------------------------------------------------------------
def _xss_findings(detail):
    return [f for f in detail["Findings"]
            if f["VulnerabilityName"] == "Cross-Site Scripting (XSS)"]


def test_attribute_breakout_xss_is_confirmed(client, dev_token, target):
    """A breakout from a quoted attribute value into markup is executable."""
    detail = _scan_target(client, dev_token, target + "attr_reflect?q=x",
                          "Quick Scan")
    xss = _xss_findings(detail)
    assert xss, "attribute breakout XSS should be detected"
    finding = xss[0]
    assert finding["Classification"] == "Confirmed"
    assert "attribute" in finding["Evidence"]
    assert "breaks out" in finding["Evidence"]
    assert "REFLECTION CONTEXT:" in finding["Evidence"]


def test_event_attribute_injection_is_confirmed(client, dev_token, target):
    """Angle brackets encoded, quotes raw: event-handler injection still works."""
    detail = _scan_target(client, dev_token, target + "attr_events?q=x",
                          "Quick Scan")
    xss = _xss_findings(detail)
    assert xss, "event-handler attribute injection should be detected"
    finding = xss[0]
    assert finding["Classification"] == "Confirmed"
    assert "event-handler" in finding["Evidence"]


def test_script_context_breakout_is_confirmed(client, dev_token, target):
    """A payload that closes the <script> element and opens markup executes."""
    detail = _scan_target(client, dev_token, target + "script_reflect?q=x",
                          "Quick Scan")
    xss = _xss_findings(detail)
    assert xss, "script-context breakout should be detected"
    finding = xss[0]
    assert finding["Classification"] == "Confirmed"
    assert "script" in finding["Evidence"]


def test_encoded_attribute_value_is_not_flagged(client, dev_token, target):
    """Encoding both quotes and brackets keeps attribute reflections inert."""
    detail = _scan_target(client, dev_token, target + "attr_safe?q=x",
                          "Quick Scan")
    assert not _xss_findings(detail), \
        "safely encoded attribute reflection must not be reported"
