"""
Cookie attribute module tests (P1).

The module inspects the `Set-Cookie` headers a page returns.  These tests cover
header parsing (including the `Expires` comma trap), the five detection rules,
severity by cookie purpose, cross-page de-duplication and - most importantly -
that the cookie value never reaches a finding, an export or the logs.
"""
import csv
import io

import pytest

from app.extensions import db
from app.models import ProfileModule, ScanProfile, Vulnerability
from app.scanner.cookie_header import parse_set_cookie, parse_set_cookies
from app.scanner.modules.cookies import cookie_purpose
from app.seeds import run_seed
from conftest import auth

try:  # PyMuPDF provides both module names depending on version
    import pymupdf as _pdf
except ImportError:  # pragma: no cover
    import fitz as _pdf

COOKIE_VULN = "Insecure Cookie Attributes"


# --------------------------------------------------------------------------
# Header parsing
# --------------------------------------------------------------------------
def test_parser_keeps_expires_comma_out_of_the_attribute_list():
    """
    `Expires` contains a comma.  Splitting a combined header on commas would
    break the attribute list, so parsing must only split on semicolons.
    """
    parsed = parse_set_cookie(
        "session=abc123; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; "
        "HttpOnly; SameSite=Lax"
    )
    assert parsed.name == "session"
    assert parsed.value_of("expires") == "Wed, 21 Oct 2026 07:28:00 GMT"
    assert parsed.value_of("path") == "/"
    assert parsed.has("httponly")
    assert parsed.value_of("samesite") == "Lax"
    assert parsed.value_of("domain") is None


def test_parser_never_retains_the_cookie_value():
    parsed = parse_set_cookie("session=super-secret-value; Path=/; HttpOnly")
    assert parsed.name == "session"
    # Nothing on the parsed object can leak the value.
    assert "super-secret-value" not in repr(parsed)
    assert all("super-secret-value" not in str(part) for part in parsed.attributes)


def test_parser_handles_multiple_headers_independently():
    headers = [
        "a=1; Path=/; HttpOnly",
        "b=2; Path=/; Expires=Thu, 01 Jan 2026 00:00:00 GMT",
        "c=3; SameSite=None; Secure",
    ]
    cookies = parse_set_cookies(headers)
    assert [c.name for c in cookies] == ["a", "b", "c"]
    assert cookies[0].has("httponly")
    assert cookies[1].value_of("expires") == "Thu, 01 Jan 2026 00:00:00 GMT"
    assert cookies[2].value_of("samesite") == "None"


def test_parser_skips_malformed_headers():
    assert parse_set_cookie(None) is None
    assert parse_set_cookie("") is None
    assert parse_set_cookie("no-equals-sign") is None
    assert parse_set_cookie("; Path=/") is None
    assert [c.name for c in parse_set_cookies(
        ["", "bad", "ok=1; HttpOnly"])] == ["ok"]


@pytest.mark.parametrize("name,expected", [
    ("session", "session"),
    ("SESSIONID", "session"),
    ("JSESSIONID", "session"),
    ("PHPSESSID", "session"),
    ("auth_token", "session"),
    ("csrf_token", "session"),
    ("remember_me", "session"),
    ("_session_id", "session"),
    ("pref", "ordinary"),
    ("theme", "ordinary"),
    ("locale", "ordinary"),
    ("__Host-good", "ordinary"),
])
def test_cookie_purpose_classification(name, expected):
    assert cookie_purpose(name) == expected


# --------------------------------------------------------------------------
# Scanning helpers
# --------------------------------------------------------------------------
def _scan(client, token, url, profile_name="OWASP Top 10 Full Scan",
          name="Cookie module scan"):
    profiles = client.get(
        "/api/scan-profiles", headers=auth(token)
    ).get_json()["ScanProfiles"]
    profile_id = next(
        p["ScanProfileID"] for p in profiles if p["Name"] == profile_name
    )
    response = client.post("/api/scans", headers=auth(token), json={
        "target_url": url, "scan_profile_id": profile_id, "scan_name": name})
    assert response.status_code == 202, response.get_json()
    scan_id = response.get_json()["Scan"]["ScanID"]
    detail = client.get(
        f"/api/scans/{scan_id}", headers=auth(token)
    ).get_json()["Scan"]
    return scan_id, detail


def _cookie_findings(detail):
    return [
        f for f in detail["Findings"]
        if f["VulnerabilityName"] == COOKIE_VULN
    ]


def _rules(finding):
    """Which rule a finding represents, read back from its evidence."""
    evidence = finding["Evidence"]
    if "SameSite=None is set without the Secure" in evidence:
        return "samesite_none"
    if "prefix contract is violated" in evidence:
        return "prefix"
    if "the SameSite attribute is missing" in evidence:
        return "samesite"
    if "the HttpOnly attribute is missing" in evidence:
        return "httponly"
    if "the Secure attribute is missing on an HTTPS" in evidence:
        return "secure"
    raise AssertionError(f"unknown rule in evidence: {evidence[:200]}")


def _by_cookie(detail):
    grouped = {}
    for finding in _cookie_findings(detail):
        grouped.setdefault(finding["Parameter"], {})[_rules(finding)] = finding
    return grouped


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
def test_weak_cookies_produce_the_expected_findings(client, dev_token, target):
    scan_id, detail = _scan(client, dev_token, target + "cookies_weak")
    assert detail["Status"] == "Completed"

    grouped = _by_cookie(detail)
    assert set(grouped) == {"session", "pref", "__Host-insecure", "tracking"}

    # Session cookie: HttpOnly (Medium) and SameSite (Low). No Secure rule,
    # because the controlled target is served over plain HTTP.
    assert set(grouped["session"]) == {"httponly", "samesite"}
    assert grouped["session"]["httponly"]["Severity"] == "Medium"
    assert grouped["session"]["httponly"]["RiskScore"] == 4.2
    assert grouped["session"]["samesite"]["Severity"] == "Low"

    # Ordinary cookie: HttpOnly is Low hardening, not a Medium vulnerability.
    assert set(grouped["pref"]) == {"httponly", "samesite"}
    assert grouped["pref"]["httponly"]["Severity"] == "Low"
    assert grouped["pref"]["httponly"]["RiskScore"] == 3.1

    # Prefix contract and SameSite=None.
    assert set(grouped["__Host-insecure"]) == {"prefix"}
    assert set(grouped["tracking"]) == {"samesite_none", "httponly"}
    assert grouped["tracking"]["samesite_none"]["Severity"] == "Medium"

    for finding in _cookie_findings(detail):
        assert finding["Classification"] == "Confirmed"
        assert finding["Technique"] == "Set-Cookie attribute policy evaluation"
        assert finding["CVSSVector"].startswith("CVSS:3.1/")
        assert finding["RequestMethod"] == "GET"
        assert finding["Status"] == "Open"

    # No HTTPS-only finding can appear on an HTTP target.
    assert all(
        "HTTPS response" not in f["Evidence"] for f in _cookie_findings(detail)
    )


def test_correctly_configured_cookies_produce_no_findings(
        client, dev_token, target):
    scan_id, detail = _scan(client, dev_token, target + "cookies_ok",
                            name="Cookie safe scan")
    assert detail["Status"] == "Completed"
    assert [p["URL"] for p in detail["Pages"] if "/cookies_ok" in p["URL"]]
    assert _cookie_findings(detail) == []


def test_multiple_set_cookie_headers_are_parsed_independently(
        client, dev_token, target):
    """Four Set-Cookie headers must yield four distinct cookies."""
    scan_id, detail = _scan(client, dev_token, target + "cookies_weak",
                            name="Cookie multi-header scan")
    grouped = _by_cookie(detail)
    assert len(grouped) == 4
    # Evidence records the attributes each cookie actually carried.
    pref = grouped["pref"]["httponly"]
    assert "ATTRIBUTES PRESENT: Path=/" in pref["Evidence"]
    host = grouped["__Host-insecure"]["prefix"]
    assert "Path=/account" in host["Evidence"]
    assert "HttpOnly" in host["Evidence"]
    assert "SameSite=Lax" in host["Evidence"]


def test_duplicate_cookie_across_pages_is_reported_once(
        client, dev_token, target):
    """
    /cookies_weak and /cookies_weak_more both set the same session cookie;
    the scan must report its two rules exactly once.
    """
    scan_id, detail = _scan(client, dev_token, target + "cookies_weak",
                            name="Cookie dedupe scan")
    pages = [p["URL"] for p in detail["Pages"]]
    assert any("/cookies_weak_more" in url for url in pages)

    session_findings = [
        f for f in _cookie_findings(detail) if f["Parameter"] == "session"
    ]
    assert len(session_findings) == 2, [f["Evidence"][:80] for f in session_findings]
    assert all("SCOPE: reported once per scan" in f["Evidence"]
               for f in session_findings)


def test_missing_summary_omits_secure_on_plain_http(
        client, dev_token, target):
    """`Secure` is not listed as missing on an HTTP page (it is not reported)."""
    scan_id, detail = _scan(client, dev_token, target + "cookies_weak",
                            name="Cookie http summary scan")
    session_httponly = next(
        f for f in _cookie_findings(detail)
        if f["Parameter"] == "session" and _rules(f) == "httponly"
    )
    assert "ATTRIBUTES MISSING: HttpOnly, SameSite" in session_httponly["Evidence"]
    assert "ATTRIBUTES MISSING: Secure" not in session_httponly["Evidence"]


def test_cookie_evidence_detail_starts_a_sentence_correctly(
        client, dev_token, target):
    scan_id, detail = _scan(client, dev_token, target + "cookies_weak",
                            name="Cookie detail scan")
    finding = next(f for f in _cookie_findings(detail)
                   if f["Parameter"] == "session")
    assert ". client-side" not in finding["Evidence"]


def test_cookie_finding_can_be_retested(client, dev_token, target):
    """Cookie findings keep their normal triage/retest lifecycle."""
    scan_id, detail = _scan(client, dev_token, target + "cookies_weak",
                            name="Cookie retest scan")
    finding = next(f for f in _cookie_findings(detail)
                   if f["Parameter"] == "session")
    response = client.post(
        f"/api/scans/{scan_id}/findings/{finding['FindingID']}/retest",
        headers=auth(dev_token), json={},
    )
    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body["Retest"]["Verdict"] in ("Still Detected", "Resolved")
    assert "RETEST" in body["Finding"]["Evidence"]
    assert body["Finding"]["Status"] in ("Open", "Resolved")
    # The retest stanza must not reintroduce the cookie value either.
    assert "vulnscan_cookie_secret" not in body["Finding"]["Evidence"]


def test_existing_modules_still_detect_their_own_findings(
        client, dev_token, target):
    """The cookie module must not disturb SQLi/XSS/header detection."""
    scan_id, detail = _scan(client, dev_token, target, name="Cookie regression scan")
    names = {f["VulnerabilityName"] for f in detail["Findings"]}
    assert {"SQL Injection", "Cross-Site Scripting (XSS)",
            "Missing HTTP Security Headers", COOKIE_VULN} <= names
    coverage = detail["Coverage"]
    assert COOKIE_VULN in coverage["ModulesExecuted"]


# --------------------------------------------------------------------------
# Secret hygiene
# --------------------------------------------------------------------------
def test_cookie_values_never_reach_findings_evidence_or_exports(
        client, dev_token, target, vuln_target_module):
    marker = vuln_target_module.COOKIE_SECRET_MARKER
    scan_id, detail = _scan(client, dev_token, target + "cookies_weak",
                            name="Cookie secret scan")
    assert _cookie_findings(detail)

    findings_json = str(detail["Findings"])
    assert marker not in findings_json
    for finding in _cookie_findings(detail):
        assert marker not in (finding["Evidence"] or "")
        assert marker not in (finding["Payload"] or "")

    csv_body = client.get(
        f"/api/scans/{scan_id}/report?format=csv", headers=auth(dev_token)
    ).data.decode("utf-8-sig")
    assert marker not in csv_body
    assert COOKIE_VULN in csv_body

    pdf = client.get(
        f"/api/scans/{scan_id}/report?format=pdf", headers=auth(dev_token)
    )
    doc = _pdf.open(stream=pdf.data, filetype="pdf")
    try:
        text = "\n".join(page.get_text() for page in doc)
    finally:
        doc.close()
    assert marker not in text
    assert COOKIE_VULN in text


def test_cookie_value_not_written_to_application_logs(
        client, dev_token, target, vuln_target_module):
    """Detection must not log the cookie value either."""
    import logging

    marker = vuln_target_module.COOKIE_SECRET_MARKER
    captured = []

    class _Capture(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    handler = _Capture()
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        _scan(client, dev_token, target + "cookies_weak",
              name="Cookie log scan")
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    assert captured, "expected some log output during a scan"
    assert all(marker not in message for message in captured)


# --------------------------------------------------------------------------
# Knowledge base and default-profile reconciliation
# --------------------------------------------------------------------------
def test_cookie_kb_entry_is_separate_from_security_headers(client, dev_token):
    vulnerabilities = client.get(
        "/api/vulnerabilities", headers=auth(dev_token)
    ).get_json()["Vulnerabilities"]
    by_name = {v["Name"]: v for v in vulnerabilities}
    assert COOKIE_VULN in by_name
    cookie_entry = by_name[COOKIE_VULN]
    assert cookie_entry["VulnerabilityID"] != by_name[
        "Missing HTTP Security Headers"]["VulnerabilityID"]
    assert cookie_entry["ModuleKey"] == "cookies"
    assert cookie_entry["OWASPCategory"] == "Security Misconfiguration"
    assert cookie_entry["Recommendation"]


def test_default_profiles_include_the_cookie_module(client, dev_token):
    profiles = client.get(
        "/api/scan-profiles", headers=auth(dev_token)
    ).get_json()["ScanProfiles"]
    for name in ("Quick Scan", "OWASP Top 10 Full Scan"):
        profile = next(p for p in profiles if p["Name"] == name)
        keys = {m["ModuleKey"] for m in profile["Modules"]}
        assert "cookies" in keys, (name, keys)
    headers_only = next(p for p in profiles if p["Name"] == "Basic Security Headers")
    assert {m["ModuleKey"] for m in headers_only["Modules"]} == {"http_headers"}


def test_seed_reconciles_an_existing_default_profile(app):
    """
    A database seeded before the cookie module existed must receive it, without
    duplicating modules and without touching user-created profiles.
    """
    with app.app_context():
        profile = ScanProfile.query.filter_by(Name="OWASP Top 10 Full Scan").one()
        cookie_vuln = Vulnerability.query.filter_by(Name=COOKIE_VULN).one()
        # Simulate the pre-P1 state: remove the cookie module only.
        ProfileModule.query.filter_by(
            ScanProfileID=profile.ScanProfileID,
            VulnerabilityID=cookie_vuln.VulnerabilityID,
        ).delete()
        # A user-created profile that must never be modified.
        custom = ScanProfile(Name="My custom profile", MaxDepth=1, MaxPages=5)
        db.session.add(custom)
        db.session.flush()
        db.session.add(ProfileModule(
            ScanProfileID=custom.ScanProfileID,
            VulnerabilityID=Vulnerability.query.filter_by(
                Name="Missing HTTP Security Headers").one().VulnerabilityID,
        ))
        db.session.commit()
        custom_id = custom.ScanProfileID

        run_seed()  # reconciliation happens here

        profile = ScanProfile.query.filter_by(Name="OWASP Top 10 Full Scan").one()
        cookie_vuln = Vulnerability.query.filter_by(Name=COOKIE_VULN).one()
        attached = ProfileModule.query.filter_by(
            ScanProfileID=profile.ScanProfileID,
            VulnerabilityID=cookie_vuln.VulnerabilityID,
        ).count()
        assert attached == 1

        custom = db.session.get(ScanProfile, custom_id)
        assert [m.VulnerabilityID for m in custom.modules] == [
            Vulnerability.query.filter_by(
                Name="Missing HTTP Security Headers").one().VulnerabilityID
        ]


def test_repeated_seed_is_idempotent(app):
    """Running the seed repeatedly must not create duplicate modules."""
    with app.app_context():
        run_seed()
        before = {
            (m.ScanProfileID, m.VulnerabilityID)
            for m in ProfileModule.query.all()
        }
        profile_ids = {
            p.ScanProfileID: p.Name for p in ScanProfile.query.all()
        }

        run_seed()
        run_seed()

        after_rows = ProfileModule.query.all()
        after = {(m.ScanProfileID, m.VulnerabilityID) for m in after_rows}
        assert len(after_rows) == len(after), "duplicate ProfileModule rows"
        assert after == before
        for scan_profile_id, name in profile_ids.items():
            rows = [m for m in after_rows if m.ScanProfileID == scan_profile_id]
            vuln_ids = [m.VulnerabilityID for m in rows]
            assert len(vuln_ids) == len(set(vuln_ids)), name
