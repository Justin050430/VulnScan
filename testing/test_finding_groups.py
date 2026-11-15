"""
Logical finding consolidation tests (P3, checkpoint 1).

Two layers are covered:

  * pure identity/aggregation tests that build findings in memory, so every
    identity dimension (rule, cookie name, rule id, endpoint, method,
    parameter) is exercised in isolation without any network access;
  * integration tests against the controlled local target that prove the
    additive API view is consistent with the unchanged flat finding list.

Nothing here asserts a hardcoded totals number: the reference expectations are
derived from the scan's own records (see test_reference_scan_groups_are_consistent).
"""
import json

import pytest

from conftest import auth, TARGET_URL

MODULES = ("sqli", "xss", "http_headers", "cookies")


# ---------------------------------------------------------------------------
# Helpers - lightweight stand-ins for stored findings
# ---------------------------------------------------------------------------
class _Vulnerability:
    def __init__(self, name, category="A05:2021 Security Misconfiguration",
                 module_key=...):
        from app.utils.modules import module_key_for_name

        self.Name = name
        self.OWASPCategory = category
        self.module_key = (
            module_key_for_name(name) if module_key is ... else module_key
        )


class _Page:
    def __init__(self, url):
        self.URL = url


class _Finding:
    """The subset of the Finding row that identity and aggregation use."""

    def __init__(self, finding_id=1, vulnerability=None, parameter=None,
                 method="GET", evidence="", payload=None, status="Open",
                 severity="Medium", risk=5.0, confidence=0.95, detected=None,
                 page_url="http://127.0.0.1:5199/", vulnerability_id=1,
                 retests=()):
        from datetime import datetime

        self.FindingID = finding_id
        self.VulnerabilityID = vulnerability_id
        self.vulnerability = vulnerability or _Vulnerability(
            "Missing HTTP Security Headers"
        )
        self.Parameter = parameter
        self.RequestMethod = method
        self.Evidence = evidence
        self.Payload = payload
        self.Status = status
        self.Severity = severity
        self.RiskScore = risk
        self.Confidence = confidence
        self.DetectedAt = detected or datetime(2026, 11, 15, 10, 0, 0)
        self.page = _Page(page_url) if page_url else None
        self._retests = list(retests)

    @property
    def classification(self):
        if self.Confidence is None:
            return "Unclassified"
        return "Confirmed" if float(self.Confidence) >= 0.8 else "Suspected"

    def retest_entries(self):
        return self._retests

    def to_dict(self):
        return {
            "FindingID": self.FindingID,
            "Severity": self.Severity,
            "RiskScore": self.RiskScore,
            "Confidence": self.Confidence,
            "Classification": self.classification,
            "Status": self.Status,
            "Parameter": self.Parameter,
            "Payload": self.Payload,
            "RequestMethod": self.RequestMethod,
            "Evidence": self.Evidence,
            "URL": self.page.URL if self.page else None,
            "Retests": self.retest_entries(),
        }


def _sqli(finding_id, parameter="id", method="GET", page_url="http://h/product?id=1",
          evidence=None, vulnerability_id=1):
    return _Finding(
        finding_id=finding_id,
        vulnerability=_Vulnerability("SQL Injection", "A03:2021 Injection"),
        parameter=parameter,
        method=method,
        page_url=page_url,
        evidence=evidence if evidence is not None else "",
        vulnerability_id=vulnerability_id,
    )


def _cookie(finding_id, name="session", rule="httponly", page_url="http://h/a"):
    return _Finding(
        finding_id=finding_id,
        vulnerability=_Vulnerability(
            "Insecure Cookie Attributes", "A05:2021 Security Misconfiguration"
        ),
        parameter=name,
        page_url=page_url,
        payload="Path=/",
        evidence=f"COOKIE NAME: {name}\nRULE VIOLATED: x\nRULE ID: {rule}",
    )


def _header(finding_id, rule="X-Frame-Options", payload="missing",
            page_url="http://h/a", status="Open"):
    return _Finding(
        finding_id=finding_id,
        vulnerability=_Vulnerability("Missing HTTP Security Headers"),
        parameter=rule,
        payload=payload,
        page_url=page_url,
        status=status,
    )


# ---------------------------------------------------------------------------
# Endpoint normalisation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("url, expected", [
    ("http://Example.COM:80/a//b/?x=1#frag", "http://example.com/a/b/"),
    ("https://example.com:443/x", "https://example.com/x"),
    ("http://example.com:8080/x", "http://example.com:8080/x"),
    ("https://example.com:80/x", "https://example.com:80/x"),      # non-default
    ("http://example.com/%7euser/%2fpath", "http://example.com/~user/%2Fpath"),
    ("http://example.com/Admin/Users", "http://example.com/Admin/Users"),
    ("http://[::1]:5199/x", "http://[::1]:5199/x"),
    ("http://example.com", "http://example.com/"),
])
def test_endpoint_normalisation(url, expected):
    from app.services.grouping_service import normalise_endpoint

    assert normalise_endpoint(url) == expected


@pytest.mark.parametrize("url", ["", None, "not a url", "ftp://example.com/x",
                                 "http://", "//missing-scheme/path"])
def test_endpoint_normalisation_fails_closed(url):
    from app.services.grouping_service import normalise_endpoint

    assert normalise_endpoint(url) is None


# ---------------------------------------------------------------------------
# Identity keys
# ---------------------------------------------------------------------------
def test_header_identity_is_per_rule():
    from app.services.grouping_service import group_key

    a = group_key(_header(1, "X-Frame-Options", page_url="http://h/a"))
    b = group_key(_header(2, "X-Frame-Options", page_url="http://h/b"))
    c = group_key(_header(3, "Content-Security-Policy", page_url="http://h/a"))

    assert a == b == "v1:http_headers:x-frame-options"
    assert c != a                      # different rule never merges


def test_header_identity_keeps_missing_and_weak_together_but_separate_in_group():
    from app.services.grouping_service import build_groups, group_key

    missing = _header(1, "X-Frame-Options", "missing", "http://h/a")
    weak = _header(2, "X-Frame-Options", "ALLOW-FROM x", "http://h/b")
    assert group_key(missing) == group_key(weak)

    groups, _ = build_groups([missing, weak])
    assert len(groups) == 1
    assert groups[0]["ConditionCounts"] == {"missing": 1, "weak": 1}
    # The condition stays visible per location.
    payloads = sorted(loc["Payload"] for loc in groups[0]["Locations"])
    assert payloads == ["ALLOW-FROM x", "missing"]


def test_unidentifiable_header_findings_never_merge():
    from app.services.grouping_service import group_key

    a = group_key(_Finding(1, parameter=None))
    b = group_key(_Finding(2, parameter=None))
    assert a != b
    assert a.startswith("v1:unidentified:")


def test_cookie_identity_is_name_plus_rule():
    from app.services.grouping_service import group_key

    httponly = group_key(_cookie(1, "session", "httponly"))
    samesite = group_key(_cookie(2, "session", "samesite"))
    other_name = group_key(_cookie(3, "pref", "httponly"))

    assert httponly == "v1:cookies:httponly:session"
    assert len({httponly, samesite, other_name}) == 3


def test_cookie_rule_falls_back_to_legacy_title():
    from app.services.grouping_service import cookie_rule, group_key

    legacy = _cookie(1, "session")
    legacy.Evidence = (
        "COOKIE NAME: session\n"
        "RULE VIOLATED: the HttpOnly attribute is missing on a "
        "session/authentication cookie"
    )
    assert cookie_rule(legacy.Evidence) == "httponly"
    assert group_key(legacy) == "v1:cookies:httponly:session"

    prefix = _cookie(2, "__Host-x")
    prefix.Evidence = (
        "RULE VIOLATED: the cookie-name prefix contract is violated "
        "('__Host-' requires the Secure attribute)"
    )
    assert cookie_rule(prefix.Evidence) == "prefix"


def test_unknown_cookie_rule_never_merges():
    from app.services.grouping_service import group_key

    first = _cookie(1, "session")
    first.Evidence = "COOKIE NAME: session\nRULE VIOLATED: something new"
    second = _cookie(2, "session")
    second.Evidence = "COOKIE NAME: session\nRULE VIOLATED: something new"
    assert group_key(first) != group_key(second)


def test_sqli_identity_merges_page_instances_of_one_endpoint():
    from app.services.grouping_service import group_key

    one = group_key(_sqli(1, page_url="http://h/product?id=1"))
    two = group_key(_sqli(2, page_url="http://h/product?id=2"))
    assert one == two == "v1:sqli:GET:http://h/product:id"


def test_sqli_identity_separates_endpoint_method_and_parameter():
    from app.services.grouping_service import group_key

    base = group_key(_sqli(1, "id", "GET", "http://h/product?id=1"))
    other_endpoint = group_key(_sqli(2, "id", "GET", "http://h/blind?id=1"))
    other_method = group_key(_sqli(3, "id", "POST", "http://h/product?id=1"))
    other_parameter = group_key(_sqli(4, "q", "GET", "http://h/product?id=1"))

    assert len({base, other_endpoint, other_method, other_parameter}) == 4


def test_legacy_injection_point_line_matches_new_request_target_line():
    """Old evidence (INJECTION POINT) must group like new evidence."""
    from app.services.grouping_service import group_key

    legacy = _sqli(
        1, "order", "POST", "http://h/feedback",
        evidence=("INJECTION POINT: form field 'order' of POST "
                  "http://h/feedback\nBASELINE REQUEST: ..."),
    )
    new = _sqli(
        2, "order", "POST", "http://h/feedback",
        evidence="REQUEST TARGET: POST http://h/feedback\n",
    )
    assert group_key(legacy) == group_key(new) == "v1:sqli:POST:http://h/feedback:order"


def test_request_target_wins_over_page_url():
    """Two forms on one page posting elsewhere must not merge."""
    from app.services.grouping_service import group_key

    first = _sqli(1, "q", "POST", "http://h/form-page",
                  evidence="REQUEST TARGET: POST http://h/search")
    second = _sqli(2, "q", "POST", "http://h/form-page",
                   evidence="REQUEST TARGET: POST http://h/filter")
    assert group_key(first) != group_key(second)


def test_xss_identity_keeps_each_reflection_point_distinct():
    from app.services.grouping_service import group_key

    def xss(fid, parameter, method, url, target=None):
        return _Finding(
            finding_id=fid,
            vulnerability=_Vulnerability("Cross-Site Scripting (XSS)",
                                         "A03:2021 Injection"),
            parameter=parameter,
            method=method,
            page_url=url,
            evidence=f"REQUEST TARGET: {method} {target or url}",
            payload="<script>vulnscan_xss_7f3a9c</script>",
        )

    keys = {
        group_key(xss(1, "q", "GET", "http://h/search?q=x")),
        group_key(xss(2, "message", "POST", "http://h/feedback")),
        group_key(xss(3, "order", "POST", "http://h/feedback")),
        group_key(xss(4, "id", "GET", "http://h/blind?id=1")),
    }
    assert len(keys) == 4


def test_unparseable_sqli_endpoint_never_merges():
    from app.services.grouping_service import group_key

    first = _sqli(1, "q", "GET", page_url=None)
    second = _sqli(2, "q", "GET", page_url=None)
    assert group_key(first) != group_key(second)
    assert group_key(first).startswith("v1:unidentified:")


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
def test_group_status_is_derived_from_members():
    from app.services.grouping_service import build_groups

    still_open = [_header(1, page_url="http://h/a"),
                  _header(2, page_url="http://h/b", status="Resolved")]
    groups, _ = build_groups(still_open)
    assert groups[0]["Status"] == "Open"
    assert groups[0]["StatusCounts"] == {
        "Open": 1, "Resolved": 1, "False Positive": 0}
    assert groups[0]["Mixed"] is True

    all_resolved = [_header(3, page_url="http://h/a", status="Resolved"),
                    _header(4, page_url="http://h/b", status="False Positive")]
    groups, _ = build_groups(all_resolved)
    assert groups[0]["Status"] == "Resolved"

    dismissed = [_header(5, page_url="http://h/a", status="False Positive")]
    groups, _ = build_groups(dismissed)
    assert groups[0]["Status"] == "False Positive"


def test_group_retest_verdict_uses_worst_location():
    from app.services.grouping_service import build_groups

    mild = _header(1, page_url="http://h/a", status="Resolved")
    mild._retests = [{"Verdict": "Resolved"}]
    worse = _header(2, page_url="http://h/b")
    worse._retests = [{"Verdict": "Still Detected"}]

    groups, _ = build_groups([mild, worse])
    assert groups[0]["LatestRetestVerdict"] == "Still Detected"
    assert groups[0]["RetestedCount"] == 2


def test_group_severity_and_classification_take_the_worst_member():
    from app.services.grouping_service import build_groups

    ordinary = _header(1, page_url="http://h/a")
    severe = _header(2, page_url="http://h/b")
    severe.Severity = "High"
    severe.RiskScore = 7.5
    severe.Confidence = 0.55

    groups, _ = build_groups([ordinary, severe])
    assert groups[0]["Severity"] == "High"
    assert groups[0]["RiskScore"] == 7.5
    assert groups[0]["Classification"] == "Confirmed"   # any confirmed wins


def test_cookie_group_lists_every_observed_url():
    from app.services.grouping_service import build_groups

    finding = _cookie(1, "session", "httponly", "http://h/cookies_weak")
    finding.Evidence += (
        "\nOBSERVATION COUNT: 2"
        "\nOBSERVED URL: http://h/cookies_weak"
        "\nOBSERVED URL: http://h/cookies_weak_more"
    )
    groups, _ = build_groups([finding])
    assert groups[0]["RecordCount"] == 1
    assert groups[0]["AffectedURLCount"] == 2
    assert groups[0]["AffectedURLs"] == [
        "http://h/cookies_weak", "http://h/cookies_weak_more"]


# ---------------------------------------------------------------------------
# Integration: additive API view over a real scan of the controlled target
# ---------------------------------------------------------------------------
def _profile(client, admin_token, name, *, max_pages=20, max_depth=2):
    vulns = client.get(
        "/api/vulnerabilities", headers=auth(admin_token),
        query_string={"include_disabled": "true"},
    ).get_json()["Vulnerabilities"]
    ids = [v["VulnerabilityID"] for v in vulns if v["ModuleKey"] in MODULES]
    resp = client.post("/api/scan-profiles", headers=auth(admin_token), json={
        "name": name, "max_depth": max_depth, "max_pages": max_pages,
        "request_delay_ms": 0, "follow_external": False,
        "module_vuln_ids": ids})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["ScanProfile"]["ScanProfileID"]


def _scan_detail(client, token, profile_id, name="Grouping scan"):
    resp = client.post("/api/scans", headers=auth(token), json={
        "target_url": TARGET_URL, "scan_profile_id": profile_id,
        "scan_name": name})
    assert resp.status_code == 202, resp.get_json()
    scan_id = resp.get_json()["Scan"]["ScanID"]
    return client.get(
        f"/api/scans/{scan_id}", headers=auth(token)
    ).get_json()["Scan"]


@pytest.fixture()
def scan(client, admin_token, dev_token, target):
    pid = _profile(client, admin_token, "Grouping profile")
    return _scan_detail(client, dev_token, pid)


def test_reference_scan_groups_are_consistent(scan):
    """Group counts must be derived from, and agree with, the records."""
    groups = scan["FindingGroups"]
    findings = scan["Findings"]

    assert scan["IssueCount"] == len(groups) > 0
    assert sum(g["RecordCount"] for g in groups) == scan["FindingCount"]
    assert scan["FindingCount"] == len(findings)
    assert sum(scan["IssueSeverityCounts"].values()) == scan["IssueCount"]
    assert sum(scan["SeverityCounts"].values()) == scan["FindingCount"]
    assert scan["IssueCount"] < scan["FindingCount"]

    # Every record is annotated with its group and that group's size.
    sizes = {g["GroupKey"]: g["RecordCount"] for g in groups}
    for finding in findings:
        assert finding["GroupKey"] in sizes
        assert finding["GroupSize"] == sizes[finding["GroupKey"]]

    # Locations expose the original evidence and retest history per record.
    for group in groups:
        assert len(group["Locations"]) == group["RecordCount"]
        for location in group["Locations"]:
            assert "FindingID" in location and "Evidence" in location
            assert "Retests" in location
        assert group["Status"] in ("Open", "Resolved", "False Positive")
        assert group["AffectedURLCount"] >= group["PageCount"] >= 1


def test_scan_list_exposes_issue_counts(client, dev_token, scan):
    listing = client.get("/api/scans", headers=auth(dev_token)).get_json()
    item = next(s for s in listing["Scans"] if s["ScanID"] == scan["ScanID"])
    assert item["IssueCount"] == scan["IssueCount"]
    assert sum(item["IssueSeverityCounts"].values()) == scan["IssueCount"]
    # Record-based fields keep their original meaning.
    assert item["FindingCount"] == scan["FindingCount"]


def test_header_groups_are_one_per_rule(scan):
    header_groups = [
        g for g in scan["FindingGroups"]
        if g["VulnerabilityName"] == "Missing HTTP Security Headers"
    ]
    keys = [g["GroupKey"] for g in header_groups]
    assert len(keys) == len(set(keys))

    for group in header_groups:
        conditions = group["ConditionCounts"]
        assert conditions["missing"] + conditions["weak"] == group["RecordCount"]
        assert group["AffectedURLCount"] == group["RecordCount"]
        assert len(group["Pages"]) == group["RecordCount"]
        # Every location keeps its own observed header state.
        for location in group["Locations"]:
            assert location["Payload"]
            assert location["Parameter"] == group["Parameters"][0]

    # A site-wide header must be a single issue, not one per page.
    assert max(g["RecordCount"] for g in header_groups) > 1


def test_cookie_groups_keep_names_rules_and_urls_without_values(
    scan, vuln_target_module
):
    marker = vuln_target_module.COOKIE_SECRET_MARKER
    cookie_groups = [
        g for g in scan["FindingGroups"]
        if g["VulnerabilityName"] == "Insecure Cookie Attributes"
    ]
    keys = {g["GroupKey"] for g in cookie_groups}
    assert all(key.startswith("v1:cookies:") for key in keys)
    # Different cookie names and different rules are separate issues.
    names = {g["GroupKey"].rsplit(":", 1)[1] for g in cookie_groups}
    rules = {g["GroupKey"].split(":")[2] for g in cookie_groups}
    assert len(names) >= 3
    assert len(rules) >= 3

    # The same weakness observed on two pages stays one record but names both.
    session_httponly = next(
        g for g in cookie_groups
        if g["GroupKey"].endswith(":session") and ":httponly:" in g["GroupKey"]
    )
    assert session_httponly["RecordCount"] == 1
    assert session_httponly["AffectedURLCount"] >= 2
    assert any("/cookies_weak" in url for url in session_httponly["AffectedURLs"])
    assert any(
        url.endswith("/cookies_weak_more")
        for url in session_httponly["AffectedURLs"]
    )
    evidence = session_httponly["Locations"][0]["Evidence"]
    assert "RULE ID: httponly" in evidence
    assert evidence.count("OBSERVED URL:") >= 2

    # Cookie values must never appear anywhere in the consolidated view.
    assert marker not in json.dumps(cookie_groups)


def test_sqli_groups_merge_page_instances_but_not_endpoints(scan):
    sqli_groups = [
        g for g in scan["FindingGroups"]
        if g["VulnerabilityName"] == "SQL Injection"
    ]
    keys = {g["GroupKey"]: g for g in sqli_groups}

    product = next(k for k in keys if "/product:" in k)
    blind = next(k for k in keys if "/blind:" in k)
    feedback = next(k for k in keys if "/feedback:" in k)

    assert keys[product]["RecordCount"] == 2
    assert keys[product]["AffectedURLs"] == [
        f"{TARGET_URL}product?id=1", f"{TARGET_URL}product?id=2"]
    assert keys[blind]["RecordCount"] == 1
    assert keys[feedback]["RecordCount"] == 1
    assert len({product, blind, feedback}) == 3
    for key in (product, blind, feedback):
        assert ":GET:" in key or ":POST:" in key


def test_xss_groups_keep_each_reflection_point_distinct(scan):
    xss_groups = [
        g for g in scan["FindingGroups"]
        if g["VulnerabilityName"] == "Cross-Site Scripting (XSS)"
    ]
    keys = {g["GroupKey"] for g in xss_groups}
    assert len(keys) == len(xss_groups) >= 3
    assert any("/search:q" in k for k in keys)
    assert any("/feedback:message" in k for k in keys)
    assert any("/feedback:order" in k for k in keys)
    # The reflected payload survives per location.
    for group in xss_groups:
        assert all(loc["Payload"] for loc in group["Locations"])


def test_findings_by_page_view_is_unchanged(scan):
    """The record-level page view must keep working exactly as before."""
    assert scan["Pages"]
    page_urls = {page["URL"] for page in scan["Pages"]}
    for finding in scan["Findings"]:
        assert finding["URL"] in page_urls
        assert finding["Evidence"]
        assert finding["Status"] in ("Open", "Resolved", "False Positive")
    # Record-level location chip data (URL + parameter) is still present.
    assert any(f["Parameter"] for f in scan["Findings"])


def test_group_view_respects_scan_ownership(client, admin_token, dev_token,
                                            scan):
    client.post("/api/users", headers=auth(admin_token), json={
        "username": "groupoutsider", "email": "groupoutsider@vulnscan.local",
        "password": "Outsider@2025", "role": "Developer"})
    outsider = client.post("/api/auth/login", json={
        "email": "groupoutsider@vulnscan.local",
        "password": "Outsider@2025"}).get_json()["access_token"]
    assert client.get(
        f"/api/scans/{scan['ScanID']}", headers=auth(outsider)
    ).status_code == 403
