"""
Crawler discovery tests (P2): robots.txt policy, sitemaps and GET form actions.

Everything runs against the controlled local target on 127.0.0.1; the
out-of-scope host is a second loopback server that counts any request it
receives, so "was this URL fetched?" is answered by evidence rather than by
inference.
"""
import pytest

from conftest import auth, EXTERNAL_URL, TARGET_URL

try:  # PyMuPDF provides both module names depending on version
    import pymupdf as _pdf
except ImportError:  # pragma: no cover
    import fitz as _pdf

DEFAULT_ROBOTS = "User-agent: *\nDisallow: /__test__\nAllow: /\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _profile(client, admin_token, name, *, max_pages=30, max_depth=2,
             module_keys=("http_headers",)):
    vulns = client.get(
        "/api/vulnerabilities", headers=auth(admin_token),
        query_string={"include_disabled": "true"},
    ).get_json()["Vulnerabilities"]
    ids = [v["VulnerabilityID"] for v in vulns if v["ModuleKey"] in module_keys]
    resp = client.post("/api/scan-profiles", headers=auth(admin_token), json={
        "name": name, "max_depth": max_depth, "max_pages": max_pages,
        "request_delay_ms": 0, "follow_external": False,
        "module_vuln_ids": ids})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["ScanProfile"]["ScanProfileID"]


def _scan(client, token, target_url, profile_id, name="Discovery scan"):
    resp = client.post("/api/scans", headers=auth(token), json={
        "target_url": target_url, "scan_profile_id": profile_id,
        "scan_name": name})
    assert resp.status_code == 202, resp.get_json()
    scan_id = resp.get_json()["Scan"]["ScanID"]
    return client.get(
        f"/api/scans/{scan_id}", headers=auth(token)
    ).get_json()["Scan"]


def _pages(detail):
    return [p["URL"] for p in detail["Pages"]]


@pytest.fixture()
def target_hits(vuln_target_module):
    """Reset the controlled target's request counters for one test."""
    vuln_target_module.HITS.clear()
    yield vuln_target_module.HITS
    vuln_target_module.HITS.clear()


@pytest.fixture()
def robots(vuln_target_module):
    """Override the target's robots.txt for one test, then restore it."""
    def _set(content):
        vuln_target_module.ROBOTS["content"] = content

    yield _set
    vuln_target_module.ROBOTS["content"] = DEFAULT_ROBOTS


# ---------------------------------------------------------------------------
# robots.txt parser (unit)
# ---------------------------------------------------------------------------
def test_robots_parser_extracts_sitemaps_and_applies_rules():
    from app.scanner.robots import parse_robots

    policy = parse_robots(
        "User-agent: *\n"
        "Disallow: /private\n"
        "Allow: /private/public\n"
        "Sitemap: https://example.test/sitemap.xml\n"
        "Sitemap: https://example.test/sitemap-2.xml\n"
    )
    assert policy.available
    assert policy.sitemaps == [
        "https://example.test/sitemap.xml",
        "https://example.test/sitemap-2.xml",
    ]
    assert not policy.allows("/private/secret")
    # Longest match wins: the Allow is more specific than the Disallow.
    assert policy.allows("/private/public/page")
    assert policy.allows("/anything-else")


def test_robots_parser_ignores_foreign_groups_and_wildcards():
    from app.scanner.robots import parse_robots

    policy = parse_robots(
        "User-agent: otherbot\n"
        "Disallow: /\n"
        "\n"
        "User-agent: *\n"
        "Disallow: /*.pdf$\n"
    )
    assert policy.allows("/index.html")
    assert not policy.allows("/manual.pdf")
    assert policy.allows("/manual.pdf?download=1")


def test_robots_parser_treats_empty_disallow_as_allow_all():
    from app.scanner.robots import parse_robots

    policy = parse_robots("User-agent: *\nDisallow:\n")
    assert policy.available
    assert policy.rules_applied == 0
    assert policy.allows("/anything")


def test_robots_fetch_rejects_html_soft_404(monkeypatch):
    """An HTML page served at /robots.txt must not become a policy."""
    from app.scanner import robots as robots_module

    class _FakeHttp:
        def get(self, url):
            class _Resp:
                ok = True
                status_code = 200
                error = None
                text = "<!doctype html><html><body>Not found</body></html>"
            return _Resp()

    policy = robots_module.fetch_policy(_FakeHttp(), "http://example.test")
    assert not policy.available
    assert "HTML" in policy.error


# ---------------------------------------------------------------------------
# sitemap parser (unit)
# ---------------------------------------------------------------------------
def test_sitemap_parser_reads_urlset_and_caps_entries():
    from app.scanner.sitemap import parse_sitemap

    xml = (
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>http://example.test/a</loc></url>"
        "<url><loc>http://example.test/b</loc></url>"
        "</urlset>"
    )
    kind, locations, truncated = parse_sitemap(xml)
    assert kind == "urlset"
    assert locations == ["http://example.test/a", "http://example.test/b"]
    assert truncated is False

    kind, locations, truncated = parse_sitemap(xml, max_urls=1)
    assert locations == ["http://example.test/a"]
    assert truncated is True


def test_sitemap_parser_reads_index_and_rejects_unknown_roots():
    from app.scanner.sitemap import SitemapError, parse_sitemap

    index = (
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<sitemap><loc>http://example.test/one.xml</loc></sitemap>"
        "</sitemapindex>"
    )
    kind, locations, _ = parse_sitemap(index)
    assert kind == "sitemapindex"
    assert locations == ["http://example.test/one.xml"]

    with pytest.raises(SitemapError):
        parse_sitemap("<rss><channel/></rss>")


@pytest.mark.parametrize("document", [
    "<urlset><url><loc>http://example.test/a</loc></url>",       # unclosed
    "<urlset>&undefined;</urlset>",                              # bad entity
    "",
])
def test_sitemap_parser_rejects_malformed_documents(document):
    from app.scanner.sitemap import SitemapError, parse_sitemap

    with pytest.raises(SitemapError):
        parse_sitemap(document)


def test_sitemap_parser_rejects_dtd_and_entities():
    """A DTD makes entity expansion ("billion laughs") possible - reject it."""
    from app.scanner.sitemap import SitemapError, parse_sitemap

    bomb = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE urlset [<!ENTITY a "aaaaaaaaaa">]>'
        "<urlset><url><loc>&a;</loc></url></urlset>"
    )
    with pytest.raises(SitemapError) as excinfo:
        parse_sitemap(bomb)
    assert "entities are not allowed" in str(excinfo.value)


def test_sitemap_parser_rejects_oversized_document():
    from app.scanner.sitemap import MAX_SITEMAP_BYTES, SitemapError, parse_sitemap

    with pytest.raises(SitemapError) as excinfo:
        parse_sitemap("<urlset>" + ("x" * (MAX_SITEMAP_BYTES + 10)) + "</urlset>")
    assert "byte limit" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Discovery gates (unit, no network)
# ---------------------------------------------------------------------------
def test_accept_gate_rejects_out_of_scope_and_unsafe_urls():
    from urllib.parse import urlparse

    from app.scanner.crawler import Crawler

    class _FakeHttp:
        url_validator = staticmethod(
            lambda url: (False, "private address") if "metadata" in url
            else (True, "")
        )

    crawler = Crawler(http=_FakeHttp(), max_pages=10, max_depth=2)
    crawler._base_parsed = urlparse("http://127.0.0.1:5199/")

    assert crawler._accept("http://127.0.0.1:5199/ok", 1, "Links") is True
    assert crawler._accept("http://evil.example.com/page", 1, "Links") is False
    assert crawler._accept("http://127.0.0.1:5199/metadata", 1, "Links") is False
    assert crawler._accept("http://127.0.0.1:5199/style.css", 1, "Links") is False
    assert crawler._accept("http://127.0.0.1:5199/ok", 1, "Links") is False

    excluded = crawler.discovery["Excluded"]
    assert excluded["ScopeRejectedCount"] == 2
    assert excluded["StaticSkippedCount"] == 1
    reasons = [sample["Reason"] for sample in excluded["Samples"]["Scope"]]
    assert "outside the target scan scope" in reasons
    assert "private address" in reasons


def test_accept_gate_respects_skip_routes_and_robots():
    from urllib.parse import urlparse

    from app.scanner.crawler import Crawler
    from app.scanner.robots import parse_robots

    crawler = Crawler(
        http=None, max_pages=10, max_depth=2, skip_url_contains=("logout",)
    )
    crawler._base_parsed = urlparse("http://127.0.0.1:5199/")
    crawler._robots = parse_robots("User-agent: *\nDisallow: /admin\n")

    assert crawler._accept("http://127.0.0.1:5199/logout", 1, "Links") is False
    assert crawler._accept("http://127.0.0.1:5199/admin", 1, "Links") is False
    assert crawler._accept("http://127.0.0.1:5199/shop", 1, "Links") is True
    assert crawler.discovery["RobotsTxt"]["BlockedCount"] == 1
    assert crawler.discovery["Excluded"]["ScopeRejectedCount"] == 1


# ---------------------------------------------------------------------------
# robots.txt Sitemap extraction and Disallow behaviour (integration)
# ---------------------------------------------------------------------------
def test_robots_sitemap_declaration_drives_discovery(
    client, admin_token, dev_token, target, target_hits, robots
):
    robots(
        "User-agent: *\n"
        f"Sitemap: {TARGET_URL}t/sitemap_ok.xml\n"
    )
    pid = _profile(client, admin_token, "Robots sitemap profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    pages = _pages(detail)
    assert f"{TARGET_URL}t/page1" in pages
    assert f"{TARGET_URL}t/page2" in pages
    assert target_hits["t_page1"] >= 1

    discovery = detail["Coverage"]["Discovery"]
    assert discovery["Available"] is True
    assert discovery["RobotsTxt"]["Fetched"] is True
    assert discovery["RobotsTxt"]["HTTPStatus"] == 200
    assert f"{TARGET_URL}t/sitemap_ok.xml" in \
        discovery["RobotsTxt"]["SitemapDeclarations"]
    assert discovery["Sitemaps"]["Parsed"] == 1
    assert discovery["Sources"]["Sitemaps"] == 2     # duplicates are not re-queued
    assert "sitemap URL(s)" in detail["CoverageNote"]


def test_robots_disallow_prevents_fetching_listed_url(
    client, admin_token, dev_token, target, target_hits, robots
):
    """A sitemap URL the policy disallows must never be requested."""
    robots(
        "User-agent: *\n"
        "Disallow: /t/private\n"
        f"Sitemap: {TARGET_URL}t/sitemap_private.xml\n"
    )
    pid = _profile(client, admin_token, "Robots disallow profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    # The allowed URL from the same sitemap is crawled ...
    assert f"{TARGET_URL}t/page1" in _pages(detail)
    assert target_hits["t_page1"] >= 1
    # ... while the disallowed one is never requested at all.
    assert target_hits["t_private"] == 0
    assert f"{TARGET_URL}t/private" not in _pages(detail)

    discovery = detail["Coverage"]["Discovery"]
    assert discovery["RobotsTxt"]["RulesApplied"] == 1
    assert discovery["RobotsTxt"]["BlockedCount"] == 1
    blocked = discovery["Excluded"]["Samples"]["Robots"]
    assert blocked[0]["URL"] == f"{TARGET_URL}t/private"
    assert "Disallow: /t/private" in blocked[0]["Reason"]
    assert any(
        "robots.txt crawl policy" in line
        for line in detail["Coverage"]["Limitations"]
    )


# ---------------------------------------------------------------------------
# Sitemap-index nesting
# ---------------------------------------------------------------------------
def test_sitemap_index_discovery_follows_one_level(
    client, admin_token, dev_token, target, target_hits, robots
):
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_index.xml\n")
    pid = _profile(client, admin_token, "Sitemap index profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    assert f"{TARGET_URL}t/nested" in _pages(detail)
    discovery = detail["Coverage"]["Discovery"]["Sitemaps"]
    assert discovery["IndexFiles"] == 1
    assert discovery["Parsed"] == 2
    # Counters see every request the scan makes, including module requests.
    assert target_hits["t_nested"] >= 1


def test_nested_sitemap_index_beyond_one_level_is_not_followed(
    client, admin_token, dev_token, target, target_hits, robots
):
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_deep_index.xml\n")
    pid = _profile(client, admin_token, "Deep sitemap index profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    assert f"{TARGET_URL}t/deep_page" not in _pages(detail)
    assert target_hits["t_deep_page"] == 0
    rejected = detail["Coverage"]["Discovery"]["Sitemaps"]["Rejected"]
    assert any("one level only" in entry["Reason"] for entry in rejected)


# ---------------------------------------------------------------------------
# Scope and SSRF boundaries
# ---------------------------------------------------------------------------
def test_out_of_scope_sitemap_url_is_never_fetched(
    client, admin_token, dev_token, target, external_server, robots
):
    before = external_server["count"]
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_ok.xml\n")
    pid = _profile(client, admin_token, "Sitemap scope profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    assert external_server["count"] == before
    assert all(url.startswith(TARGET_URL) for url in _pages(detail))
    excluded = detail["Coverage"]["Discovery"]["Excluded"]
    assert excluded["ScopeRejectedCount"] >= 1
    assert any(
        "sitemap-listed" in sample["URL"]
        for sample in excluded["Samples"]["Scope"]
    )


def test_external_sitemap_declaration_is_not_fetched(
    client, admin_token, dev_token, target, external_server, robots
):
    before = external_server["count"]
    robots(f"User-agent: *\nSitemap: {EXTERNAL_URL}sitemap.xml\n")
    pid = _profile(client, admin_token, "External sitemap profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    assert external_server["count"] == before
    sitemaps = detail["Coverage"]["Discovery"]["Sitemaps"]
    assert sitemaps["Parsed"] == 0
    assert sitemaps["RejectedCount"] == 1
    assert "outside the target scan scope" in sitemaps["Rejected"][0]["Reason"]


def test_sitemap_redirect_to_external_host_is_blocked(
    client, admin_token, dev_token, target, external_server, robots
):
    before = external_server["count"]
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_redirect.xml\n")
    pid = _profile(client, admin_token, "Sitemap redirect profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    assert external_server["count"] == before
    sitemaps = detail["Coverage"]["Discovery"]["Sitemaps"]
    assert sitemaps["Parsed"] == 0
    assert any(
        "Blocked redirect" in entry["Reason"] for entry in sitemaps["Rejected"]
    )


# ---------------------------------------------------------------------------
# Malformed / oversized / flooding sitemaps
# ---------------------------------------------------------------------------
def test_malformed_sitemap_is_rejected_without_failing_the_scan(
    client, admin_token, dev_token, target, robots
):
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_bad.xml\n")
    pid = _profile(client, admin_token, "Malformed sitemap profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    assert detail["Status"] == "Completed"
    assert f"{TARGET_URL}t/broken" not in _pages(detail)
    sitemaps = detail["Coverage"]["Discovery"]["Sitemaps"]
    assert sitemaps["Parsed"] == 0
    assert "malformed XML" in sitemaps["Rejected"][0]["Reason"]
    assert any(
        "sitemap file(s) could not be used" in line
        for line in detail["Coverage"]["Limitations"]
    )


def test_entity_expansion_sitemap_is_rejected(
    client, admin_token, dev_token, target, robots
):
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_entity.xml\n")
    pid = _profile(client, admin_token, "Entity sitemap profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    sitemaps = detail["Coverage"]["Discovery"]["Sitemaps"]
    assert sitemaps["Parsed"] == 0
    assert "entities are not allowed" in sitemaps["Rejected"][0]["Reason"]


def test_oversized_sitemap_is_rejected(
    client, admin_token, dev_token, target, target_hits, robots
):
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_big.xml\n")
    pid = _profile(client, admin_token, "Oversized sitemap profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    sitemaps = detail["Coverage"]["Discovery"]["Sitemaps"]
    assert sitemaps["Parsed"] == 0
    assert "byte limit" in sitemaps["Rejected"][0]["Reason"]
    assert target_hits["t_oversized"] == 0


def test_sitemap_url_count_limit_is_enforced(
    client, admin_token, dev_token, target, robots
):
    from app.scanner.sitemap import MAX_URLS_PER_SITEMAP

    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_flood.xml\n")
    pid = _profile(client, admin_token, "Flood sitemap profile", max_pages=5)
    detail = _scan(client, dev_token, TARGET_URL, pid)

    sitemaps = detail["Coverage"]["Discovery"]["Sitemaps"]
    assert sitemaps["URLsFound"] == MAX_URLS_PER_SITEMAP
    assert sitemaps["Truncated"] is True
    assert detail["PageCount"] <= 5
    assert any(
        "limit" in line for line in detail["Coverage"]["Limitations"]
    )


# ---------------------------------------------------------------------------
# Duplicates, form actions and relative URLs
# ---------------------------------------------------------------------------
def test_duplicate_urls_across_links_and_sitemaps_are_crawled_once(
    client, admin_token, dev_token, target, robots
):
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_ok.xml\n")
    pid = _profile(client, admin_token, "Duplicate URL profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    pages = _pages(detail)
    about = f"{TARGET_URL}about"
    assert pages.count(about) == 1
    assert len(pages) == len(set(pages))


def test_get_form_action_is_discovered_and_post_action_is_not(
    client, admin_token, dev_token, target, target_hits
):
    pid = _profile(client, admin_token, "Form discovery profile", max_depth=1)
    detail = _scan(client, dev_token, f"{TARGET_URL}t/form_discover", pid)

    pages = _pages(detail)
    assert f"{TARGET_URL}t/form_target" in pages
    assert target_hits["t_form_target"] >= 1
    # Forms are never submitted and POST actions are never requested.
    assert target_hits["t_post_target"] == 0
    assert f"{TARGET_URL}t/post_target" not in pages

    discovery = detail["Coverage"]["Discovery"]
    assert discovery["Sources"]["FormActions"] == 1
    assert "GET form action(s)" in detail["CoverageNote"]


def test_form_action_relative_url_is_resolved():
    """A relative form action must resolve against the page that served it."""
    from app.scanner.forms import parse_forms

    forms = parse_forms(
        "http://127.0.0.1:5199/t/form_discover",
        '<form method="get" action="form_target">'
        '<input type="text" name="q" value="term"></form>',
    )
    assert len(forms) == 1
    assert forms[0].action == "http://127.0.0.1:5199/t/form_target"
    assert forms[0].method == "GET"


# ---------------------------------------------------------------------------
# Limits and existing protections
# ---------------------------------------------------------------------------
def test_page_budget_limit_is_reported(client, admin_token, dev_token, target,
                                       robots):
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_flood.xml\n")
    pid = _profile(client, admin_token, "Budget profile", max_pages=3)
    detail = _scan(client, dev_token, TARGET_URL, pid)

    assert detail["PageCount"] <= 3
    limits = detail["Coverage"]["Discovery"]["Limits"]
    assert limits["PageBudgetReached"] is True
    assert any(
        "page limit" in line for line in detail["Coverage"]["Limitations"]
    )


def test_max_depth_zero_does_not_queue_sitemap_urls(
    client, admin_token, dev_token, target, robots
):
    """Sitemap URLs must not bypass the profile's depth limit."""
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_ok.xml\n")
    pid = _profile(client, admin_token, "Depth zero profile", max_depth=0)
    detail = _scan(client, dev_token, TARGET_URL, pid)

    assert detail["PageCount"] == 1
    assert detail["Coverage"]["Discovery"]["Sources"]["Sitemaps"] == 0


def test_robots_disabled_by_configuration_still_validates_scope(
    app, client, admin_token, dev_token, target, external_server, robots
):
    before = external_server["count"]
    app.config["SCANNER_RESPECT_ROBOTS_TXT"] = False
    try:
        robots("User-agent: *\nDisallow: /\n")
        pid = _profile(client, admin_token, "Robots disabled profile")
        detail = _scan(client, dev_token, TARGET_URL, pid)
    finally:
        app.config["SCANNER_RESPECT_ROBOTS_TXT"] = True

    # Crawling still worked (the policy was ignored) ...
    assert detail["PageCount"] >= 5
    discovery = detail["Coverage"]["Discovery"]
    assert discovery["RobotsTxt"]["Respected"] is False
    # ... but the scope rules were untouched.
    assert external_server["count"] == before
    assert all(url.startswith(TARGET_URL) for url in _pages(detail))


def test_existing_detection_modules_still_work_with_wider_discovery(
    client, admin_token, dev_token, target, robots
):
    """Discovery must not disturb SQLi/XSS/header/cookie detection."""
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_ok.xml\n")
    pid = _profile(
        client, admin_token, "Regression discovery profile", max_pages=15,
        max_depth=2,
        module_keys=("sqli", "xss", "http_headers", "cookies"),
    )
    detail = _scan(client, dev_token, TARGET_URL, pid)

    names = {finding["VulnerabilityName"] for finding in detail["Findings"]}
    assert "SQL Injection" in names
    assert "Cross-Site Scripting (XSS)" in names
    assert "Missing HTTP Security Headers" in names
    assert "Insecure Cookie Attributes" in names
    # Sitemap-discovered pages were analysed, not merely stored.
    assert detail["AnalysedPages"] == detail["PageCount"]


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
def test_csv_report_describes_page_discovery(
    client, admin_token, dev_token, target, robots
):
    import csv
    import io

    robots(
        "User-agent: *\n"
        "Disallow: /t/private\n"
        f"Sitemap: {TARGET_URL}t/sitemap_private.xml\n"
    )
    pid = _profile(client, admin_token, "Discovery CSV profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    scan_id = detail["ScanID"]
    resp = client.get(f"/api/scans/{scan_id}/report?format=csv",
                      headers=auth(dev_token))
    assert resp.status_code == 200
    text = resp.data.decode("utf-8-sig")
    rows = list(csv.reader(io.StringIO(text)))
    values = {r[0]: r[1] for r in rows if len(r) == 2}

    discovery = detail["Coverage"]["Discovery"]
    assert values["Sitemap URLs"] == str(discovery["Sources"]["Sitemaps"])
    assert values["robots.txt URLs Excluded"] == "1"
    assert values["robots.txt Consulted"] == "True"
    assert "PAGE DISCOVERY" in [r[0] for r in rows if r]


def test_pdf_report_includes_page_discovery(client, admin_token, dev_token,
                                            target, robots):
    """The PDF must actually render the discovery facts, not just build."""
    robots(f"User-agent: *\nSitemap: {TARGET_URL}t/sitemap_ok.xml\n")
    pid = _profile(client, admin_token, "Discovery PDF profile")
    detail = _scan(client, dev_token, TARGET_URL, pid)

    resp = client.get(f"/api/scans/{detail['ScanID']}/report?format=pdf",
                      headers=auth(dev_token))
    assert resp.status_code == 200
    assert resp.data[:4] == b"%PDF"

    document = _pdf.open(stream=resp.data, filetype="pdf")
    try:
        text = "\n".join(page.get_text() for page in document)
    finally:
        document.close()
    assert "Page discovery" in text
    assert "sitemap URL(s)" in text
    assert "robots.txt" in text
