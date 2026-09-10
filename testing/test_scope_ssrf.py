"""
Scanner scope, SSRF protection and crawl-limit tests.

All hosts are local (127.0.0.1); no public site is ever contacted.
"""
from conftest import auth, EXTERNAL_URL, TARGET_URL


def _admin_profile(client, admin_token, name, *, max_pages=10, max_depth=1,
                   module_keys=("http_headers",)):
    """Create a scan profile using the requested implemented modules."""
    vulns = client.get("/api/vulnerabilities", headers=auth(admin_token),
                       query_string={"include_disabled": "true"}).get_json()["Vulnerabilities"]
    ids = [v["VulnerabilityID"] for v in vulns if v["ModuleKey"] in module_keys]
    resp = client.post("/api/scan-profiles", headers=auth(admin_token), json={
        "name": name, "max_depth": max_depth, "max_pages": max_pages,
        "request_delay_ms": 0, "follow_external": False, "module_vuln_ids": ids})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()["ScanProfile"]["ScanProfileID"]


def _scan(client, token, target_url, profile_id, name):
    resp = client.post("/api/scans", headers=auth(token), json={
        "target_url": target_url, "scan_profile_id": profile_id, "scan_name": name})
    assert resp.status_code == 202, resp.get_json()
    scan_id = resp.get_json()["Scan"]["ScanID"]
    return client.get(f"/api/scans/{scan_id}", headers=auth(token)).get_json()["Scan"]


# --------------------------------------------------------------------------
# SSRF protection
# --------------------------------------------------------------------------
def test_private_target_blocked_when_disabled(app, client, dev_token, target):
    app.config["SCANNER_ALLOW_PRIVATE_TARGETS"] = False
    try:
        resp = client.post("/api/scans", headers=auth(dev_token), json={
            "target_url": TARGET_URL, "scan_profile_id": 1})
        assert resp.status_code == 400
        assert "private" in resp.get_json()["message"].lower() \
            or "loopback" in resp.get_json()["message"].lower()
    finally:
        app.config["SCANNER_ALLOW_PRIVATE_TARGETS"] = True


def test_private_target_allowed_when_enabled(client, dev_token, target):
    # default test config allows local targets (needed for local scanning)
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": TARGET_URL, "scan_profile_id": 1})
    assert resp.status_code == 202


# --------------------------------------------------------------------------
# Scope enforcement
# --------------------------------------------------------------------------
def test_external_links_are_not_crawled(client, admin_token, dev_token, external_server, target):
    before = external_server["count"]
    pid = _admin_profile(client, admin_token, "Scope Test Profile")
    detail = _scan(client, dev_token, TARGET_URL + "external-link", pid, "Scope test")
    assert detail["Status"] == "Completed"
    # the out-of-scope host must never have been requested
    assert external_server["count"] == before
    # only same-origin pages were recorded
    assert all(p["URL"].startswith(TARGET_URL) for p in detail["Pages"])


def test_redirect_to_out_of_scope_is_blocked(client, admin_token, dev_token, external_server, target):
    before = external_server["count"]
    pid = _admin_profile(client, admin_token, "Redirect Test Profile")
    detail = _scan(client, dev_token, TARGET_URL + "redirect-external", pid,
                   "Redirect test")
    assert detail["Status"] == "Completed"
    assert external_server["count"] == before
    # the redirect must not have produced findings from the external host
    assert all(f["URL"].startswith(TARGET_URL) for f in detail["Findings"])


# --------------------------------------------------------------------------
# Crawl limits
# --------------------------------------------------------------------------
def test_max_pages_limit_enforced(client, admin_token, dev_token, target):
    pid = _admin_profile(client, admin_token, "Page Limit Profile", max_pages=3, max_depth=2)
    detail = _scan(client, dev_token, TARGET_URL + "many?n=40", pid, "Page limit")
    assert detail["PageCount"] <= 3
    assert detail["PageCount"] >= 1


def test_max_depth_limit_enforced(client, admin_token, dev_token, target):
    pid = _admin_profile(client, admin_token, "Depth Limit Profile", max_pages=30, max_depth=0)
    detail = _scan(client, dev_token, TARGET_URL + "many?n=40", pid, "Depth limit")
    assert detail["PageCount"] == 1


def test_request_limits_media_type_skip_is_safe(client, admin_token, dev_token, target):
    """Static resources must not be queued as scannable pages."""
    pid = _admin_profile(client, admin_token, "Static Skip Profile", max_pages=30, max_depth=2)
    detail = _scan(client, dev_token, TARGET_URL, pid, "Static skip")
    paths = [p["URL"] for p in detail["Pages"]]
    for suffix in (".css", ".js", ".png", ".jpg", ".ico"):
        assert not any(u.endswith(suffix) for u in paths)


# --------------------------------------------------------------------------
# Scope / SSRF unit checks (no network required)
# --------------------------------------------------------------------------
def test_hostname_resolving_to_loopback_is_blocked(monkeypatch):
    import socket

    from app.scanner.safety import check_target_allowed

    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))])
    ok, reason = check_target_allowed("http://internal.example.com/", allow_private=False)
    assert not ok
    assert reason


def test_public_hostname_allowed_when_private_disabled(monkeypatch):
    import socket

    from app.scanner.safety import check_target_allowed

    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    ok, _ = check_target_allowed("http://public.example.com/", allow_private=False)
    assert ok


def test_scope_unit_rules():
    from urllib.parse import urlparse

    from app.scanner.crawler import Crawler

    crawler = Crawler(follow_external=False)
    base = urlparse("http://127.0.0.1:5199/")
    assert crawler.in_scope("http://127.0.0.1:5199/about", base)
    assert crawler.in_scope("HTTP://127.0.0.1:5199/ABOUT", base)  # host case-insensitive
    assert not crawler.in_scope("http://127.0.0.1:5198/", base)   # different port
    assert not crawler.in_scope("https://evil.example.com/", base)
    assert not crawler.in_scope("ftp://127.0.0.1:5199/", base)    # non-HTTP scheme
    assert not crawler.in_scope("http://sub.example.test/", urlparse("http://example.test/"))
    assert not crawler.in_scope("http://example.test:8080/", urlparse("http://example.test/"))
