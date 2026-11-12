"""
Scanner robustness tests: timeout handling, form safety policy and protection
against false positives on pages that legitimately contain SQL-error-like text.
"""
from conftest import auth
from app.scanner.forms import parse_forms


def _headers_profile(client, token):
    profiles = client.get("/api/scan-profiles", headers=auth(token)).get_json()["ScanProfiles"]
    return next(p for p in profiles if p["Name"] == "OWASP Top 10 Full Scan")["ScanProfileID"]


def test_slow_target_times_out_and_fails_gracefully(app, client, dev_token, target):
    """A target that exceeds the timeout must not hang the scanner."""
    app.config["SCANNER_DEFAULT_TIMEOUT"] = 0.5
    try:
        pid = _headers_profile(client, dev_token)
        resp = client.post("/api/scans", headers=auth(dev_token), json={
            "target_url": target + "slow", "scan_profile_id": pid,
            "scan_name": "Timeout scan"})
        assert resp.status_code == 202
        scan_id = resp.get_json()["Scan"]["ScanID"]
        detail = client.get(f"/api/scans/{scan_id}", headers=auth(dev_token)).get_json()["Scan"]
        # The unreachable/slow start page means the scan cannot proceed.
        assert detail["Status"] == "Failed"
        assert detail["FinishedAt"] is not None
    finally:
        app.config["SCANNER_DEFAULT_TIMEOUT"] = 10


def test_sql_like_text_in_normal_page_is_not_reported(client, dev_token, target):
    """
    A page containing SQL-error-like text as ordinary content must NOT produce
    an SQL Injection finding (the signature is present in the baseline).
    """
    pid = _headers_profile(client, dev_token)
    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target + "docs?q=test", "scan_profile_id": pid,
        "scan_name": "SQL text control"})
    scan_id = resp.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}", headers=auth(dev_token)).get_json()["Scan"]

    sqli = [f for f in detail["Findings"] if f["VulnerabilityName"] == "SQL Injection"]
    assert not sqli, "page with SQL-like text wrongly flagged as SQL injection"


# --------------------------------------------------------------------------
# Form discovery safety policy (app/scanner/forms.py)
# --------------------------------------------------------------------------
def test_form_parser_keeps_state_but_skips_unsafe_forms():
    html = """
    <form method="post" action="/login">
      <input type="email" name="email">
      <input type="password" name="password">
    </form>
    <form method="post" action="/account/delete">
      <input type="text" name="reason" value="">
    </form>
    <form method="dialog"><input type="text" name="ignored"></form>
    <form method="post" action="/save">
      <input type="hidden" name="csrf" value="tok123">
      <input type="text" name="comment" value="hi">
      <select name="rating"><option value="">-</option><option>5</option></select>
      <button type="submit" name="action" value="save">Save</button>
    </form>
    """
    forms = parse_forms("http://example.test/page", html)
    assert len(forms) == 1, [form.action for form in forms]
    form = forms[0]
    assert form.action == "http://example.test/save"
    assert form.method == "POST"
    # Hidden and submit controls are submitted but never injected into.
    assert [c.name for c in form.injectable_controls] == ["comment", "rating"]
    assert form.data() == {
        "csrf": "tok123", "comment": "hi", "rating": "", "action": "save",
    }
    assert form.data_with("comment", "x' OR '1'='1")["csrf"] == "tok123"


def test_form_parser_skips_forms_without_injectable_fields():
    html = (
        '<form method="post" action="/go">'
        '<input type="hidden" name="id" value="1">'
        '<input type="submit" name="go" value="Go">'
        "</form>"
    )
    assert parse_forms("http://example.test/page", html) == ()


def test_form_parser_handles_empty_and_malformed_html():
    assert parse_forms("http://example.test/page", "") == ()
    assert parse_forms("http://example.test/page", "<form method=post>") == ()


def test_crawler_deduplicates_site_wide_forms():
    """The same form on many pages must only be tested once per scan."""
    from app.scanner.crawler import Crawler

    html = (
        '<form method="post" action="/search">'
        '<input type="text" name="q" value=""></form>'
    )
    crawler = Crawler(follow_external=False)
    first_page = crawler.dedupe_forms(parse_forms("http://example.test/a", html))
    second_page = crawler.dedupe_forms(parse_forms("http://example.test/b", html))
    assert len(first_page) == 1
    assert second_page == ()
