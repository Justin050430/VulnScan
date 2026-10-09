"""
VulnScan controlled vulnerable test application.

This local application is an INTENTIONALLY INSECURE web app used ONLY to
validate the VulnScan scanner engine against a target we control.  It must
never be deployed or exposed to the internet.

Vulnerabilities (documented VulnScan scope):
  * /search        - reflected Cross-Site Scripting (unsafe echo)
  * /product?id=   - SQL Injection (simulated DB error + boolean behaviour)
  * /             - pages served without security headers
Control pages (no vulnerability) are provided too so tests can confirm the
scanner does not raise false positives:
  * /safe_search   - safely escaped echo
  * /headers_ok    - all recommended security headers present
"""
from flask import Flask, Response, request

app = Flask(__name__)

HOME = """
<!doctype html><html><head><title>VulnScan Test Shop</title></head><body>
<h1>Welcome to the VulnScan Test Shop</h1>
<ul>
  <li><a href="/">Home</a></li>
  <li><a href="/search?q=laptop">Search products</a></li>
  <li><a href="/safe_search?q=laptop">Search (safe)</a></li>
  <li><a href="/product?id=1">Product 1</a></li>
  <li><a href="/product?id=2">Product 2</a></li>
  <li><a href="/blind?id=1">Product lookup</a></li>
  <li><a href="/boolean_safe?id=1">Product lookup (safe)</a></li>
  <li><a href="/about">About us</a></li>
  <li><a href="/headers_ok">Header-safe page</a></li>
</ul>
</body></html>
"""

EXTERNAL_PAGE = """
<!doctype html><html><head><title>Links</title></head><body>
<h1>Useful links</h1>
<a href="/">Home</a>
<a href="EXTERNAL_URL">External partner site</a>
</body></html>
"""


@app.route("/")
def home():
    return HOME


@app.route("/about")
def about():
    return "<!doctype html><html><head><title>About</title></head><body><h1>About</h1></body></html>"


@app.route("/search")
def search():
    """Reflected XSS: echoes the raw query parameter into the page."""
    q = request.args.get("q", "")
    return (
        "<!doctype html><html><head><title>Search</title></head><body>"
        "<h1>Search results for:</h1>"
        f"<p>{q}</p>"
        "</body></html>"
    )


@app.route("/safe_search")
def safe_search():
    """Control page: safely escapes user input (no XSS)."""
    import html

    q = html.escape(request.args.get("q", ""), quote=True)
    return (
        "<!doctype html><html><head><title>Safe Search</title></head><body>"
        "<h1>Safe search results</h1>"
        f"<p>{q}</p>"
        "</body></html>"
    )


def _fake_query_products(condition_sql):
    """
    Simulates a SQL WHERE clause: when the injected boolean makes the clause
    true one product row is returned, otherwise none (blind SQLi behaviour).
    """
    return condition_sql  # for demonstration we mirror the "clause truthiness"


@app.route("/product")
def product():
    """SQL Injection: simulates a vulnerable numeric-id lookup."""
    raw_id = request.args.get("id", "")

    # Simulated DB error when an unsafe quote/breakout reaches the query.
    if "'" in raw_id or '"' in raw_id or "--" in raw_id or ";" in raw_id:
        return (
            "<!doctype html><html><head><title>Product - Error</title></head><body>"
            "<h1>Database error</h1>"
            "<p>Unclosed quotation mark before the character string '1''. "
            "Incorrect syntax near '1'.</p>"
            "</body></html>",
            500,
        )

    # Boolean-based: emulate different row counts for true/false conditions.
    if raw_id.isdigit() and int(raw_id) in (1, 2):
        return (
            "<!doctype html><html><head><title>Product 1</title></head><body>"
            "<h1>Product found</h1><p>Wireless Mouse - $29</p></body></html>"
        )
    return (
        "<!doctype html><html><head><title>Product - Not found</title></head><body>"
        "<h1>No product</h1></body></html>",
        404,
    )


@app.route("/headers_ok")
def headers_ok():
    """Control page that sets all recommended security headers."""
    html = (
        "<!doctype html><html><head><title>Secure page</title></head><body>"
        "<h1>Secure headers page</h1></body></html>"
    )
    resp = Response(html)
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    return resp


@app.route("/boolean_safe")
def boolean_safe():
    """Control page: reflects input safely and never changes with SQL logic."""
    import html as _html

    idv = _html.escape(request.args.get("id", ""), quote=True)
    return (
        "<!doctype html><html><head><title>Static lookup</title></head><body>"
        "<h1>Static results</h1>"
        f"<p>Query: {idv}</p>"
        "</body></html>"
    )


@app.route("/blind")
def blind():
    """
    Blind (boolean-based) SQL Injection simulation.

    The id parameter is echoed into the page. A logically-true SQL condition
    returns the 'product found' page while a false condition returns an empty
    result page - no database error is produced, so only a differential
    (blind) technique can detect it.
    """
    idv = request.args.get("id", "")
    lowered = idv.lower()
    if "and '1'='2" in lowered:
        rows = 0
    elif "and '1'='1" in lowered:
        rows = 1
    else:
        rows = 1 if idv.isdigit() else 0

    if rows:
        body = "<h1>Product found</h1><p>Wireless Mouse - $29</p>"
    else:
        body = "<h1>No products found</h1><p>Please try another product.</p>"
    return (
        "<!doctype html><html><head><title>Product lookup</title></head><body>"
        f"{body}"
        f"<p>Query: {idv}</p>"
        "</body></html>"
    )


def _html_escape(value):
    import html as _html

    return _html.escape(value, quote=True)


_FLAKY_ERROR_STATE = {"consumed": False}


@app.route("/flaky_error")
def flaky_error():
    """
    Control page for the SQLi repeat-confirmation logic: the first request
    whose input contains a SQL metacharacter returns a database error once;
    repeated identical requests return a normal page, simulating a transient
    error page that must NOT be reported as confirmed evidence.
    """
    idv = request.args.get("id", "")
    has_metachar = ("'" in idv) or ('"' in idv) or ("--" in idv) or (";" in idv)
    if has_metachar and not _FLAKY_ERROR_STATE["consumed"]:
        _FLAKY_ERROR_STATE["consumed"] = True
        return (
            "<!doctype html><html><head><title>Server error</title></head><body>"
            "<h1>Application error</h1>"
            "<p>Incorrect syntax near '1'.</p>"
            "</body></html>",
            500,
        )
    safe = _html_escape(idv)
    return (
        "<!doctype html><html><head><title>Item lookup</title></head><body>"
        f"<h1>Item lookup</h1><p>Item: {safe}</p>"
        "</body></html>"
    )


@app.route("/error_cond")
def error_cond():
    """
    Conditional-error SQLi control: the response fails with a database error
    ONLY when the injected CASE condition is true (simulates a DB engine
    evaluating attacker-controlled SQL logic).
    """
    idv = request.args.get("id", "")
    if "and 1=case when 1=1 then 1/0" in idv.lower():
        return (
            "<!doctype html><html><head><title>Server error</title></head><body>"
            "<h1>Application error</h1>"
            "<p>Divide by zero error encountered.</p>"
            "</body></html>",
            500,
        )
    safe = _html_escape(idv)
    return (
        "<!doctype html><html><head><title>Item lookup</title></head><body>"
        f"<h1>Item lookup</h1><p>Query: {safe}</p>"
        "</body></html>"
    )


@app.route("/attr_reflect")
def attr_reflect():
    """Reflected XSS: raw echo inside a double-quoted attribute value."""
    q = request.args.get("q", "")
    return (
        "<!doctype html><html><head><title>Attribute reflection</title></head>"
        "<body><h1>Profile</h1>"
        f'<input type="text" name="nickname" value="{q}">'
        "</body></html>"
    )


@app.route("/attr_safe")
def attr_safe():
    """Control page: attribute value safely encoded (no XSS)."""
    q = _html_escape(request.args.get("q", ""))
    return (
        "<!doctype html><html><head><title>Attribute reflection</title></head>"
        "<body><h1>Profile</h1>"
        f'<input type="text" name="nickname" value="{q}">'
        "</body></html>"
    )


@app.route("/attr_events")
def attr_events():
    """
    Reflected XSS with angle brackets encoded but quotes raw: the
    attribute-injection / event-handler payload path must still be detected.
    """
    q = request.args.get("q", "")
    encoded = q.replace("<", "&lt;").replace(">", "&gt;")
    return (
        "<!doctype html><html><head><title>Attribute reflection</title></head>"
        "<body><h1>Profile</h1>"
        f'<input type="text" name="nickname" value="{encoded}">'
        "</body></html>"
    )


@app.route("/script_reflect")
def script_reflect():
    """Reflected XSS: raw echo inside a <script> string literal."""
    q = request.args.get("q", "")
    return (
        "<!doctype html><html><head><title>Script reflection</title></head>"
        "<body><h1>Greeting</h1>"
        f"<script>var greeting = \"{q}\";</script>"
        "</body></html>"
    )


@app.route("/csp_weak")
def csp_weak():
    """CSP present but weak (unsafe-inline + wildcard); other headers secure."""
    html = (
        "<!doctype html><html><head><title>Weak CSP</title></head><body>"
        "<h1>Weak CSP page</h1></body></html>"
    )
    resp = Response(html)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'unsafe-inline' *"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=()"
    return resp


@app.route("/frame_ok")
def frame_ok():
    """Framing protection via CSP frame-ancestors (no X-Frame-Options)."""
    html = (
        "<!doctype html><html><head><title>Frame protected</title></head><body>"
        "<h1>Frame protected page</h1></body></html>"
    )
    resp = Response(html)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=()"
    return resp


@app.route("/external-link")
def external_link():
    """Page containing a link to an out-of-scope host (scope test)."""
    import os

    external = os.environ.get("VULN_TEST_EXTERNAL_URL", "http://127.0.0.1:5198/")
    return EXTERNAL_PAGE.replace("EXTERNAL_URL", external)


@app.route("/redirect-external")
def redirect_external():
    """Redirects to an out-of-scope host (redirect SSRF/scope test)."""
    import os

    external = os.environ.get("VULN_TEST_EXTERNAL_URL", "http://127.0.0.1:5198/")
    return Response(status=302, headers={"Location": external})


@app.route("/many")
def many():
    """Page with many same-site links (crawl page-limit test)."""
    try:
        n = min(int(request.args.get("n", "25")), 200)
    except ValueError:
        n = 25
    links = "".join(f'<a href="/about?i={i}">item {i}</a> ' for i in range(1, n + 1))
    return (
        "<!doctype html><html><head><title>Many links</title></head><body>"
        f"<h1>Link farm</h1>{links}</body></html>"
    )


@app.route("/slow")
def slow():
    """Deliberately slow page (scanner timeout-handling test)."""
    import time

    time.sleep(2)
    return "<!doctype html><html><head><title>Slow</title></head><body>slow</body></html>"


@app.route("/docs")
def docs():
    """
    Control page whose normal content already contains SQL-error-like text and
    which safely escapes the query parameter.  The Sqli module must NOT report
    a finding here because the signature is present in the baseline response.
    """
    import html as _html

    q = _html.escape(request.args.get("q", ""), quote=True)
    return (
        "<!doctype html><html><head><title>Database documentation</title></head><body>"
        "<h1>Troubleshooting</h1>"
        "<p>Common error reference: Incorrect syntax near 'x'; "
        "Unclosed quotation mark after the character string.</p>"
        f"<p>Search: {q}</p>"
        "</body></html>"
    )


@app.route("/comment_reflect")
def comment_reflect():
    """Reflects input un-encoded but inside an HTML comment (not executable)."""
    q = request.args.get("q", "")
    return (
        "<!doctype html><html><head><title>Comment</title></head><body>"
        f"<!-- user note: {q} -->"
        "<p>Comment stored.</p></body></html>"
    )


@app.route("/textarea_reflect")
def textarea_reflect():
    """Reflects input un-encoded but inside a <textarea> (not executable)."""
    q = request.args.get("q", "")
    return (
        "<!doctype html><html><head><title>Textarea</title></head><body>"
        f"<textarea name=\"note\">{q}</textarea>"
        "</body></html>"
    )


@app.route("/weak_headers")
def weak_headers():
    """Headers present but configured with insecure values."""
    html = (
        "<!doctype html><html><head><title>Weak headers</title></head><body>"
        "<h1>Weak configuration</h1></body></html>"
    )
    resp = Response(html)
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "ALLOWALL"
    resp.headers["X-Content-Type-Options"] = "sniff"
    resp.headers["Referrer-Policy"] = "unsafe-url"
    resp.headers["Permissions-Policy"] = "geolocation=()"
    return resp


@app.route("/malformed")
def malformed():
    """Malformed/truncated HTML and mismatched tags (parser robustness)."""
    return (
        "<html><body><div><a href='/about'>unclosed "
        "<script>var x = '<not closed>'",
        200,
        {"Content-Type": "text/html"},
    )


@app.route("/binary")
def binary():
    """Non-HTML binary response (must be skipped safely)."""
    return Response(b"\x00\x01\x02\x03\xff\xfe", mimetype="application/octet-stream")


@app.after_request
def add_csp_on_home(response):
    return response


if __name__ == "__main__":
    # Local only - for validating the VulnScan scanner.
    print("Starting VulnScan vulnerable test app on http://127.0.0.1:5001")
    app.run(host="127.0.0.1", port=5001, debug=False)
