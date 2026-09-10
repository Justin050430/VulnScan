"""
Response comparison helpers used by differential (blind) detection.

Comparison is content-based (token-set Jaccard similarity) rather than a
naive response-length check, and injected payload reflections are masked out
first so that a page which merely echoes the payload is not mistaken for a
differential vulnerability.
"""
import html
import re
from urllib.parse import quote, quote_plus

_TAG_RE = re.compile(r"<[^>]+>")
_TOKEN_RE = re.compile(r"[a-z0-9_]+")


def mask_reflection(body, payload):
    """Remove echoed copies of the injected payload from a response body."""
    if not body:
        return ""
    variants = {
        payload,
        html.escape(payload, quote=True),
        html.escape(payload, quote=False),
        quote(payload, safe=""),
        quote_plus(payload, safe=""),
    }
    masked = body
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            masked = masked.replace(variant, "§INJECT§")
    # Also mask a bare fragment occurring in attributes/quotes.
    escaped_quotes = payload.replace("'", "")
    if escaped_quotes and escaped_quotes != payload:
        masked = masked.replace(escaped_quotes, "§INJECT§")
    return masked


def _tokens(body):
    text = _TAG_RE.sub(" ", body or "").lower()
    return set(_TOKEN_RE.findall(text))


# Elements whose text content is not rendered as markup (reflection inside
# them cannot execute, even if returned unencoded).
_NON_EXECUTABLE_ELEMENTS = ("textarea", "title", "xmp", "noscript", "template")


def is_executable_reflection(body, payload):
    """
    Return True only when the reflected payload sits in an executable HTML
    context.  Un-encoded reflection inside an HTML comment, <textarea>,
    <title>, <xmp>, <noscript> or <template> is not executable and must not
    be reported as reflected XSS.
    """
    if not body or not payload:
        return False
    index = body.find(payload)
    if index == -1:
        return False
    before = body[:index]
    lowered = before.lower()

    # HTML comment context: <!-- ... payload ...
    if before.rfind("<!--") > before.rfind("-->"):
        return False
    # Raw-text / non-rendered element context.
    for tag in _NON_EXECUTABLE_ELEMENTS:
        if lowered.rfind(f"<{tag}") > lowered.rfind(f"</{tag}"):
            return False
    return True


def token_similarity(body_a, body_b):
    """Jaccard similarity of the token sets of two response bodies (0..1)."""
    ta, tb = _tokens(body_a), _tokens(body_b)
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)
