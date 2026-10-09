"""
Reflected Cross-Site Scripting (XSS) detection module.

For each query-string parameter the module injects structurally active XSS
payloads and checks whether the payload is echoed back *byte-for-byte* into an
HTML response (i.e. no HTML-encoding was applied).  Reflection alone is not
enough: the payload must land in a context the browser parses as markup, an
executable attribute or a script breakout - see
`app.scanner.html_context.classify_reflection`.  A raw reflection inside a
<script> block that cannot be shown to break out is reported as SUSPECTED.
"""
import logging
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.scanner.base import DetectionModule
from app.scanner.html_context import classify_reflection
from app.utils.constants import NAME_CROSS_SITE_SCRIPTING

logger = logging.getLogger("vulnscan.xss")

# CVSS v3.1 base vector for reflected XSS (6.1 Medium).
CVSS_XSS_REFLECTED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

TECHNIQUE_CONFIRMED = (
    "reflected payload in executable HTML context (byte-for-byte, unencoded)"
)
TECHNIQUE_SUSPECTED = "reflected payload in <script> context (breakout not proven)"

REFERENCES = (
    "OWASP XSS Prevention Cheat Sheet "
    "(https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html); "
    "PortSwigger - Cross-site scripting contexts "
    "(https://portswigger.net/web-security/cross-site-scripting/contexts)"
)

# A distinctive marker used to reliably detect reflection.
MARKER = "vulnscan_xss_7f3a9c"
# Only structurally active payloads are used. A bare javascript: token
# reflected as plain text is not exploitable, so it is intentionally omitted
# to avoid false positives.
PAYLOADS = [
    f"<script>{MARKER}</script>",
    f"<img src=x onerror={MARKER}>",
    f"<svg/onload={MARKER}>",
    f"<body onload={MARKER}>",
    f"<iframe src=javascript:{MARKER}>",
    f"\"'><script>{MARKER}</script>",
    f"\" autofocus onfocus={MARKER} x=\"",
    f"' autofocus onfocus={MARKER} x='",
    f"</script><svg onload={MARKER}>",
]

HTML_CONTEXT_MARKERS = (
    "text/html",
)


class XSSModule(DetectionModule):
    key = "xss"
    vulnerability_name = NAME_CROSS_SITE_SCRIPTING

    def detect(self):
        results = []
        parameters = self.page.parameters
        if not parameters:
            return results

        for name in parameters:
            result = self._test_parameter(name)
            if result is not None:
                results.append(result)
        return results

    def _test_parameter(self, param_name):
        best_suspected = None
        for payload in PAYLOADS:
            response = self.http.get(self._build_url(param_name, payload))
            if not response.ok:
                continue
            content_type = (response.headers.get("Content-Type") or "").lower()
            if not any(m in content_type for m in HTML_CONTEXT_MARKERS):
                continue
            body = response.text or ""
            # Only a byte-for-byte echo of the raw payload is considered; the
            # reflection-context analysis then decides whether the browser
            # would parse it as markup (see html_context.classify_reflection).
            if MARKER not in body or payload not in body:
                continue
            ctx = classify_reflection(body, payload)
            if ctx is None:
                continue
            if ctx.executable:
                return self._confirmed_result(param_name, payload, body, ctx)
            if ctx.suspected and best_suspected is None:
                best_suspected = self._suspected_result(
                    param_name, payload, body, ctx
                )
        return best_suspected

    def _confirmed_result(self, param_name, payload, body, ctx):
        evidence = (
            f"CONFIRMED: the raw XSS payload {payload!r} was reflected "
            f"byte-for-byte (unencoded) in an executable HTML context for "
            f"parameter '{param_name}'."
        ) + "\n\n" + self._context_block(payload, body, ctx)
        return self._scored_result(
            CVSS_XSS_REFLECTED,
            0.92,
            parameter=param_name,
            payload=payload,
            technique=TECHNIQUE_CONFIRMED,
            evidence=evidence,
            detail=(
                "Reflected cross-site scripting detected: attacker-controlled "
                "input is echoed without output encoding into a context the "
                "browser parses as markup, so injected script can execute in "
                "the victim's browser."
            ),
        )

    def _suspected_result(self, param_name, payload, body, ctx):
        evidence = (
            f"SUSPECTED (script context): the raw XSS payload {payload!r} was "
            f"reflected byte-for-byte (unencoded) inside a <script> block for "
            f"parameter '{param_name}', but the response does not prove a "
            f"breakout from the surrounding JavaScript."
        ) + "\n\n" + self._context_block(payload, body, ctx)
        return self._scored_result(
            CVSS_XSS_REFLECTED,
            0.55,
            parameter=param_name,
            payload=payload,
            technique=TECHNIQUE_SUSPECTED,
            evidence=evidence,
            detail=(
                "Reflection inside a script block requires a JavaScript "
                "string/statement breakout to execute. Manual verification is "
                "recommended; the scanner does not analyse the surrounding "
                "JavaScript."
            ),
        )

    def _context_block(self, payload, body, ctx):
        index = body.find(payload)
        start = max(0, index - 60)
        end = min(len(body), index + len(payload) + 60)
        snippet = re.sub(r"\s+", " ", body[start:end]).strip()
        position = (
            "executable"
            if ctx.executable
            else ("unproven" if ctx.suspected else "not executable")
        )
        return "\n".join([
            f"REFLECTION CONTEXT: {ctx.description}",
            f"REFLECTION POSITION: {position}",
            "ENCODING: raw (payload echoed byte-for-byte; no HTML-encoding "
            "was applied)",
            f"EVIDENCE SNIPPET: ...{snippet}...",
            "WHY THIS DECISION: the payload was classified by parsing the "
            "response structure (tags, attribute values, raw-text blocks, "
            "comments), not by string matching alone.",
            "ALTERNATIVE EXPLANATIONS / LIMITATIONS: the analysis is static - "
            "no browser was launched, so a client-side control (sanitiser, "
            "WAF, CSP) could still block execution; stored and DOM-based XSS "
            "are out of scope.",
            "REMEDIATION: apply context-aware output encoding (HTML text, "
            "attribute and JavaScript contexts); treat untrusted input as "
            "data, never markup; consider a strict CSP as defence in depth.",
            f"REFERENCES: {REFERENCES}",
            "VERIFICATION: Not retested yet.",
        ])

    def _build_url(self, param_name, new_value):
        parsed = urlparse(self.page.url)
        query = urlencode(
            [(k, v) if k != param_name else (k, new_value)
             for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
        )
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, "")
        )
