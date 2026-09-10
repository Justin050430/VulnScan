"""
Reflected Cross-Site Scripting (XSS) detection module.

For each query-string parameter the module injects XSS payloads and checks
whether the payload is echoed back into an HTML response without being encoded.
"""
import logging
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.scanner.base import DetectionModule
from app.scanner.similarity import is_executable_reflection
from app.utils.constants import NAME_CROSS_SITE_SCRIPTING

logger = logging.getLogger("vulnscan.xss")

# CVSS v3.1 base vector for reflected XSS (6.1 Medium).
CVSS_XSS_REFLECTED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

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
        for payload in PAYLOADS:
            response = self.http.get(self._build_url(param_name, payload))
            if not response.ok:
                continue
            content_type = (response.headers.get("Content-Type") or "").lower()
            if not any(m in content_type for m in HTML_CONTEXT_MARKERS):
                continue
            body = response.text or ""
            # Only a byte-for-byte echo of the raw payload in an executable HTML
            # context proves reflected XSS; escaped output would contain
            # &lt; / &gt; entities and reflections inside comments or
            # <textarea>/<title> cannot execute.
            if MARKER in body and payload in body and is_executable_reflection(body, payload):
                evidence = (
                    f"CONFIRMED: the raw XSS payload {payload!r} was reflected "
                    f"byte-for-byte (unencoded) in the HTML response for parameter "
                    f"'{param_name}'."
                )
                return self._scored_result(
                    CVSS_XSS_REFLECTED,
                    0.92,
                    parameter=param_name,
                    payload=payload,
                    evidence=evidence,
                    detail="Reflected cross-site scripting detected: "
                           "attacker-controlled input is echoed without "
                           "output encoding.",
                )
        return None

    def _build_url(self, param_name, new_value):
        parsed = urlparse(self.page.url)
        query = urlencode(
            [(k, v) if k != param_name else (k, new_value)
             for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
        )
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, "")
        )
