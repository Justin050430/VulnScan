"""
HTTP Security Header analysis module (Security Misconfiguration).

Sends a request to the page and verifies that recommended HTTP security
headers are present *and* configured with secure values.  This matches the
documented OWASP category, which covers headers that are "missing or
improperly configured".

Examples of insecure configurations detected:
  * X-Frame-Options with a value other than DENY/SAMEORIGIN
  * X-Content-Type-Options not set to nosniff
  * Referrer-Policy set to an unsafe value (e.g. unsafe-url)
  * Strict-Transport-Security without a positive max-age
"""
import logging
from urllib.parse import urlparse

from app.scanner.base import DetectionModule
from app.utils.constants import NAME_MISSING_SECURITY_HEADERS

logger = logging.getLogger("vulnscan.headers")

# CVSS v3.1 base vector for insecure security-header configuration
# (5.4 Medium): no privileges required, user interaction required, partial
# confidentiality/integrity impact (e.g. clickjacking, MIME sniffing).
CVSS_MISSING_HEADERS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"

SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "origin",
    "origin-when-cross-origin",
}


def _valid_frame_options(value):
    return value.strip().upper() in ("DENY", "SAMEORIGIN")


def _valid_content_type_options(value):
    return value.strip().lower() == "nosniff"


def _valid_referrer_policy(value):
    first = value.split(",")[0].strip().lower()
    return first in SAFE_REFERRER_POLICIES


def _valid_hsts(value):
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1].strip()) > 0
            except ValueError:
                return False
    return False


# name, insecure-value check (None = presence required only), explanation, guidance
HEADER_RULES = [
    (
        "Content-Security-Policy",
        None,
        "Content Security Policy (CSP) is missing, increasing the risk of "
        "cross-site scripting and content injection.",
        "Set a Content-Security-Policy header (e.g. default-src 'self').",
    ),
    (
        "X-Frame-Options",
        _valid_frame_options,
        "X-Frame-Options is missing or not set to DENY/SAMEORIGIN, allowing the "
        "page to be framed by other sites (clickjacking).",
        "Set X-Frame-Options: DENY (or SAMEORIGIN), or use CSP frame-ancestors.",
    ),
    (
        "X-Content-Type-Options",
        _valid_content_type_options,
        "X-Content-Type-Options is missing or not set to 'nosniff', allowing "
        "MIME-type sniffing.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    (
        "Referrer-Policy",
        _valid_referrer_policy,
        "Referrer-Policy is missing or set to an unsafe value; the Referer "
        "header may leak URL data.",
        "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
    ),
    (
        "Strict-Transport-Security",
        _valid_hsts,
        "HTTP Strict Transport Security (HSTS) is missing or has no positive "
        "max-age on an HTTPS page.",
        "Set Strict-Transport-Security: max-age=31536000; includeSubDomains.",
    ),
    (
        "Permissions-Policy",
        None,
        "Permissions-Policy is missing, so browser features are not restricted.",
        "Set a Permissions-Policy header that disables unused features.",
    ),
]


class HTTPHeaderModule(DetectionModule):
    key = "http_headers"
    vulnerability_name = NAME_MISSING_SECURITY_HEADERS

    def detect(self):
        response = self.http.get(self.page.url)
        if not response.ok:
            return []
        headers = {k.lower(): v for k, v in response.headers.items()}
        is_https = urlparse(response.final_url or self.page.url).scheme == "https"

        missing = []
        misconfigured = []
        for name, value_check, explanation, guidance in HEADER_RULES:
            if name == "Strict-Transport-Security" and not is_https:
                continue
            value = headers.get(name.lower())
            if value is None:
                missing.append((name, explanation, guidance))
            elif value_check is not None and not value_check(value):
                misconfigured.append((name, value, explanation, guidance))

        if not missing and not misconfigured:
            return []

        lines = ""
        if missing:
            lines += "Missing headers:\n" + "".join(
                f"- {name}: {reason}\n" for name, reason, _ in missing)
        if misconfigured:
            lines += "Improperly configured headers:\n" + "".join(
                f"- {name}: value {value!r} - {reason}\n"
                for name, value, reason, _ in misconfigured)

        guidance_lines = "".join(
            f"- {name}: {guide}\n" for name, _, guide in missing)
        guidance_lines += "".join(
            f"- {name}: {guide}\n" for name, _, _, guide in misconfigured)

        evidence = (
            "CONFIRMED: the HTTP response for this page does not include all "
            "recommended security headers with secure values.\n" + lines
        )
        detail = (
            "Security misconfiguration: one or more recommended HTTP security "
            "headers are missing or improperly configured.\nSuggested fixes:\n"
            + guidance_lines
        )
        affected = [name for name, _, _ in missing] + [
            name for name, _, _, _ in misconfigured
        ]
        return [
            self._scored_result(
                CVSS_MISSING_HEADERS,
                0.95,
                evidence=evidence,
                detail=detail,
                parameter="HTTP Response Headers",
                payload=",".join(affected),
            )
        ]
