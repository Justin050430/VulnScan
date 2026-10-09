"""
HTTP Security Header analysis module (Security Misconfiguration).

Sends a request to the page and evaluates the recommended HTTP security
headers against expected values and policy strength.  Findings are raised
per rule (one finding per failing header), each with its own CVSS v3.1
vector, structured evidence and remediation guidance.  This matches the
documented OWASP category, which covers headers that are "missing or
improperly configured".

Evaluation summary:
  * Content-Security-Policy   - missing, or present but weak (unsafe-inline /
                                unsafe-eval / wildcard or insecure sources)
  * X-Frame-Options           - missing or not DENY/SAMEORIGIN; suppressed
                                when the CSP defines frame-ancestors (the
                                modern equivalent, per OWASP)
  * X-Content-Type-Options    - missing or not nosniff
  * Referrer-Policy           - missing or an unsafe value
  * Strict-Transport-Security - HTTPS responses only; missing, without a
                                positive max-age, or below 6 months
  * Permissions-Policy        - missing (presence-only check)

The absence of a header alone does not prove exploitability - each rule's
evidence states the concern, the impact and the limitations.
"""
import logging
from urllib.parse import urlparse

from app.scanner.base import DetectionModule
from app.utils.constants import NAME_MISSING_SECURITY_HEADERS

logger = logging.getLogger("vulnscan.headers")

TECHNIQUE = "HTTP security header policy evaluation"

# CVSS v3.1 base vectors per rule (fixed, defensible per evidence class).
CVSS_CSP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"          # 5.4 Medium
CVSS_FRAMING = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"      # 4.3 Medium
CVSS_MIME = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"         # 4.3 Medium
CVSS_HSTS = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"         # 4.2 Medium
CVSS_PRIVACY = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"      # 3.1 Low

# HSTS policies shorter than 6 months are considered weak.
HSTS_MIN_MAX_AGE = 15768000

SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "origin",
    "origin-when-cross-origin",
}

# Per-rule metadata: vector, recommended configuration, concern, impact and
# authoritative references.
RULES = {
    "Content-Security-Policy": {
        "vector": CVSS_CSP,
        "recommended": "Content-Security-Policy: default-src 'self'",
        "concern": "a missing or weak CSP leaves no browser-enforced "
                   "restriction on where scripts may load from or whether "
                   "inline scripts may run.",
        "impact": "CSP is a defence-in-depth control: its absence or weakness "
                  "does not create a vulnerability by itself but removes a "
                  "mitigation layer for HTML-injection flaws.",
        "references": (
            "OWASP CSP Cheat Sheet "
            "(https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html); "
            "MDN Content-Security-Policy "
            "(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)"
        ),
    },
    "X-Frame-Options": {
        "vector": CVSS_FRAMING,
        "recommended": "X-Frame-Options: DENY (or CSP frame-ancestors 'none')",
        "concern": "the page can be embedded in a frame on another site, "
                   "enabling clickjacking.",
        "impact": "clickjacking requires user interaction and causes UI "
                  "redressing / limited integrity impact; this is a "
                  "defence-in-depth header.",
        "references": (
            "OWASP Clickjacking Defence Cheat Sheet "
            "(https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html); "
            "MDN X-Frame-Options "
            "(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)"
        ),
    },
    "X-Content-Type-Options": {
        "vector": CVSS_MIME,
        "recommended": "X-Content-Type-Options: nosniff",
        "concern": "browsers may MIME-sniff responses and interpret "
                   "non-script content as script.",
        "impact": "content sniffing exposure depends on the browser and the "
                  "content served; modern browsers treat this as a hardening "
                  "control.",
        "references": (
            "MDN X-Content-Type-Options "
            "(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)"
        ),
    },
    "Referrer-Policy": {
        "vector": CVSS_PRIVACY,
        "recommended": "Referrer-Policy: strict-origin-when-cross-origin",
        "concern": "full URLs (which may contain sensitive data) can leak to "
                   "other origins through the Referer header.",
        "impact": "this is an information-disclosure control with lower "
                  "severity than the other rules.",
        "references": (
            "MDN Referrer-Policy "
            "(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)"
        ),
    },
    "Strict-Transport-Security": {
        "vector": CVSS_HSTS,
        "recommended": ("Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains"),
        "concern": "without a strong HSTS policy, HTTPS users can be "
                   "downgraded to HTTP by a network attacker.",
        "impact": "HSTS applies only to HTTPS responses; a short max-age "
                  "reduces the protected window (6+ months recommended).",
        "references": (
            "OWASP HSTS Cheat Sheet "
            "(https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html); "
            "MDN Strict-Transport-Security "
            "(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)"
        ),
    },
    "Permissions-Policy": {
        "vector": CVSS_PRIVACY,
        "recommended": ("Permissions-Policy: geolocation=(), microphone=() "
                        "(disable unused features)"),
        "concern": "browser features (camera, geolocation, etc.) are not "
                   "restricted for the page and its embedded content.",
        "impact": "this is a hardening control; its absence alone does not "
                  "prove exploitability.",
        "references": (
            "MDN Permissions-Policy "
            "(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy)"
        ),
    },
}

_WEAK_CSP_SOURCES = ("unsafe-inline", "unsafe-eval")


def _parse_csp(value):
    """Parse a CSP header into {directive: [sources...]} (lower-cased)."""
    directives = {}
    for part in (value or "").split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives


def _csp_has_frame_ancestors(value):
    return "frame-ancestors" in _parse_csp(value)


def _csp_weakness(value):
    """Return a description of weak CSP directives, or None when acceptable."""
    directives = _parse_csp(value)
    reasons = []
    default_sources = directives.get("default-src", [])
    script_sources = directives.get("script-src", default_sources)
    for label, sources in (("default-src", default_sources),
                           ("script-src", script_sources)):
        if "unsafe-inline" in sources:
            reasons.append(f"{label} allows 'unsafe-inline' (inline scripts)")
        if "unsafe-eval" in sources:
            reasons.append(f"{label} allows 'unsafe-eval'")
        if "*" in sources or "http:" in sources:
            reasons.append(f"{label} allows wildcard or insecure sources")
    return "; ".join(dict.fromkeys(reasons)) if reasons else None


def _valid_frame_options(value):
    return value.strip().upper() in ("DENY", "SAMEORIGIN")


def _valid_content_type_options(value):
    return value.strip().lower() == "nosniff"


def _valid_referrer_policy(value):
    first = value.split(",")[0].strip().lower()
    return first in SAFE_REFERRER_POLICIES


def _hsts_max_age(value):
    """Return the HSTS max-age in seconds, or None when absent/invalid."""
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1].strip())
            except ValueError:
                return None
    return None


class HTTPHeaderModule(DetectionModule):
    key = "http_headers"
    vulnerability_name = NAME_MISSING_SECURITY_HEADERS

    def detect(self):
        response = self.http.get(self.page.url)
        if not response.ok:
            return []
        headers = {k.lower(): v for k, v in response.headers.items()}
        is_https = urlparse(response.final_url or self.page.url).scheme == "https"
        results = []

        # ---- Content-Security-Policy (missing or weak policy) ------------
        csp = headers.get("content-security-policy")
        frame_ancestors = _csp_has_frame_ancestors(csp)
        if csp is None:
            results.append(self._finding("Content-Security-Policy", None, "missing"))
        else:
            weakness = _csp_weakness(csp)
            if weakness:
                results.append(self._finding(
                    "Content-Security-Policy", csp, "weak", reason=weakness))

        # ---- X-Frame-Options (suppressed when CSP frame-ancestors set) ---
        xfo = headers.get("x-frame-options")
        if not frame_ancestors:
            if xfo is None:
                results.append(self._finding("X-Frame-Options", None, "missing"))
            elif not _valid_frame_options(xfo):
                results.append(self._finding("X-Frame-Options", xfo, "weak"))

        # ---- X-Content-Type-Options --------------------------------------
        xcto = headers.get("x-content-type-options")
        if xcto is None:
            results.append(self._finding(
                "X-Content-Type-Options", None, "missing"))
        elif not _valid_content_type_options(xcto):
            results.append(self._finding(
                "X-Content-Type-Options", xcto, "weak"))

        # ---- Referrer-Policy ---------------------------------------------
        referrer = headers.get("referrer-policy")
        if referrer is None:
            results.append(self._finding("Referrer-Policy", None, "missing"))
        elif not _valid_referrer_policy(referrer):
            results.append(self._finding("Referrer-Policy", referrer, "weak"))

        # ---- Strict-Transport-Security (HTTPS responses only) ------------
        if is_https:
            hsts = headers.get("strict-transport-security")
            if hsts is None:
                results.append(self._finding(
                    "Strict-Transport-Security", None, "missing"))
            else:
                max_age = _hsts_max_age(hsts)
                if max_age is None or max_age <= 0:
                    results.append(self._finding(
                        "Strict-Transport-Security", hsts, "weak",
                        reason="no positive max-age directive"))
                elif max_age < HSTS_MIN_MAX_AGE:
                    results.append(self._finding(
                        "Strict-Transport-Security", hsts, "weak",
                        reason=(f"max-age={max_age} is below the recommended "
                                f"6 months ({HSTS_MIN_MAX_AGE} seconds)")))

        # ---- Permissions-Policy (presence-only) --------------------------
        if headers.get("permissions-policy") is None:
            results.append(self._finding("Permissions-Policy", None, "missing"))

        return results

    # ---------------------------------------------------------------- helper
    def _finding(self, header, value, kind, reason=None):
        rule = RULES[header]
        if kind == "missing":
            verdict = (f"CONFIRMED: the '{header}' header is missing from the "
                       f"HTTP response for this page.")
            current = "not present"
        else:
            extra = f" ({reason})" if reason else ""
            verdict = (f"CONFIRMED: the '{header}' header is present but "
                       f"misconfigured{extra}; the current value is not a "
                       f"secure configuration.")
            current = value
        lines = [
            verdict,
            "",
            f"HEADER: {header}",
            f"CURRENT VALUE: {current}",
            f"RECOMMENDED: {rule['recommended']}",
        ]
        if header == "X-Frame-Options":
            lines.append(
                "NOTE: the CSP does not define frame-ancestors either, so the "
                "response has no framing protection at all."
            )
        lines += [
            f"SECURITY CONCERN: {rule['concern']}",
            f"IMPACT / LIMITATIONS: {rule['impact']}",
            f"REMEDIATION EXAMPLE: {rule['recommended']}",
            f"REFERENCES: {rule['references']}",
            "VERIFICATION: Not retested yet.",
        ]
        detail = (
            f"Security misconfiguration: the '{header}' header is missing or "
            f"improperly configured. {rule['concern']} Set the header as "
            f"recommended and verify the configuration after deployment."
        )
        return self._scored_result(
            rule["vector"],
            0.95,
            parameter=header,
            payload=(value if value is not None else "missing"),
            technique=TECHNIQUE,
            evidence="\n".join(lines),
            detail=detail,
        )
