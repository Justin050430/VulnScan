"""
Cookie attribute assessment module (Security Misconfiguration).

Evaluates the `Set-Cookie` headers a page returns against the attributes that
protect a cookie in the browser.  Each violation is reported as its own finding
with a CVSS v3.1 vector, structured evidence and remediation guidance.

Rules:

  * `Secure` missing on an HTTPS page - the cookie can be sent over cleartext.
  * `HttpOnly` missing - script on the page can read the cookie.  Severity
    depends on the cookie's apparent purpose: a session/authentication cookie
    exposes an account, an ordinary preference cookie exposes very little.  An
    ordinary cookie without `HttpOnly` is therefore reported as Low and the
    evidence states that exploitation requires an XSS flaw in the same origin.
  * `SameSite` missing - the cookie is attached to cross-site requests.
  * `SameSite=None` without `Secure` - browsers reject such a cookie, and any
    that do accept it send it in cross-site contexts over HTTP.
  * `__Host-` / `__Secure-` prefix contract violated - the browser-enforced
    guarantees the prefix name implies are not actually in place.

Deliberate limits:

  * Cookies are only reported over HTTPS for the `Secure` rule; on a plain HTTP
    page a missing `Secure` attribute is not a weakness of the cookie.
  * The cookie **value** is never parsed, stored, logged or exported - only the
    name and the attribute list reach the finding.
  * Each (cookie name, rule) pair is reported once per scan.  A site-wide
    cookie is set by many pages; repeating it once per page would bury the rest
    of the report.  The evidence names the page where it was first observed and
    states the scope explicitly.
"""
import logging

from app.scanner.base import DetectionModule
from app.scanner.cookie_header import parse_set_cookies
from app.utils.constants import NAME_INSECURE_COOKIES

logger = logging.getLogger("vulnscan.cookies")

TECHNIQUE = "Set-Cookie attribute policy evaluation"

RULE_SECURE = "secure"
RULE_HTTPONLY = "httponly"
RULE_SAMESITE = "samesite"
RULE_SAMESITE_NONE = "samesite_none"
RULE_PREFIX = "prefix"

#: CVSS v3.1 base vectors per rule and cookie purpose.
CVSS_SESSION_ONLY = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"   # 4.2 Medium
CVSS_ORDINARY_ONLY = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1 Low
CVSS_SAMESITE_MISSING = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 3.1 Low
CVSS_SAMESITE_NONE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 4.3 Medium

PURPOSE_SESSION = "session"
PURPOSE_ORDINARY = "ordinary"

#: Canonical display names for the attributes that appear in evidence.
ATTRIBUTE_LABELS = {
    "secure": "Secure",
    "httponly": "HttpOnly",
    "samesite": "SameSite",
    "path": "Path",
    "domain": "Domain",
    "expires": "Expires",
    "max-age": "Max-Age",
    "partitioned": "Partitioned",
    "priority": "Priority",
}

#: Whole-name tokens that mark a cookie as a session/authentication cookie.
SESSION_TOKENS = frozenset({
    "sid", "sess", "session", "auth", "token", "jwt", "csrf", "xsrf",
    "remember", "login", "sso", "ticket",
})
#: Longer markers matched as substrings (well-known session cookie names).
SESSION_MARKERS = (
    "session", "jsessionid", "phpsessid", "asp.net_sessionid", "auth",
    "token", "jwt", "csrf", "xsrf", "remember", "login", "ssoid",
)

REFERENCES = (
    "OWASP Session Management Cheat Sheet "
    "(https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html); "
    "MDN Set-Cookie "
    "(https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)"
)


def cookie_purpose(name):
    """Classify a cookie name as a session/authentication or ordinary cookie."""
    lowered = (name or "").lower()
    tokens = {token for token in _split_tokens(lowered) if token}
    if tokens & SESSION_TOKENS:
        return PURPOSE_SESSION
    for marker in SESSION_MARKERS:
        if marker in lowered:
            return PURPOSE_SESSION
    return PURPOSE_ORDINARY


def _split_tokens(name):
    token = []
    for char in name:
        if char.isalnum():
            token.append(char)
        else:
            yield "".join(token)
            token = []
    yield "".join(token)


def _prefix_violation(cookie):
    """Return the reasons a `__Host-`/`__Secure-` prefix contract is broken."""
    lowered = cookie.name.lower()
    if lowered.startswith("__host-"):
        problems = []
        if not cookie.has("secure"):
            problems.append("'__Host-' requires the Secure attribute")
        if (cookie.value_of("path") or "").strip() != "/":
            problems.append("'__Host-' requires Path=/ exactly")
        if cookie.has("domain"):
            problems.append("'__Host-' forbids the Domain attribute")
        return "; ".join(problems) or None
    if lowered.startswith("__secure-"):
        if not cookie.has("secure"):
            return "'__Secure-' requires the Secure attribute"
    return None


class CookieModule(DetectionModule):
    key = "cookies"
    vulnerability_name = NAME_INSECURE_COOKIES

    def detect(self):
        response = self.http.get(self.page.url)
        if not response.ok:
            return []
        cookies = parse_set_cookies(response.set_cookies)
        if not cookies:
            return []

        is_https = (response.final_url or self.page.url).lower().startswith("https://")
        seen = self._seen()
        results = []
        for cookie in cookies:
            purpose = cookie_purpose(cookie.name)
            for rule, detail in self._violations(cookie, is_https):
                key = (cookie.name, rule)
                if key in seen:
                    # Same cookie and rule already reported for this scan.
                    continue
                seen.add(key)
                results.append(self._finding(cookie, purpose, rule, detail, is_https))
        return results

    # ---------------------------------------------------------------- state
    def _seen(self):
        """Per-scan set of (cookie name, rule) pairs already reported."""
        state = self.page.scan_state
        if not isinstance(state, dict):
            return set()
        return state.setdefault("cookie_findings", set())

    # --------------------------------------------------------------- rules
    def _violations(self, cookie, is_https):
        violations = []
        if is_https and not cookie.has("secure"):
            violations.append((RULE_SECURE, None))
        if not cookie.has("httponly"):
            violations.append((RULE_HTTPONLY, None))
        samesite = cookie.value_of("samesite")
        if samesite is None:
            violations.append((RULE_SAMESITE, None))
        elif samesite.strip().lower() == "none" and not cookie.has("secure"):
            violations.append((RULE_SAMESITE_NONE, None))
        prefix = _prefix_violation(cookie)
        if prefix:
            violations.append((RULE_PREFIX, prefix))
        return violations

    # ------------------------------------------------------------- evidence
    def _finding(self, cookie, purpose, rule, detail, is_https):
        if rule == RULE_HTTPONLY:
            vector = (
                CVSS_SESSION_ONLY if purpose == PURPOSE_SESSION
                else CVSS_ORDINARY_ONLY
            )
        elif rule == RULE_SAMESITE_NONE:
            vector = CVSS_SAMESITE_NONE
        elif rule == RULE_SECURE:
            vector = (
                CVSS_SESSION_ONLY if purpose == PURPOSE_SESSION
                else CVSS_ORDINARY_ONLY
            )
        else:
            vector = CVSS_SAMESITE_MISSING if rule == RULE_SAMESITE \
                else CVSS_ORDINARY_ONLY

        title, concern, impact, remediation = self._rule_text(
            rule, purpose, detail
        )
        evidence = "\n".join([
            f"CONFIRMED: the cookie '{cookie.name}' is set with a weak "
            f"configuration - {title}.",
            "",
            f"COOKIE NAME: {cookie.name}",
            f"COOKIE PURPOSE: {purpose}"
            + (" (name matches a session/authentication pattern)"
               if purpose == PURPOSE_SESSION else
               " (no session/authentication pattern in the name)"),
            f"RULE VIOLATED: {title}",
            f"ATTRIBUTES PRESENT: {self._attributes_summary(cookie)}",
            f"ATTRIBUTES MISSING: {self._missing_summary(cookie, rule, is_https)}",
            f"OBSERVED ON: {self.page.url}",
            "SCOPE: reported once per scan for this cookie and rule; the same "
            "cookie configuration is served on every page of this scan that "
            "sets it.",
            f"SECURITY CONCERN: {concern}",
            f"IMPACT / LIMITATIONS: {impact}",
            f"REMEDIATION: {remediation}",
            f"REFERENCES: {REFERENCES}",
            "VERIFICATION: Not retested yet.",
        ])
        return self._scored_result(
            vector,
            0.95,
            parameter=cookie.name,
            payload=self._attributes_summary(cookie),
            technique=TECHNIQUE,
            evidence=evidence,
            detail=(
                f"Security misconfiguration: the cookie '{cookie.name}' is set "
                f"without the recommended attributes ({title}). "
                f"{concern[0].upper()}{concern[1:]} "
                "Configure the cookie as recommended and verify the response "
                "after deployment."
            ),
        )

    @staticmethod
    def _attributes_summary(cookie):
        """Attribute names with the non-secret values that matter."""
        parts = []
        for key, value in cookie.attributes:
            label = ATTRIBUTE_LABELS.get(key, key)
            if key in ("path", "samesite", "max-age", "expires", "domain"):
                parts.append(f"{label}={value}" if value is not None else label)
            else:
                parts.append(label)
        return ", ".join(parts) if parts else "(none)"

    @staticmethod
    def _missing_summary(cookie, rule, is_https):
        """
        Attributes that are genuinely absent.

        `Secure` is only listed for an HTTPS response: on a plain-HTTP page it
        is not a weakness of the cookie, and the module does not report it.
        """
        if rule == RULE_PREFIX:
            return "prefix contract not satisfied"
        missing = []
        if is_https and not cookie.has("secure"):
            missing.append("Secure")
        if not cookie.has("httponly"):
            missing.append("HttpOnly")
        if cookie.value_of("samesite") is None:
            missing.append("SameSite")
        return ", ".join(missing) if missing else "(none relevant to this rule)"

    @staticmethod
    def _rule_text(rule, purpose, detail):
        if rule == RULE_SECURE:
            return (
                "the Secure attribute is missing on an HTTPS response",
                "without Secure, the browser will also send this cookie over "
                "plain HTTP, where a network attacker can read it.",
                "the exposure depends on the site being reachable over HTTP; "
                "this is a transport-confidentiality control.",
                "Set-Cookie: <name>=<value>; Secure; HttpOnly; SameSite=Lax; Path=/",
            )
        if rule == RULE_HTTPONLY:
            if purpose == PURPOSE_SESSION:
                return (
                    "the HttpOnly attribute is missing on a "
                    "session/authentication cookie",
                    "client-side JavaScript can read this cookie, so any XSS "
                    "flaw on the same origin escalates to session theft.",
                    "exploitation requires an injection flaw in the same "
                    "origin; without one this is a missing defence-in-depth "
                    "control, not a directly exploitable weakness.",
                    "Set-Cookie: <name>=<value>; HttpOnly; Secure; SameSite=Lax; Path=/",
                )
            return (
                "the HttpOnly attribute is missing on an ordinary cookie",
                "client-side JavaScript can read this cookie.",
                "this cookie does not appear to carry session state, so the "
                "impact is limited to the data it holds; it is reported as Low "
                "hardening rather than as a vulnerability on its own.",
                "Set-Cookie: <name>=<value>; HttpOnly; Path=/",
            )
        if rule == RULE_SAMESITE:
            return (
                "the SameSite attribute is missing",
                "the cookie is attached to cross-site requests, which enables "
                "cross-site request forgery against endpoints that rely on it.",
                "exploitation depends on the endpoint the cookie "
                "authenticates lacking its own CSRF defence.",
                "Set-Cookie: <name>=<value>; SameSite=Lax; Secure; HttpOnly",
            )
        if rule == RULE_SAMESITE_NONE:
            return (
                "SameSite=None is set without the Secure attribute",
                "browsers reject a SameSite=None cookie that is not also "
                "Secure, and any client that accepts it sends it in cross-site "
                "contexts over plain HTTP.",
                "the behaviour differs per browser: most drop the cookie "
                "entirely, which can break functionality while providing no "
                "protection.",
                "Set-Cookie: <name>=<value>; SameSite=None; Secure; HttpOnly",
            )
        return (
            f"the cookie-name prefix contract is violated ({detail})",
            "the security guarantees that the __Host-/__Secure- prefix "
            "promises are not actually in place.",
            "a cookie that looks protected by its name is not; tooling and "
            "code reviews can therefore misjudge its protections.",
            "Use __Host-<name> with Secure; Path=/; and no Domain attribute, "
            "or __Secure-<name> with the Secure attribute.",
        )
