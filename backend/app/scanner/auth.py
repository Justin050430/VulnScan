"""Authenticated scanner session bootstrap (FORM login).

The login handshake runs on the same hardened ``HttpClient`` session used by
the crawler and the detection modules, so cookies obtained here are reused for
the rest of the scan.  Credentials are held in memory only and are never
included in error messages or logs.

Supported flow (v1):
  * GET the login page,
  * parse the first form containing a password field (hidden CSRF fields and
    submit values are preserved),
  * POST the form with the configured username/password fields,
  * require an explicit success indicator (URL substring or page text).
"""
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse

MAX_REAUTHENTICATIONS = 1


class LoginError(Exception):
    """The login handshake failed.  The message never contains the secret."""


@dataclass
class LoginConfig:
    login_url: str
    username: str
    password: str = field(repr=False)
    username_field: str = None
    password_field: str = None
    extra_fields: dict = field(default_factory=dict, repr=False)
    success_url_contains: str = None
    success_text: str = None

    def __post_init__(self):
        self.login_url = _clean_url(self.login_url)
        self.extra_fields = {
            str(key): "" if value is None else str(value)
            for key, value in (self.extra_fields or {}).items()
        }


def _clean_url(url):
    parsed = urlparse(str(url).strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise LoginError("The login URL must be an absolute http(s) URL.")
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, "")
    )


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        attrs = {key.lower(): (value or "") for key, value in attrs}
        if tag == "form":
            self._end_current()
            self._current = {
                "action": attrs.get("action", ""),
                "method": (attrs.get("method") or "get").lower(),
                "inputs": [],
            }
            return
        if tag == "input" and self._current is not None:
            self._current["inputs"].append({
                "type": (attrs.get("type") or "text").lower(),
                "name": attrs.get("name", ""),
                "value": attrs.get("value", ""),
            })
        elif tag == "button" and self._current is not None:
            name = attrs.get("name", "")
            if name:
                self._current["inputs"].append({
                    "type": "submit",
                    "name": name,
                    "value": attrs.get("value", ""),
                })

    def handle_endtag(self, tag):
        if tag == "form":
            self._end_current()

    def _end_current(self):
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def close(self):
        super().close()
        self._end_current()


def _select_form(forms):
    for form in forms:
        if any(
            item["type"] == "password" and item["name"]
            for item in form["inputs"]
        ):
            return form
    return None


def _detect_fields(form, config):
    password_field = config.password_field
    if not password_field:
        for item in form["inputs"]:
            if item["type"] == "password" and item["name"]:
                password_field = item["name"]
                break
    username_field = config.username_field
    if not username_field:
        for item in form["inputs"]:
            if item["type"] in ("email", "text") and item["name"]:
                username_field = item["name"]
                break
    if not password_field or not username_field:
        raise LoginError(
            "The login form did not expose identifiable username/password fields."
        )
    return username_field, password_field


def _build_form_data(form, config, username_field, password_field):
    data = {}
    for item in form["inputs"]:
        name = item["name"]
        if not name or name in (username_field, password_field):
            continue
        if item["type"] in ("hidden", "submit"):
            data[name] = item["value"]
    # Explicit extra fields override parsed hidden values on purpose.
    data.update(config.extra_fields)
    data[username_field] = config.username
    data[password_field] = config.password
    return data


def _same_origin(url_a, url_b):
    a, b = urlparse(url_a), urlparse(url_b)
    return (a.scheme, a.netloc.lower()) == (b.scheme, b.netloc.lower())


class AuthSession:
    """Stateful login helper attached to a scan's ``HttpClient``."""

    def __init__(self, http, config):
        self.http = http
        self.config = config
        self.login_path = urlparse(config.login_url).path or "/"
        self.logged_in = False
        self.reauth_count = 0
        self.failure_reason = None

    def login(self):
        page = self.http.get(self.config.login_url)
        if not page.ok:
            raise LoginError(
                f"The login page could not be loaded: {page.error or 'request failed'}."
            )
        if page.status_code != 200:
            raise LoginError(
                f"The login page returned HTTP {page.status_code}."
            )

        parser = _FormParser()
        try:
            parser.feed(page.text or "")
            parser.close()
        except Exception as exc:
            raise LoginError("The login page could not be parsed.") from exc
        form = _select_form(parser.forms)
        if form is None:
            raise LoginError("No login form with a password field was found.")

        username_field, password_field = _detect_fields(form, self.config)
        action = urljoin(
            page.final_url or self.config.login_url,
            form["action"] or page.final_url or self.config.login_url,
        )
        if not _same_origin(action, self.config.login_url):
            raise LoginError(
                "The login form posts to a different host; refusing to send "
                "credentials off-scope."
            )

        response = self.http.post(
            action, data=_build_form_data(form, self.config, username_field,
                                          password_field),
        )
        if not response.ok:
            raise LoginError(
                f"The login request failed: {response.error or 'request failed'}."
            )
        if response.status_code is None or response.status_code >= 400:
            raise LoginError(
                f"The login request returned HTTP {response.status_code}."
            )

        self._confirm_success(response)
        self.logged_in = True
        self.failure_reason = None
        return {
            "FinalURL": response.final_url,
            "StatusCode": response.status_code,
        }

    def _confirm_success(self, response):
        expected_url = (self.config.success_url_contains or "").strip()
        expected_text = (self.config.success_text or "").strip()
        if not expected_url and not expected_text:
            raise LoginError(
                "The credential has no success indicator configured."
            )
        url_ok = bool(expected_url) and expected_url.lower() in (
            response.final_url or ""
        ).lower()
        text_ok = bool(expected_text) and expected_text in (response.text or "")
        if not url_ok and not text_ok:
            raise LoginError(
                "The login response did not match the configured success "
                "indicator; the supplied account may be invalid or the fields "
                "may be misconfigured."
            )

    def session_lost(self, response):
        """True when a scan response looks like an unauthenticated redirect."""
        if response is None:
            return False
        try:
            if _clean_url(response.url) == self.config.login_url:
                return False
        except LoginError:
            return False
        if response.status_code == 401:
            return True
        final_path = urlparse(response.final_url or "").path or "/"
        login_path = self.login_path.rstrip("/") or "/"
        return final_path == login_path or final_path.startswith(login_path + "/")

    def reauthenticate(self):
        if self.reauth_count >= MAX_REAUTHENTICATIONS:
            self.failure_reason = "The authenticated session could not be restored."
            return False
        self.reauth_count += 1
        try:
            self.login()
            return True
        except LoginError as exc:
            # The message is generated above and never includes the secret.
            self.failure_reason = str(exc)
            return False

    def close(self):
        self.http.close()
