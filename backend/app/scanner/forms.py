"""
HTML form discovery for parameter injection.

Real applications accept user input through forms at least as often as through
the query string, so a scanner that only fuzzes GET parameters misses the
majority of injectable inputs.  This module extracts the forms of a crawled
page (method, action, controls and their page-provided default values) so the
SQL injection and XSS modules can treat form fields as injection points using
the same evidence standards as query parameters.

Deliberate safety policy - a form is **not** submitted when:

  * its method is neither GET nor POST (dialog/put/delete forms are skipped),
  * its action is not an http(s) URL,
  * it contains a password or file input (credential and upload testing are
    out of scope and could lock out or overwrite real accounts/files),
  * its action or a control name looks destructive (delete/remove/payment/...),
    because even a read-only payload would mutate data there.

Hidden inputs keep the values the page served, so CSRF tokens, record ids and
other required state stay valid and the server processes the request instead of
rejecting it.  Processing is bounded (MAX_FORMS_PER_PAGE, MAX_FIELDS_PER_FORM)
so a form-heavy page cannot multiply the scan's request count without limit.
"""
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from app.utils.urls import is_http_url

ALLOWED_METHODS = ("GET", "POST")

MAX_FORMS_PER_PAGE = 5
MAX_FIELDS_PER_FORM = 12

#: Controls that are submitted but never injected into.
NON_INJECTABLE_TYPES = {
    "hidden", "submit", "button", "reset", "image", "checkbox", "radio",
}
#: Any of these makes the whole form out of scope.
FORBIDDEN_TYPES = {"password", "file"}

#: Name/path fragments that indicate a state-changing (unsafe to submit) form.
DESTRUCTIVE_TOKENS = (
    "delete", "remove", "destroy", "logout", "signout", "sign-out",
    "checkout", "payment", "purchase", "unsubscribe", "cancel", "revoke",
    "deactivate", "reset-password",
)


@dataclass(frozen=True)
class FormControl:
    """One named control of a form, with the value the page rendered."""

    name: str
    value: str
    kind: str          # input type, or 'textarea' / 'select' / 'button'
    injectable: bool


@dataclass(frozen=True)
class Form:
    """A submittable form discovered on a page."""

    action: str
    method: str        # 'GET' or 'POST'
    controls: tuple

    @property
    def injectable_controls(self):
        return tuple(control for control in self.controls if control.injectable)

    def data(self):
        """Default submission payload (all controls, page-served values)."""
        return {control.name: control.value for control in self.controls}

    def data_with(self, field_name, value):
        """Default submission payload with one field replaced."""
        payload = self.data()
        payload[field_name] = value
        return payload


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self._form = None
        self._select = None
        self._option_text = None

    # ------------------------------------------------------------- elements
    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form":
            self._form = {
                "action": attributes.get("action") or "",
                "method": (attributes.get("method") or "get").strip().lower(),
                "controls": [],
            }
            self._select = None
            self._option_text = None
            return
        if self._form is None:
            return
        if tag == "input":
            name = attributes.get("name")
            if name:
                kind = (attributes.get("type") or "text").strip().lower()
                self._form["controls"].append(
                    (name, attributes.get("value") or "", kind)
                )
        elif tag == "textarea":
            name = attributes.get("name")
            if name:
                self._form["controls"].append((name, "", "textarea"))
        elif tag == "select":
            self._select = {
                "name": attributes.get("name"),
                "value": "",
                "chosen": False,
            }
        elif tag == "option" and self._select is not None:
            if "value" in attributes and not self._select["chosen"]:
                self._select["value"] = attributes.get("value") or ""
                self._select["chosen"] = True
            self._option_text = ""
        elif tag == "button":
            name = attributes.get("name")
            if name:
                self._form["controls"].append(
                    (name, attributes.get("value") or "", "button")
                )

    def handle_endtag(self, tag):
        if tag == "option" and self._select is not None:
            if not self._select["chosen"]:
                # <option>Text</option> submits its text when it has no value.
                self._select["value"] = (self._option_text or "").strip()
                self._select["chosen"] = True
            self._option_text = None
        elif tag == "select" and self._form is not None and self._select is not None:
            if self._select["name"]:
                self._form["controls"].append(
                    (self._select["name"], self._select["value"], "select")
                )
            self._select = None
        elif tag == "form":
            if self._form is not None:
                self.forms.append(self._form)
            self._form = None
            self._select = None
            self._option_text = None

    def handle_data(self, data):
        if self._option_text is not None:
            self._option_text += data


def form_signature(form):
    """
    Identity of a form for cross-page deduplication.

    A site-wide form (header search box, newsletter box) appears on many pages
    but points at the same endpoint with the same fields; testing it once is
    enough and keeps the scan's request count bounded.
    """
    return (
        form.method,
        form.action,
        tuple(sorted(control.name for control in form.controls)),
    )


def _looks_destructive(action, controls):
    targets = [urlparse(action).path.lower()]
    targets.extend(control.name.lower() for control in controls)
    return any(token in target for target in targets for token in DESTRUCTIVE_TOKENS)


def parse_forms(base_url, html, limit=MAX_FORMS_PER_PAGE):
    """Return the submittable, safe-to-test forms found in `html`."""
    if not html:
        return ()
    parser = _FormParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return ()

    forms = []
    for raw in parser.forms:
        method = raw["method"].upper()
        if method not in ALLOWED_METHODS:
            continue
        action = urljoin(base_url, raw["action"] or base_url)
        if not is_http_url(action):
            continue
        if any(kind in FORBIDDEN_TYPES for _, _, kind in raw["controls"]):
            continue
        controls = tuple(
            FormControl(
                name=name,
                value=value,
                kind=kind,
                injectable=kind not in NON_INJECTABLE_TYPES,
            )
            for name, value, kind in raw["controls"][:MAX_FIELDS_PER_FORM]
        )
        if not any(control.injectable for control in controls):
            continue
        if _looks_destructive(action, controls):
            continue
        forms.append(Form(action=action, method=method, controls=controls))
        if len(forms) >= limit:
            break
    return tuple(forms)
