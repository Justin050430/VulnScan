"""
`Set-Cookie` header parsing for cookie attribute assessment.

Two properties drive this module:

  * **The cookie value is never retained.**  It is discarded while parsing, so
    no code path can accidentally place a live session token into a finding,
    a log line or an exported report.
  * **Header boundaries are respected.**  A response can carry several
    `Set-Cookie` headers, and each one is parsed independently.  The attribute
    list is delimited by semicolons, *never* by commas: an `Expires` value
    legitimately contains a comma
    (`Expires=Wed, 21 Oct 2026 07:28:00 GMT`), so splitting a combined header
    on commas would corrupt the attributes and invent false findings.

A header that cannot be parsed into `name=value` is skipped rather than
guessed at.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ParsedCookie:
    """A cookie's name and attributes - deliberately without its value."""

    name: str
    #: ((lower-cased attribute name, value or None for a flag), ...)
    attributes: tuple

    def has(self, attribute):
        return any(key == attribute for key, _value in self.attributes)

    def value_of(self, attribute):
        for key, value in self.attributes:
            if key == attribute:
                return value
        return None

    @property
    def attribute_names(self):
        return [key for key, _value in self.attributes]


def parse_set_cookie(header: Optional[str]) -> Optional[ParsedCookie]:
    """
    Parse one `Set-Cookie` header value.

    Returns None when the header does not start with a usable `name=value`
    pair (for example a malformed or truncated header).
    """
    if not header:
        return None
    parts = header.split(";")
    pair = parts[0].strip()
    if "=" not in pair:
        return None
    name, _value = pair.split("=", 1)  # the value is intentionally dropped
    name = name.strip()
    if not name:
        return None

    attributes = []
    for raw in parts[1:]:
        raw = raw.strip()
        if not raw:
            continue
        if "=" in raw:
            key, value = raw.split("=", 1)
            attributes.append((key.strip().lower(), value.strip()))
        else:
            attributes.append((raw.lower(), None))
    return ParsedCookie(name=name, attributes=tuple(attributes))


def parse_set_cookies(headers) -> list:
    """Parse every `Set-Cookie` header of a response, in order."""
    cookies = []
    for header in headers or ():
        parsed = parse_set_cookie(header)
        if parsed is not None:
            cookies.append(parsed)
    return cookies
