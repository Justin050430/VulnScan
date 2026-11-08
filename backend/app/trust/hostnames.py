"""Hostname validation and exact-match scope rules.

The Trust Boundary only accepts exact hostnames.  Wildcards and IP literals
are rejected, and scanning a sub-domain of a verified host is not permitted in
this FYP slice.
"""
import ipaddress
import re
from urllib.parse import urlparse

from app.trust.constants import ERR_HOSTNAME_INVALID
from app.trust.permissions import TrustError

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_MAX_HOSTNAME = 253


def _invalid(message):
    return TrustError(message, ERR_HOSTNAME_INVALID, 400)


def is_ip_literal(host):
    if not host:
        return False
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def normalise_hostname(value):
    """Lowercase, strip a trailing dot and reject anything unsafe."""
    if value is None:
        raise _invalid("A hostname is required.")
    if not isinstance(value, str):
        raise _invalid("A hostname must be a string.")
    host = value.strip().lower()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise _invalid("A hostname is required.")
    if "*" in host:
        raise _invalid("Wildcards are not supported; register an exact hostname.")
    if "/" in host or ":" in host or "@" in host or "?" in host:
        raise _invalid("Enter a hostname only (no scheme, port, path or credentials).")
    if is_ip_literal(host):
        raise _invalid("IP addresses cannot be registered; use a hostname.")
    if len(host) > _MAX_HOSTNAME:
        raise _invalid("The hostname is too long.")
    labels = host.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise _invalid("The hostname is not valid.")
    if labels[-1].isdigit():
        raise _invalid("IP addresses cannot be registered; use a hostname.")
    return host


def hostname_from_url(url):
    """Return the lower-cased hostname of an http(s) URL (or None)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    host = (parsed.hostname or "").lower()
    if host.endswith("."):
        host = host[:-1]
    return host or None


def url_matches_asset(url, asset_hostname, asset_scheme=None):
    """True only for an exact hostname match (and allowed scheme)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    if asset_scheme and parsed.scheme != asset_scheme:
        return False
    return hostname_from_url(url) == (asset_hostname or "").lower()


def is_subdomain_of(hostname, parent):
    hostname = (hostname or "").lower()
    parent = (parent or "").lower()
    return hostname != parent and hostname.endswith("." + parent)
