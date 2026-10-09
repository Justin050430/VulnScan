"""
Vulnerability detection module registry.

The final ERD does not include a dedicated "module code" column. Detection
modules are therefore associated with a canonical Vulnerability knowledge-base
entry by its stable Name.  Only vulnerabilities whose Name appears in
MODULE_NAMES correspond to an actually implemented detection module; the
scanner engine executes a module only for those names.  This keeps the
database structure exactly as documented while allowing future modules to be
added simply by registering a new name here and shipping an implementation.
"""
from app.utils.constants import (
    NAME_CROSS_SITE_SCRIPTING,
    NAME_MISSING_SECURITY_HEADERS,
    NAME_SQL_INJECTION,
)

MODULE_SQLI = "sqli"
MODULE_XSS = "xss"
MODULE_HTTP_HEADERS = "http_headers"

# module key -> canonical vulnerability name
MODULE_NAMES = {
    MODULE_SQLI: NAME_SQL_INJECTION,
    MODULE_XSS: NAME_CROSS_SITE_SCRIPTING,
    MODULE_HTTP_HEADERS: NAME_MISSING_SECURITY_HEADERS,
}

# canonical vulnerability name -> module key
NAME_TO_MODULE = {name: key for key, name in MODULE_NAMES.items()}


def module_key_for_name(name):
    """Return the implemented module key for a vulnerability name, or None."""
    if not name:
        return None
    return NAME_TO_MODULE.get(name.strip())


def name_for_module_key(key):
    return MODULE_NAMES.get(key)


def implemented_module_names():
    """Names of vulnerabilities that have a real detection implementation."""
    return set(MODULE_NAMES.values())


# Human-readable detection techniques per module, used by the pre-scan
# preview (C3).  Keep in sync with the actual module implementations.
MODULE_TECHNIQUES = {
    MODULE_SQLI: [
        "error-based (database error signatures)",
        "conditional-error differential",
        "boolean differential analysis",
        "time-based blind (only when enabled by the server operator)",
    ],
    MODULE_XSS: [
        "executable-context reflection analysis",
    ],
    MODULE_HTTP_HEADERS: [
        "HTTP security header policy evaluation (per rule)",
    ],
}


def techniques_for_module_key(key):
    """Detection techniques implemented by a module key (may be empty)."""
    return list(MODULE_TECHNIQUES.get(key, []))
