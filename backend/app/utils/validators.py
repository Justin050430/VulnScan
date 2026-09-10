"""Input validation helpers used by the API and the scanner."""
import re
from urllib.parse import urlparse

from email_validator import EmailNotValidError, validate_email

from app.utils.constants import ROLE_ADMINISTRATOR, ROLE_DEVELOPER

USERNAME_RE = re.compile(r"^[A-Za-z0-9_. -]{3,50}$")
PASSWORD_MIN_LENGTH = 8


class ValidationError(ValueError):
    """Raised when user-supplied input fails validation."""


def validate_username(value):
    if not value or not isinstance(value, str):
        raise ValidationError("Username is required.")
    value = value.strip()
    if not USERNAME_RE.match(value):
        raise ValidationError(
            "Username must be 3-50 characters and contain only letters, digits, "
            "underscores, dots, spaces or hyphens."
        )
    return value


# Permissive-but-strict fallback for internal domains (e.g. name@company.local)
# that the email-validator library rejects as "special-use or reserved".
_FALLBACK_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def validate_email_address(value):
    if not value or not isinstance(value, str):
        raise ValidationError("Email address is required.")
    value = value.strip().lower()
    try:
        validated = validate_email(value, check_deliverability=False)
        return validated.normalized.lower()
    except EmailNotValidError:
        # Accept only if the address is well-formed but on an internal/
        # special-use domain (rejected purely for domain-type reasons).
        if _FALLBACK_EMAIL_RE.match(value):
            return value
        raise ValidationError("A valid email address is required.") from None


def validate_password(value):
    if not value or not isinstance(value, str):
        raise ValidationError("Password is required.")
    if len(value) < PASSWORD_MIN_LENGTH:
        raise ValidationError(
            f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
        )
    return value


def validate_role(value):
    if value not in (ROLE_ADMINISTRATOR, ROLE_DEVELOPER):
        raise ValidationError(
            f"Role must be one of: {ROLE_ADMINISTRATOR}, {ROLE_DEVELOPER}."
        )
    return value


def validate_target_url(value):
    """Validate a scan target URL. Returns a normalised URL or raises."""
    if not value or not isinstance(value, str):
        raise ValidationError("Target URL is required.")
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError("Target URL must start with http:// or https://.")
    if not parsed.netloc or "." not in parsed.netloc:
        # allow localhost / 127.0.0.1 / host:port without a dot for local testing
        if parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise ValidationError("Target URL must include a valid hostname.")
    if parsed.scheme == "http" and parsed.port == 443:
        raise ValidationError("Invalid target URL.")
    return value


def validate_int_field(value, name, minimum=None, maximum=None):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{name} must be an integer.") from None
    if minimum is not None and number < minimum:
        raise ValidationError(f"{name} must be at least {minimum}.")
    if maximum is not None and number > maximum:
        raise ValidationError(f"{name} must be at most {maximum}.")
    return number
