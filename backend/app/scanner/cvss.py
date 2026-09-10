"""
CVSS v3.1 base-score calculator.

VulnScan derives a finding's RiskScore and Severity from a formally defined
CVSS v3.1 base metric vector, following the FIRST CVSS v3.1 specification
(https://www.first.org/cvss/v3.1/specification-document).  Severity bands
follow the project's Table 2.2 (CVSS scores -> severity levels), so the risk
value has a documented, reproducible basis rather than an arbitrary constant.

Only BASE metrics are used (temporal/environmental metrics are out of the
documented project scope).
"""
import math
from decimal import ROUND_CEILING, Decimal

from app.utils.constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_NONE,
)

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


class CvssError(ValueError):
    pass


def _roundup(value):
    """CVSS 3.1 Roundup: smallest number >= value, rounded to one decimal."""
    return float(Decimal(str(value)).quantize(Decimal("0.1"), rounding=ROUND_CEILING))


def parse_vector(vector):
    """Parse a CVSS:3.1/... vector string into a metric dict."""
    if not vector:
        raise CvssError("Empty CVSS vector")
    parts = vector.strip().split("/")
    if not parts or not parts[0].upper().startswith("CVSS:3"):
        raise CvssError("Only CVSS v3.x vectors are supported")
    metrics = {}
    for part in parts[1:]:
        if ":" not in part:
            raise CvssError(f"Malformed metric: {part}")
        key, value = part.split(":", 1)
        metrics[key.upper()] = value.upper()
    return metrics


def base_score(vector):
    """Compute the CVSS v3.1 base score for a vector string."""
    m = parse_vector(vector)
    try:
        scope_changed = m["S"] == "C"
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        ui = _UI[m["UI"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError as exc:
        raise CvssError(f"Missing or invalid metric: {exc}") from exc

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        value = min(1.08 * (impact + exploitability), 10)
    else:
        value = min(impact + exploitability, 10)
    return _roundup(value)


def severity_for_score(score):
    """Map a CVSS base score to the project's severity bands (Table 2.2)."""
    if score is None:
        return SEVERITY_NONE
    if score == 0.0:
        return SEVERITY_NONE
    if score < 4.0:
        return SEVERITY_LOW
    if score < 7.0:
        return SEVERITY_MEDIUM
    if score < 9.0:
        return SEVERITY_HIGH
    return SEVERITY_CRITICAL


def score_and_severity(vector):
    score = base_score(vector)
    return score, severity_for_score(score)
