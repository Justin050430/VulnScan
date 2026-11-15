"""
Logical finding identity and consolidation (P3, checkpoint 1).

The scanner stores one `Finding` row per detection.  That is exactly right for
evidence, triage and retesting - every affected URL keeps its own payload,
evidence and retest history - but it produces many near-duplicate rows: a
missing `X-Frame-Options` header on 15 pages is 15 findings describing one
problem.

This module derives a stable, **versioned logical identity** for each stored
finding so the API (and, in checkpoint 2, the reports and the UI) can present
one consolidated issue per logical vulnerability while every original record
stays untouched.  Nothing is merged, rewritten or deleted, and no schema is
involved.

Identity is computed from stored data only - the `Finding` columns plus the
structured lines inside `Evidence` - so:

  * historical scans group exactly like new scans (no backfill),
  * the group key is reproducible from the database alone,
  * an identity that cannot be determined falls back to a *unique* key, so
    unknown data is never merged with anything.

Identity per module (see docs/DEVELOPMENT_NOTES.md round 12):

  * headers  `v1:http_headers:<header-rule>`
             one issue per rule; the missing/weak condition stays per location.
  * cookies  `v1:cookies:<rule>:<cookie-name>`
             different names and different violated rules never merge, and no
             cookie value is ever part of a key.
  * SQLi/XSS `v1:<module>:<method>:<origin><path>:<parameter>`
             method and parameter are mandatory; query strings are not part of
             the endpoint, so `/product?id=1` and `/product?id=2` are one issue
             while `/product` and `/blind` are not.
"""
import re
import string
from urllib.parse import urlparse

from app.utils.constants import (
    FINDING_STATUS_FALSE_POSITIVE,
    FINDING_STATUS_OPEN,
    FINDING_STATUS_RESOLVED,
    SEVERITIES,
    SEVERITY_ORDER,
)
from app.utils.modules import module_key_for_name

KEY_VERSION = "v1"

MODULE_HEADERS = "http_headers"
MODULE_COOKIES = "cookies"
MODULE_SQLI = "sqli"
MODULE_XSS = "xss"

POINT_MODULES = (MODULE_SQLI, MODULE_XSS)

DEFAULT_PORTS = {"http": 80, "https": 443}

STATUSES = (
    FINDING_STATUS_OPEN,
    FINDING_STATUS_RESOLVED,
    FINDING_STATUS_FALSE_POSITIVE,
)

#: Worst outcome first: one still-vulnerable location must dominate a group.
RETEST_VERDICT_PRECEDENCE = (
    "Still Detected",
    "Inconclusive",
    "Unable to Verify",
    "Resolved",
)

REQUEST_TARGET_RE = re.compile(
    r"^REQUEST TARGET:\s*([A-Za-z]+)\s+(\S+)\s*$", re.MULTILINE
)
INJECTION_POINT_RE = re.compile(
    r"^INJECTION POINT:.*?\b(GET|POST|PUT|PATCH|DELETE|HEAD)\s+(https?://\S+)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
COOKIE_RULE_ID_RE = re.compile(r"^RULE ID:\s*(\S+)\s*$", re.MULTILINE)
COOKIE_RULE_TITLE_RE = re.compile(r"^RULE VIOLATED:\s*(.+?)\s*$", re.MULTILINE)
OBSERVED_URL_RE = re.compile(r"^OBSERVED URL:\s*(\S+)\s*$", re.MULTILINE)

#: Legacy cookie findings (recorded before the explicit `RULE ID:` line) are
#: mapped back from their evidence title.  Anything unmapped stays unidentified.
COOKIE_RULE_TITLES = {
    "the secure attribute is missing on an https response": "secure",
    "the httponly attribute is missing on a session/authentication cookie":
        "httponly",
    "the httponly attribute is missing on an ordinary cookie": "httponly",
    "the samesite attribute is missing": "samesite",
    "samesite=none is set without the secure attribute": "samesite_none",
}
COOKIE_RULE_TITLE_PREFIXES = {
    "the cookie-name prefix contract is violated": "prefix",
}

_UNRESERVED = set(string.ascii_letters + string.digits + "-._~")
_PERCENT_RE = re.compile(r"%([0-9A-Fa-f]{2})")


# --------------------------------------------------------------- endpoints
def normalise_endpoint(url):
    """
    Return ``scheme://host[:port]/path`` for `url`, or None when it cannot be
    parsed.

    Rules (approved): lower-case scheme and host, drop default ports, keep
    non-default ports, keep the path case-sensitive, collapse duplicate
    slashes, strip the query string and fragment, and normalise
    percent-encoding (unreserved characters decoded, remaining hex upper-cased).
    Returning None makes the caller fall back to a unique identity, so an
    unparsable endpoint never merges.
    """
    if not isinstance(url, str) or not url.strip():
        return None
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme not in DEFAULT_PORTS:
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None

    path = parsed.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = "/" + path
    path = _normalise_percent(path)

    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"
    return f"{scheme}://{netloc}{path}"


def _normalise_percent(path):
    def replace(match):
        char = chr(int(match.group(1), 16))
        if char in _UNRESERVED:
            return char
        return "%" + match.group(1).upper()

    return _PERCENT_RE.sub(replace, path)


def request_identity(method, evidence, fallback_url=None):
    """
    Return ``(method, url)`` for a SQLi/XSS finding.

    Prefers the explicit ``REQUEST TARGET:`` line written for new findings,
    falls back to the legacy ``INJECTION POINT:`` line, and finally to the
    finding's own request method and page URL.
    """
    text = evidence or ""
    match = REQUEST_TARGET_RE.search(text)
    if match:
        return match.group(1).upper(), match.group(2)
    match = INJECTION_POINT_RE.search(text)
    if match:
        return match.group(1).upper(), match.group(2)
    return ((method or "GET").upper()), fallback_url


# ------------------------------------------------------------------ cookies
def cookie_rule(evidence):
    """Return the violated cookie rule id recorded in `evidence`, or None."""
    text = evidence or ""
    match = COOKIE_RULE_ID_RE.search(text)
    if match:
        return match.group(1).strip().lower() or None
    match = COOKIE_RULE_TITLE_RE.search(text)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip().lower()
    if title in COOKIE_RULE_TITLES:
        return COOKIE_RULE_TITLES[title]
    for prefix, rule in COOKIE_RULE_TITLE_PREFIXES.items():
        if title.startswith(prefix):
            return rule
    return None


def observed_urls(evidence):
    """Every URL a cookie finding recorded as affected (ordered, unique)."""
    urls = []
    for match in OBSERVED_URL_RE.finditer(evidence or ""):
        url = match.group(1)
        if url not in urls:
            urls.append(url)
    return urls


# ------------------------------------------------------------------ identity
def identity_key(module_key, parameter, method, evidence, page_url,
                 vulnerability_id, finding_id):
    """
    Compute the versioned logical identity for one finding.

    Falls back to a unique key whenever a mandatory component is missing, so
    unknown data is never merged with other findings.
    """
    key = None
    if module_key == MODULE_HEADERS:
        rule = (parameter or "").strip().lower()
        if rule:
            key = f"{KEY_VERSION}:{MODULE_HEADERS}:{rule}"
    elif module_key == MODULE_COOKIES:
        name = (parameter or "").strip()
        rule = cookie_rule(evidence)
        if name and rule:
            key = f"{KEY_VERSION}:{MODULE_COOKIES}:{rule}:{name}"
    elif module_key in POINT_MODULES:
        name = (parameter or "").strip()
        request_method, url = request_identity(method, evidence, page_url)
        endpoint = normalise_endpoint(url)
        if name and endpoint:
            key = (
                f"{KEY_VERSION}:{module_key}:{request_method}"
                f":{endpoint}:{name}"
            )
    return key or unique_key(vulnerability_id, finding_id)


def unique_key(vulnerability_id, finding_id):
    """Identity used when the logical key cannot be determined (never merges)."""
    return f"{KEY_VERSION}:unidentified:{vulnerability_id}:{finding_id}"


def _module_key(finding):
    vulnerability = getattr(finding, "vulnerability", None)
    return getattr(vulnerability, "module_key", None) if vulnerability else None


def _page_url(finding):
    page = getattr(finding, "page", None)
    return page.URL if page is not None else None


def group_key(finding):
    """The logical identity of one stored `Finding`."""
    return identity_key(
        module_key=_module_key(finding),
        parameter=finding.Parameter,
        method=finding.RequestMethod,
        evidence=finding.Evidence,
        page_url=_page_url(finding),
        vulnerability_id=finding.VulnerabilityID,
        finding_id=finding.FindingID,
    )


# ---------------------------------------------------------------- aggregation
def _worst_status(members):
    counts = {status: 0 for status in STATUSES}
    for member in members:
        counts[member.Status] = counts.get(member.Status, 0) + 1
    if counts[FINDING_STATUS_OPEN]:
        return FINDING_STATUS_OPEN, counts
    if counts[FINDING_STATUS_RESOLVED]:
        return FINDING_STATUS_RESOLVED, counts
    return FINDING_STATUS_FALSE_POSITIVE, counts


def _latest_verdict(member):
    entries = member.retest_entries()
    return entries[-1]["Verdict"] if entries else None


def _aggregate_verdict(members):
    verdicts = [v for v in (_latest_verdict(m) for m in members) if v]
    for verdict in RETEST_VERDICT_PRECEDENCE:
        if verdict in verdicts:
            return verdict
    return None


def _classification(members):
    classes = {member.classification for member in members}
    if "Confirmed" in classes:
        return "Confirmed"
    if "Suspected" in classes:
        return "Suspected"
    return "Unclassified"


def _affected_urls_for(member, module_key):
    """
    The URLs a single record says are affected.

    Cookie findings consolidate the same weakness across pages into one record,
    so they list every observing URL; other modules are one record per page.
    """
    urls = []
    if module_key == MODULE_COOKIES:
        urls.extend(observed_urls(member.Evidence))
    page_url = _page_url(member)
    if page_url and page_url not in urls:
        urls.append(page_url)
    return urls


def _condition_counts(members, module_key):
    if module_key != MODULE_HEADERS:
        return {}
    counts = {"missing": 0, "weak": 0}
    for member in members:
        if (member.Payload or "").strip().lower() == "missing":
            counts["missing"] += 1
        else:
            counts["weak"] += 1
    return counts


def build_group(key, members):
    """Build the consolidated view of one logical issue."""
    members = sorted(members, key=lambda f: (f.FindingID or 0))
    module_key = _module_key(members[0])

    status, status_counts = _worst_status(members)
    severities = [m.Severity for m in members]
    severity = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))
    risks = [float(m.RiskScore) for m in members if m.RiskScore is not None]
    confidences = [
        float(m.Confidence) for m in members if m.Confidence is not None
    ]

    affected_urls = []
    for member in members:
        for url in _affected_urls_for(member, module_key):
            if url not in affected_urls:
                affected_urls.append(url)
    pages = []
    for member in members:
        page_url = _page_url(member)
        if page_url and page_url not in pages:
            pages.append(page_url)

    parameters = sorted({
        m.Parameter for m in members if m.Parameter
    })
    methods = sorted({
        m.RequestMethod for m in members if m.RequestMethod
    })
    detected = [m.DetectedAt for m in members if m.DetectedAt]

    locations = []
    for member in members:
        data = member.to_dict()
        data["GroupKey"] = key
        data["GroupSize"] = len(members)
        locations.append(data)

    vulnerability = members[0].vulnerability
    return {
        "GroupKey": key,
        "VulnerabilityID": members[0].VulnerabilityID,
        "VulnerabilityName": vulnerability.Name if vulnerability else None,
        "OWASPCategory": (
            vulnerability.OWASPCategory if vulnerability else None
        ),
        "Severity": severity,
        "RiskScore": round(max(risks), 1) if risks else None,
        "Confidence": round(max(confidences), 2) if confidences else None,
        "Classification": _classification(members),
        "Status": status,
        "StatusCounts": status_counts,
        "Mixed": len([c for c in status_counts.values() if c]) > 1,
        "RecordCount": len(members),
        "AffectedURLCount": len(affected_urls),
        "AffectedURLs": affected_urls,
        "PageCount": len(pages),
        "Pages": pages,
        "Parameters": parameters,
        "Methods": methods,
        "ConditionCounts": _condition_counts(members, module_key),
        "FirstDetectedAt": min(detected).isoformat() if detected else None,
        "LastDetectedAt": max(detected).isoformat() if detected else None,
        "LatestRetestVerdict": _aggregate_verdict(members),
        "RetestedCount": len([m for m in members if m.retest_entries()]),
        "Locations": locations,
    }


def find_group(findings, key):
    """
    Return ``(group, members)`` for `key` within `findings`, or ``(None, [])``.

    The key is resolved against the scan's own records, so a group key can
    never address findings that belong to another scan.
    """
    members = [finding for finding in findings if group_key(finding) == key]
    if not members:
        return None, []
    return build_group(key, members), members


def aggregate_verdict(verdicts):
    """
    Worst verdict of a set of retests: Still Detected > Inconclusive >
    Unable to Verify > Resolved > Not Run.
    """
    present = [verdict for verdict in verdicts if verdict]
    for verdict in RETEST_VERDICT_PRECEDENCE:
        if verdict in present:
            return verdict
    return present[0] if present else "Not Run"


def _sort_key(group):    return (
        -SEVERITY_ORDER.get(group["Severity"], 0),
        -(group["RiskScore"] or 0),
        group["VulnerabilityName"] or "",
        group["GroupKey"],
    )


def build_groups(findings):
    """
    Group `findings` into consolidated issues.

    Returns ``(groups, identities)`` where `identities` maps ``FindingID`` to
    ``(GroupKey, GroupSize)`` so callers can annotate the flat finding list
    without recomputing keys.
    """
    buckets = {}
    for finding in findings:
        buckets.setdefault(group_key(finding), []).append(finding)

    groups = []
    identities = {}
    for key, members in buckets.items():
        groups.append(build_group(key, members))
        for member in members:
            identities[member.FindingID] = (key, len(members))
    groups.sort(key=_sort_key)
    return groups, identities


def issue_counts(findings):
    """``(issue_count, severity_counts)`` without building full group views."""
    buckets = {}
    for finding in findings:
        key = group_key(finding)
        current = buckets.get(key)
        if current is None:
            buckets[key] = finding.Severity
        elif SEVERITY_ORDER.get(finding.Severity, 0) > SEVERITY_ORDER.get(current, 0):
            buckets[key] = finding.Severity
    counts = {}
    for severity in buckets.values():
        counts[severity] = counts.get(severity, 0) + 1
    return len(buckets), counts


def issue_counts_for_scans(scan_ids):
    """
    Per-scan issue counts for the scan list, without loading full findings.

    Reads only the columns the identity needs (evidence included, because the
    cookie rule and the SQLi/XSS request target live there).
    """
    from app.extensions import db
    from app.models import DiscoveredPage, Finding, Vulnerability

    result = {
        scan_id: {
            "IssueCount": 0,
            "IssueSeverityCounts": {s: 0 for s in SEVERITIES},
        }
        for scan_id in scan_ids
    }
    if not scan_ids:
        return result

    rows = (
        db.session.query(
            DiscoveredPage.ScanID,
            DiscoveredPage.URL,
            Finding.FindingID,
            Finding.Severity,
            Finding.RequestMethod,
            Finding.Parameter,
            Finding.Evidence,
            Finding.VulnerabilityID,
            Vulnerability.Name,
        )
        .join(Finding, Finding.PageID == DiscoveredPage.PageID)
        .join(
            Vulnerability,
            Finding.VulnerabilityID == Vulnerability.VulnerabilityID,
        )
        .filter(DiscoveredPage.ScanID.in_(scan_ids))
        .all()
    )
    keys_by_scan = {}
    for (scan_id, page_url, finding_id, severity, method, parameter,
         evidence, vulnerability_id, vulnerability_name) in rows:
        key = identity_key(
            module_key=module_key_for_name(vulnerability_name),
            parameter=parameter,
            method=method,
            evidence=evidence,
            page_url=page_url,
            vulnerability_id=vulnerability_id,
            finding_id=finding_id,
        )
        bucket = keys_by_scan.setdefault(scan_id, {})
        current = bucket.get(key)
        if current is None or SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(current, 0):
            bucket[key] = severity

    for scan_id, bucket in keys_by_scan.items():
        severity_counts = {s: 0 for s in SEVERITIES}
        for severity in bucket.values():
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        result[scan_id] = {
            "IssueCount": len(bucket),
            "IssueSeverityCounts": severity_counts,
        }
    return result
