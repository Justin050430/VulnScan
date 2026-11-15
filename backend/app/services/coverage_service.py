"""
Scan coverage description - one source of truth for the API and the reports.

The scan detail endpoint and the PDF/CSV exports must never disagree about what
was actually tested, so both render the structure built here instead of each
maintaining its own prose.

Four distinct tiers are kept apart deliberately:

  * **Supported** - what this scanner can detect at all (implemented modules).
    A knowledge-base entry with no module is *not* supported, however it is
    configured.
  * **Enabled** - what the scan's profile actually switched on.
  * **Executed** - modules that ran against at least one analysed page.  With
    zero analysed pages nothing ran, whatever the profile enabled.
  * **Completed** - the scan reached `Completed`, so the executed modules ran to
    the end rather than being cut short by a failure.

Authentication is reported from the credential binding and the credential's own
failure record, so an anonymous or failed-login scan never claims authenticated
coverage.  No secret, cookie value or credential password is ever included.
"""
from urllib.parse import parse_qsl, urlparse

from app.scanner.registry import get_module_class
from app.utils.modules import implemented_module_names, techniques_for_module_key
from app.utils.constants import (
    AUDIT_ACTION_SCAN_DISCOVERY,
    AUDIT_CATEGORY_SCAN,
    SCAN_STATUS_COMPLETED,
)

AUTH_ANONYMOUS = "Anonymous"
AUTH_AUTHENTICATED = "Authenticated"
AUTH_FAILED = "AuthenticationFailed"


def _discovery(scan):
    """
    Read back the crawl's discovery record.

    The crawler stores how it found the scan's pages as one scan audit event
    (see app/scanner/engine.py), so discovery provenance survives a restart
    without adding a column to the approved entities.  Scans recorded before
    this existed simply report ``Available: False``.
    """
    import json

    from app.models import SecurityAuditLog

    try:
        row = (
            SecurityAuditLog.query
            .filter(
                SecurityAuditLog.Category == AUDIT_CATEGORY_SCAN,
                SecurityAuditLog.Action == AUDIT_ACTION_SCAN_DISCOVERY,
                SecurityAuditLog.EntityType == "Scan",
                SecurityAuditLog.EntityID == scan.ScanID,
            )
            .order_by(SecurityAuditLog.AuditID.desc())
            .first()
        )
    except Exception:  # pragma: no cover - defensive
        row = None
    if row is None or not row.Description:
        return {"Available": False}
    try:
        data = json.loads(row.Description)
    except (TypeError, ValueError):
        return {"Available": False}
    if not isinstance(data, dict):
        return {"Available": False}
    data["Available"] = True
    return data


def discovery_sentence(coverage):
    """
    One sentence describing how pages were discovered, or None.

    Only produced when the crawl actually recorded its sources, so older scans
    and coverage-free scans keep their existing wording.
    """
    discovery = coverage.get("Discovery") or {}
    if not discovery.get("Available"):
        return None
    sources = discovery.get("Sources") or {}
    parts = []
    if sources.get("Links"):
        parts.append(f"{sources['Links']} followed link(s)")
    if sources.get("Sitemaps"):
        parts.append(f"{sources['Sitemaps']} sitemap URL(s)")
    if sources.get("FormActions"):
        parts.append(f"{sources['FormActions']} GET form action(s)")
    if not parts:
        return None
    sentence = (
        f"Beyond the start URL, {sources.get('Links', 0)} link(s), "
        f"{sources.get('Sitemaps', 0)} sitemap URL(s) and "
        f"{sources.get('FormActions', 0)} GET form action(s) were queued "
        "for crawling."
    )
    excluded = discovery.get("Excluded") or {}
    blocked = (discovery.get("RobotsTxt") or {}).get("BlockedCount") or 0
    rejected = excluded.get("ScopeRejectedCount") or 0
    if blocked or rejected:
        sentence += (
            f" {blocked} URL(s) were excluded by robots.txt and {rejected} by "
            "scope or safety validation."
        )
    return sentence



def _authentication(scan):
    """
    Describe the authentication context from durable records only.

    Returns a dict with Mode, CredentialID, CredentialName and Reason.  The
    reason is the credential's recorded login failure, never a secret.
    """
    from app.services import credential_service

    credential = credential_service.credential_for_scan(scan.ScanID)
    if credential is None:
        return {
            "Mode": AUTH_ANONYMOUS,
            "CredentialID": None,
            "CredentialName": None,
            "Reason": None,
        }

    failed = bool(credential.FailureReason)
    return {
        "Mode": AUTH_FAILED if failed else AUTH_AUTHENTICATED,
        "CredentialID": credential.CredentialID,
        "CredentialName": credential.Name,
        "Reason": credential.FailureReason if failed else None,
    }


def _modules(scan):
    """
    Split the profile's modules into enabled/executed/unsupported.

    A profile can reference knowledge-base entries that have no detection module
    (for example CSRF or SSRF).  Those are reported as unsupported instead of
    being silently counted as tested.
    """
    enabled = []
    unsupported = []
    profile = scan.scan_profile
    for profile_module in (profile.modules if profile is not None else []):
        vulnerability = profile_module.vulnerability
        if vulnerability is None or not vulnerability.IsEnabled:
            continue
        module_class = get_module_class(vulnerability.module_key)
        if module_class is None:
            unsupported.append(vulnerability.Name)
        else:
            enabled.append(
                (module_class.key, vulnerability.Name)
            )
    return enabled, unsupported


def build_coverage(scan, pages=None):
    """
    Build the structured coverage description for a scan.

    `pages` may be passed when the caller already has the scan's pages loaded
    (report generation does); otherwise the relationship is used.
    """
    scan_pages = list(pages if pages is not None else scan.pages)
    analysed = [
        page for page in scan_pages
        if page.HTTPStatus is not None and page.HTTPStatus < 400
    ]
    skipped = [
        page for page in scan_pages
        if page.HTTPStatus is None or page.HTTPStatus >= 400
    ]

    tested_parameters = set()
    for page in analysed:
        for name, _value in parse_qsl(
            urlparse(page.URL).query, keep_blank_values=True
        ):
            tested_parameters.add(name)

    enabled_modules, unsupported_modules = _modules(scan)
    modules_executed = (
        [name for _key, name in enabled_modules] if analysed else []
    )
    not_executed_reason = (
        None if analysed else "no page could be analysed"
    )

    from flask import current_app

    forms_enabled = bool(
        current_app.config.get("SCANNER_ENABLE_FORM_TESTING", True)
    )
    time_based_enabled = bool(
        current_app.config.get("SCANNER_ENABLE_TIME_BASED", False)
    )

    coverage = {
        "DiscoveredPages": len(scan_pages),
        "AnalysedPages": len(analysed),
        "SkippedPages": [
            {"URL": page.URL, "HTTPStatus": page.HTTPStatus}
            for page in skipped
        ],
        "Authentication": _authentication(scan),
        "ModulesSupported": sorted(implemented_module_names()),
        "ModulesEnabled": [name for _key, name in enabled_modules],
        "ModulesExecuted": modules_executed,
        "ModulesNotExecuted": (
            [name for _key, name in enabled_modules] if not analysed else []
        ),
        "ModulesNotImplemented": sorted(unsupported_modules),
        "NotExecutedReason": not_executed_reason,
        "SupportedCapabilities": {
            name: techniques_for_module_key(key)
            for key, name in enabled_modules
        },
        "TestedQueryParameters": sorted(tested_parameters),
        "FormsTested": forms_enabled,
        "TimeBasedTestingEnabled": time_based_enabled,
        "Completed": scan.Status == SCAN_STATUS_COMPLETED,
        "Discovery": _discovery(scan),
    }
    coverage["Limitations"] = limitations(coverage)
    return coverage


def authentication_sentence(coverage):
    """One honest sentence about authenticated coverage."""
    auth = coverage["Authentication"]
    if auth["Mode"] == AUTH_AUTHENTICATED:
        if not coverage["Completed"]:
            return (
                "The scan authenticated with the approved temporary test "
                "account, but the scan did not complete, so authenticated "
                "coverage is partial."
            )
        return (
            "Pages reachable by the approved temporary test account were "
            "included in the crawl; pages that account cannot access were "
            "not assessed."
        )
    if auth["Mode"] == AUTH_FAILED:
        return (
            "Authentication was attempted with the approved temporary test "
            "account and failed, so login-protected pages were not assessed."
        )
    return (
        "No temporary scan credential was used, so login-protected pages "
        "were not assessed."
    )


def coverage_note(coverage):
    """
    Single-line coverage summary used by the scan detail API and the UI.

    Keeps the counters and the phrases the UI and tests rely on while stating
    the module and authentication facts accurately.
    """
    parts = [
        f"{coverage['AnalysedPages']} of {coverage['DiscoveredPages']} "
        "discovered page(s) were analysed.",
        authentication_sentence(coverage),
    ]

    discovery = discovery_sentence(coverage)
    if discovery:
        parts.insert(1, discovery)

    if coverage["ModulesExecuted"]:
        parts.append(
            "Detection modules executed: "
            + ", ".join(coverage["ModulesExecuted"])
            + "."
        )
    elif coverage["ModulesNotExecuted"]:
        parts.append(
            "No detection module ran because "
            f"{coverage['NotExecutedReason']}."
        )

    if coverage["ModulesNotImplemented"]:
        parts.append(
            "Enabled but not tested (no detection module implemented): "
            + ", ".join(coverage["ModulesNotImplemented"])
            + "."
        )

    if coverage["AnalysedPages"]:
        if coverage["FormsTested"]:
            parts.append(
                "Query-string parameters and HTML form fields (GET and POST) "
                "are tested; forms containing password or file inputs, and "
                "forms with destructive actions, are skipped. "
                "JavaScript-rendered content is not executed."
            )
        else:
            parts.append(
                "Only GET query-string parameters are tested (form-field "
                "testing is disabled on this server). JavaScript-rendered "
                "content is not executed."
            )
    else:
        parts.append(
            "No HTML form or parameter was tested because no page could be "
            "analysed."
        )

    parts.append(
        "Pages skipped due to a non-success HTTP status are listed in "
        "SkippedPages and were not tested."
    )
    return " ".join(parts)


def limitations(coverage):
    """
    Limitations that are true for this specific scan.

    Each statement is generated from the configuration and outcome, so the list
    can never contradict the coverage it is printed next to.
    """
    statements = []

    if not coverage["AnalysedPages"]:
        statements.append(
            "No page could be analysed, so no vulnerability was confirmed and "
            "no detection module produced results."
        )
        statements.append(
            "No HTML form was submitted and no parameter was tested, because "
            "the scan analysed no page."
        )
    elif coverage["FormsTested"]:
        statements.append(
            "GET and POST HTML forms are submitted with read-only payloads; "
            "forms containing password or file inputs, and forms with "
            "destructive actions (delete, payment, logout), are skipped."
        )
    else:
        statements.append(
            "HTML form fields are not tested because form-field testing is "
            "disabled on this server; only query-string parameters are tested."
        )

    statements.append(
        "PUT/PATCH/DELETE request bodies and JSON/XML payloads are not tested."
    )

    statements.append(
        "Request headers, cookies and JSON bodies are not used as injection "
        "points; response security headers are assessed as server "
        "configuration rather than as injection points."
    )
    statements.append(
        "JavaScript is not executed, so script-rendered content, DOM-based XSS "
        "and stored XSS are not analysed."
    )
    if coverage["Authentication"]["Mode"] == AUTH_ANONYMOUS:
        statements.append(
            "Login-protected pages are not covered by this scan because no "
            "temporary scan credential was used."
        )
    elif coverage["Authentication"]["Mode"] == AUTH_FAILED:
        statements.append(
            "Login-protected pages are not covered by this scan because the "
            "authentication attempt failed."
        )
    else:
        statements.append(
            "Login-protected coverage is limited to pages the temporary test "
            "account could reach and the crawler could discover."
        )

    if coverage["TimeBasedTestingEnabled"]:
        statements.append(
            "Time-based blind SQL injection probing was enabled and is "
            "attempted only when the other SQL injection techniques are "
            "inconclusive."
        )
    else:
        statements.append(
            "Time-based blind SQL injection probing is disabled on this "
            "server, so a delay-based injection would not be reported."
        )

    statements.extend(_discovery_limitations(coverage))
    return statements


def _discovery_limitations(coverage):
    """
    Limitations that come from how this scan's pages were discovered.

    Only conditions that actually occurred are reported, so a scan of a site
    without robots.txt or a sitemap is not given extra caveats.
    """
    discovery = coverage.get("Discovery") or {}
    if not discovery.get("Available"):
        return []

    statements = []
    robots = discovery.get("RobotsTxt") or {}
    limits = discovery.get("Limits") or {}
    sitemaps = discovery.get("Sitemaps") or {}
    excluded = discovery.get("Excluded") or {}

    if limits.get("PageBudgetReached"):
        statements.append(
            f"The crawl stopped at the configured page limit "
            f"({limits.get('MaxPages')} page(s)); URLs still queued at that "
            "point were not requested or analysed."
        )
    if robots.get("Respected") is False:
        statements.append(
            "robots.txt was not consulted for this scan because it is "
            "disabled in the server configuration; only the scope and safety "
            "rules limited crawling."
        )
    elif robots.get("BlockedCount"):
        statements.append(
            f"{robots['BlockedCount']} URL(s) disallowed by the target's "
            "robots.txt crawl policy were not requested."
        )
    if not robots.get("Fetched") and robots.get("Error"):
        statements.append(
            "robots.txt could not be interpreted "
            f"({robots['Error']}), so no path was excluded on that basis."
        )
    if excluded.get("ScopeRejectedCount"):
        statements.append(
            f"{excluded['ScopeRejectedCount']} discovered URL(s) were "
            "rejected by the target-scope or safety validation and were not "
            "requested."
        )
    if sitemaps.get("RejectedCount") and (
        sitemaps.get("Parsed") or not sitemaps.get("UsedDefaultLocation", True)
    ):
        first = (sitemaps.get("Rejected") or [{}])[0]
        detail = first.get("Reason")
        statements.append(
            f"{sitemaps['RejectedCount']} sitemap file(s) could not be used "
            "for discovery" + (f" (first reason: {detail})" if detail else "")
            + "."
        )
    if sitemaps.get("Truncated"):
        statements.append(
            "Sitemap discovery stopped at its per-file or per-crawl limit, so "
            "URLs listed beyond that limit were not requested."
        )
    return statements
