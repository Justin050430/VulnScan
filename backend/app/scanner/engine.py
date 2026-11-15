"""
Scanner Engine orchestrator.

Flow (matches Fig 4.8 Vulnerability Scanning Activity Diagram):
  validate request -> crawl pages (store DiscoveredPage) -> for each page run
  the enabled detection modules and record Findings -> update scan status ->
  present results.

All URL requests (including HTTP redirects) are validated against the target's
scan scope and the SSRF guard before they are issued.
"""
import json
import logging
from datetime import datetime
from urllib.parse import urlparse
from flask import current_app

from app.extensions import db
from app.models import DiscoveredPage, Finding, Scan
from app.scanner import progress
from app.scanner.base import PageInfo
from app.scanner.client import HttpClient
from app.scanner.crawler import Crawler
from app.scanner.registry import get_module_class
from app.scanner.safety import check_target_allowed
from app.services.audit_service import write_audit
from app.utils.constants import (
    AUDIT_ACTION_SCAN_DISCOVERY,
    AUDIT_CATEGORY_SCAN,
    AUDIT_STATUS_FAILURE,
    FINDING_STATUS_OPEN,
    SCAN_STATUS_CANCELLED,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_RUNNING,
)
from app.utils.urls import normalize_url

logger = logging.getLogger("vulnscan.engine")

#: Upper bound on the stored discovery record (JSON in the audit description).
MAX_DISCOVERY_RECORD_BYTES = 20_000


def _is_cancelled(scan_id):
    """Cheap cancellation check used between pages."""
    try:
        status = (
            db.session.query(Scan.Status)
            .filter(Scan.ScanID == int(scan_id))
            .scalar()
        )
        return status == SCAN_STATUS_CANCELLED
    except Exception:
        logger.debug("Cancellation check failed for scan %s", scan_id, exc_info=True)
        return False


class ScanValidationError(ValueError):
    pass


def validate_scan_request(target_url, profile):
    """Validate a scan request before a Scan row is created/started."""
    from app.utils.validators import (
        ValidationError,
        validate_target_url,
        validate_target_url_length,
    )

    try:
        validate_target_url(target_url)
    except ValidationError as exc:
        raise ScanValidationError(str(exc)) from exc
    allow_private = bool(
        current_app.config.get("SCANNER_ALLOW_PRIVATE_TARGETS", True)
    )
    ok, reason = check_target_allowed(target_url, allow_private=allow_private)
    if not ok:
        raise ScanValidationError(reason)
    if profile is None:
        raise ScanValidationError("A valid scan profile is required.")
    normalised = normalize_url(target_url)
    try:
        # Normalisation can lengthen the URL, so re-check what will be stored.
        validate_target_url_length(normalised)
    except ValidationError as exc:
        raise ScanValidationError(str(exc)) from exc
    return normalised


def make_url_validator(target_url, follow_external, allow_private):
    """
    Build a validator used for every request the scanner issues (and every
    redirect hop).  It enforces both the scan scope and the SSRF guard.
    """
    scope = Crawler(http=None, follow_external=follow_external)
    base_parsed = urlparse(normalize_url(target_url))

    def validator(url):
        ok, reason = check_target_allowed(url, allow_private=allow_private)
        if not ok:
            return False, reason
        if not scope.in_scope(url, base_parsed):
            return False, "outside the target scan scope"
        return True, ""

    return validator


def run_scan(scan_id):
    """
    Execute a stored scan synchronously.  Callers must run within an
    application context.  Results are committed to the database.
    """
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        logger.error("run_scan: scan %s not found", scan_id)
        return
    progress.start(scan_id)

    profile = scan.scan_profile
    if profile is None:
        _finish_failed(scan, "Scan profile no longer exists.")
        return

    allow_private = bool(
        current_app.config.get("SCANNER_ALLOW_PRIVATE_TARGETS", True)
    )
    timeout = float(current_app.config.get("SCANNER_DEFAULT_TIMEOUT", 10))
    verify_ssl = current_app.config.get("SCANNER_VERIFY_SSL", True)
    http = HttpClient(
        timeout=timeout,
        delay_ms=profile.RequestDelayMs or 0,
        verify_ssl=verify_ssl,
        url_validator=make_url_validator(
            scan.TargetURL, profile.FollowExternalLinks, allow_private
        ),
    )

    # ------------------------------------------------------ authentication
    # Authenticate before the scan is marked Running so a bad credential does
    # not consume the reserved credit.  Anonymous scans skip this block.
    from app.scanner.auth import AuthSession
    from app.services import credential_service

    auth_session = None
    credential = credential_service.credential_for_scan(scan.ScanID)
    if credential is not None:
        auth_failure = None
        progress.update(scan_id, http=http, stage="authenticating")
        try:
            password = credential_service.decrypt_for_use(credential)
            auth_session = AuthSession(
                http, credential_service.login_config(credential, password)
            )
            auth_session.login()
            http.auth_session = auth_session
        except Exception as exc:  # LoginError plus storage/unexpected I/O
            auth_failure = str(exc)
            logger.warning("Scan %s authentication failed: %s", scan_id, auth_failure)
        if auth_failure:
            try:
                credential_service.mark_login_failure(credential, auth_failure)
                db.session.commit()
            except Exception:
                db.session.rollback()
                logger.exception(
                    "Could not record credential failure for scan %s", scan_id
                )
            _finish_failed(scan, f"Authentication failed: {auth_failure}")
            try:
                from app.services.scan_gate_service import release_if_never_started

                release_if_never_started(
                    scan.ScanID,
                    "Authentication failed before the scan started",
                )
            except Exception:
                logger.exception(
                    "Could not release credit for failed auth scan %s", scan_id
                )
            http.close()
            return

    scan.Status = SCAN_STATUS_RUNNING
    scan.StartedAt = datetime.utcnow()
    db.session.commit()
    # The scan really started, so the reserved credit becomes consumed.
    try:
        from app.services.scan_gate_service import consume_credit_for_scan

        consume_credit_for_scan(scan.ScanID)
    except Exception:
        logger.exception("Credit consumption failed for scan %s", scan.ScanID)
    write_audit(
        category=AUDIT_CATEGORY_SCAN,
        action="SCAN_STARTED",
        description=f"Vulnerability scan '{scan.ScanName}' started for target "
                    f"{scan.TargetURL}.",
        user_id=scan.UserID,
        entity_type="Scan",
        entity_id=scan.ScanID,
        commit=True,
    )

    progress.update(scan_id, http=http, stage="crawling")

    try:
        # --------------------------------------------------------- crawl
        skip_paths = ()
        if auth_session is not None:
            skip_paths = ("logout", "signout", "sign-out")
            if auth_session.login_path not in ("", "/"):
                skip_paths = skip_paths + (auth_session.login_path,)
        crawler = Crawler(
            http=http,
            max_pages=profile.MaxPages,
            max_depth=profile.MaxDepth,
            follow_external=profile.FollowExternalLinks,
            skip_url_contains=skip_paths,
            respect_robots=bool(
                current_app.config.get("SCANNER_RESPECT_ROBOTS_TXT", True)
            ),
            discover_sitemaps=bool(
                current_app.config.get("SCANNER_ENABLE_SITEMAP_DISCOVERY", True)
            ),
        )
        pages = crawler.crawl(scan.TargetURL)
        _record_discovery(scan, crawler.discovery)
        progress.update(scan_id, pages_found=len(pages), stage="analysing")
        if http.auth_failed:
            _finish_failed(
                scan,
                "The authenticated session was lost during the crawl and "
                "could not be restored.",
            )
            return
        if not pages:
            _finish_failed(scan, "Crawler discovered no reachable pages.")
            return

        start_page = pages[0]
        if start_page.http_status is None:
            _finish_failed(
                scan,
                "Target could not be reached"
                + (f": {start_page.error}" if start_page.error else "."),
            )
            return

        page_rows = []
        for page in pages:
            row = DiscoveredPage(
                ScanID=scan.ScanID,
                URL=page.url,
                PageTitle=page.title,
                HTTPStatus=page.http_status,
                CrawlDepth=page.depth,
                DiscoveryOrder=page.order,
            )
            db.session.add(row)
            page_rows.append((page, row))
        db.session.commit()

        # ------------------------------------------------- modules
        module_specs = []
        for pm in profile.modules:
            vuln = pm.vulnerability
            if vuln is None or not vuln.IsEnabled:
                continue
            module_class = get_module_class(vuln.module_key)
            if module_class is None:
                # Vulnerability KB entries without an implemented module.
                continue
            module_specs.append((module_class, vuln))

        pages_done = 0
        findings_total = 0
        cancelled = False
        # Shared across every page and module of this scan; used by modules
        # that must report a site-wide condition only once (e.g. a cookie).
        scan_state = {}
        # Cookie findings are reported once per (cookie, rule) but must name
        # every page where the weakness was observed; they are collected here
        # and completed after the crawl (see _finalise_cookie_observations).
        cookie_findings = []
        test_form_fields = bool(
            current_app.config.get("SCANNER_ENABLE_FORM_TESTING", True)
        )
        for page, page_row in page_rows:
            if auth_session is not None:
                usable, reason = credential_service.scan_credential_usable(scan_id)
                if not usable:
                    _finish_failed(
                        scan, f"Authenticated scan stopped: {reason}."
                    )
                    return
            if _is_cancelled(scan_id):
                cancelled = True
                break
            pages_done += 1
            if page_row.HTTPStatus is None or page_row.HTTPStatus >= 400:
                progress.update(scan_id, pages_done=pages_done,
                                requests=http.request_count)
                continue
            forms = page.forms if test_form_fields else ()
            for module_class, vuln in module_specs:
                try:
                    module = module_class(
                        http=http,
                        page=PageInfo(
                            url=page_row.URL, forms=forms, scan_state=scan_state
                        ),
                    )
                    results = module.detect()
                except Exception:
                    logger.exception(
                        "Module %s failed on %s", module_class.key, page_row.URL
                    )
                    progress.add_error(
                        scan_id,
                        f"Module {module_class.key} failed on {page_row.URL}",
                    )
                    continue
                for result in results:
                    finding = _store_finding(page_row, vuln, result)
                    if module_class.key == "cookies":
                        cookie_findings.append(finding)
                    findings_total += 1
            db.session.commit()
            progress.update(
                scan_id,
                pages_done=pages_done,
                findings=findings_total,
                requests=http.request_count,
            )

        # One Finding per (cookie, rule) must still name every affected URL.
        _finalise_cookie_observations(
            cookie_findings, scan_state.get("cookie_observations") or {}
        )
        db.session.commit()

        if cancelled:
            scan.Status = SCAN_STATUS_CANCELLED
            scan.FinishedAt = datetime.utcnow()
            db.session.commit()
            write_audit(
                category=AUDIT_CATEGORY_SCAN,
                action="SCAN_CANCELLED",
                description=f"Vulnerability scan '{scan.ScanName}' was cancelled.",
                user_id=scan.UserID,
                entity_type="Scan",
                entity_id=scan.ScanID,
                status=AUDIT_STATUS_FAILURE,
                commit=True,
            )
            progress.finish(scan_id, "cancelled")
            logger.info("Scan %s cancelled by request", scan_id)
            return

        progress.update(scan_id, stage="finalising")
        scan.Status = SCAN_STATUS_COMPLETED
        scan.FinishedAt = datetime.utcnow()
        db.session.commit()

        finding_count = db.session.query(Finding.FindingID).join(
            DiscoveredPage, Finding.PageID == DiscoveredPage.PageID
        ).filter(DiscoveredPage.ScanID == scan.ScanID).count()
        write_audit(
            category=AUDIT_CATEGORY_SCAN,
            action="SCAN_COMPLETED",
            description=f"Vulnerability scan '{scan.ScanName}' completed: "
                        f"{len(page_rows)} page(s) analysed, {finding_count} "
                        f"finding(s) recorded.",
            user_id=scan.UserID,
            entity_type="Scan",
            entity_id=scan.ScanID,
            commit=True,
        )
        progress.finish(scan_id, "completed")
        logger.info("Scan %s completed with %d pages", scan_id, len(page_rows))
    except Exception:
        logger.exception("Scan %s failed unexpectedly", scan_id)
        db.session.rollback()
        _finish_failed(scan, "An unexpected error occurred during the scan.")
    finally:
        http.close()


def _record_discovery(scan, discovery):
    """
    Persist how the crawler found this scan's pages.

    Stored as a scan audit event rather than a new column so the approved core
    entities stay unchanged: the description is JSON, bounded by the crawler's
    own sampling limits, and coverage_service reads it back for the API and the
    reports.  Discovery provenance is a property of the scan event, not of an
    individual page.
    """
    if not discovery:
        return
    try:
        payload = json.dumps(discovery, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        logger.debug("Discovery record for scan %s is not serialisable", scan.ScanID)
        return
    if len(payload) > MAX_DISCOVERY_RECORD_BYTES:
        # Keep the record valid JSON: drop the per-URL samples first.
        trimmed = dict(discovery)
        excluded = dict(trimmed.get("Excluded") or {})
        excluded["Samples"] = {"Robots": [], "Scope": []}
        trimmed["Excluded"] = excluded
        sitemaps = dict(trimmed.get("Sitemaps") or {})
        sitemaps["Rejected"] = []
        trimmed["Sitemaps"] = sitemaps
        payload = json.dumps(trimmed, separators=(",", ":"), sort_keys=True)
        payload = payload[:MAX_DISCOVERY_RECORD_BYTES]
        payload = payload[: payload.rfind("}") + 1]
    write_audit(
        category=AUDIT_CATEGORY_SCAN,
        action=AUDIT_ACTION_SCAN_DISCOVERY,
        description=payload,
        user_id=scan.UserID,
        entity_type="Scan",
        entity_id=scan.ScanID,
        commit=True,
    )


def _store_finding(page_row, vuln, result):
    evidence = result.evidence
    if result.detail:
        evidence = f"{evidence}\n\n{result.detail}".strip()
    footer = []
    if result.target:
        # Machine-readable endpoint so the finding's logical identity (P3)
        # can name the endpoint even when a form posts elsewhere.
        footer.append(
            f"REQUEST TARGET: {(result.method or 'GET').upper()} {result.target}"
        )
    if result.technique:
        footer.append(f"DETECTION TECHNIQUE: {result.technique}")
    if result.cvss_vector:
        footer.append(f"CVSS Vector: {result.cvss_vector}")
    if footer:
        evidence = f"{evidence}\n\n" + "\n".join(footer)
    finding = Finding(
        Severity=result.severity,
        RiskScore=round(result.risk_score, 1),
        Confidence=round(result.confidence, 2),
        RequestMethod=result.method or "GET",
        Parameter=result.parameter,
        Payload=result.payload,
        Evidence=evidence,
        Status=FINDING_STATUS_OPEN,
        DetectedAt=datetime.utcnow(),
        PageID=page_row.PageID,
        VulnerabilityID=vuln.VulnerabilityID,
    )
    db.session.add(finding)
    return finding


def _finalise_cookie_observations(cookie_findings, observations):
    """
    Append every URL a cookie finding was observed on to its evidence.

    The cookie module reports one finding per (cookie, rule) and records the
    observing page URLs in the scan's shared state.  Because pages are analysed
    after the finding is created, the complete list is written once here, in a
    single evidence block:

        OBSERVATION COUNT: 2
        OBSERVED URL: http://host/cookies_weak
        OBSERVED URL: http://host/cookies_weak_more

    No cookie value is involved - only page URLs already known to the scan.
    """
    if not cookie_findings or not observations:
        return
    from app.services.grouping_service import cookie_rule

    for finding in cookie_findings:
        rule = cookie_rule(finding.Evidence)
        urls = observations.get((finding.Parameter, rule))
        if not urls:
            continue
        evidence = finding.Evidence or ""
        if "OBSERVED URL:" in evidence:
            # Already written (defensive: the finaliser runs once per scan).
            continue
        lines = [f"OBSERVATION COUNT: {len(urls)}"]
        lines.extend(f"OBSERVED URL: {url}" for url in urls)
        finding.Evidence = evidence.rstrip() + "\n" + "\n".join(lines)


def _finish_failed(scan, reason):
    scan.Status = SCAN_STATUS_FAILED
    scan.FinishedAt = datetime.utcnow()
    progress.finish(scan.ScanID, "failed", error=reason)
    logger.warning("Scan %s failed: %s", scan.ScanID, reason)
    write_audit(
        category=AUDIT_CATEGORY_SCAN,
        action="SCAN_FAILED",
        description=f"Vulnerability scan '{scan.ScanName}' failed: {reason}",
        user_id=scan.UserID,
        entity_type="Scan",
        entity_id=scan.ScanID,
        status=AUDIT_STATUS_FAILURE,
        commit=False,
    )
    db.session.commit()
