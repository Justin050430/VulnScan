"""
Scanner Engine orchestrator.

Flow (matches Fig 4.8 Vulnerability Scanning Activity Diagram):
  validate request -> crawl pages (store DiscoveredPage) -> for each page run
  the enabled detection modules and record Findings -> update scan status ->
  present results.

All URL requests (including HTTP redirects) are validated against the target's
scan scope and the SSRF guard before they are issued.
"""
import logging
from datetime import datetime
from urllib.parse import urlparse

from flask import current_app

from app.extensions import db
from app.models import DiscoveredPage, Finding, Scan
from app.scanner.base import PageInfo
from app.scanner.client import HttpClient
from app.scanner.crawler import Crawler
from app.scanner.registry import get_module_class
from app.scanner.safety import check_target_allowed
from app.services.audit_service import write_audit
from app.utils.constants import (
    AUDIT_CATEGORY_SCAN,
    AUDIT_STATUS_FAILURE,
    FINDING_STATUS_OPEN,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_RUNNING,
)
from app.utils.urls import normalize_url

logger = logging.getLogger("vulnscan.engine")


class ScanValidationError(ValueError):
    pass


def validate_scan_request(target_url, profile):
    """Validate a scan request before a Scan row is created/started."""
    from app.utils.validators import ValidationError, validate_target_url

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
    return normalize_url(target_url)


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

    profile = scan.scan_profile
    if profile is None:
        _finish_failed(scan, "Scan profile no longer exists.")
        return

    scan.Status = SCAN_STATUS_RUNNING
    scan.StartedAt = datetime.utcnow()
    db.session.commit()
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

    try:
        # --------------------------------------------------------- crawl
        crawler = Crawler(
            http=http,
            max_pages=profile.MaxPages,
            max_depth=profile.MaxDepth,
            follow_external=profile.FollowExternalLinks,
        )
        pages = crawler.crawl(scan.TargetURL)
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

        for page, page_row in page_rows:
            if page_row.HTTPStatus is None or page_row.HTTPStatus >= 400:
                continue
            for module_class, vuln in module_specs:
                try:
                    module = module_class(http=http, page=PageInfo(url=page_row.URL))
                    results = module.detect()
                except Exception:
                    logger.exception(
                        "Module %s failed on %s", module_class.key, page_row.URL
                    )
                    continue
                for result in results:
                    _store_finding(page_row, vuln, result)
            db.session.commit()

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
        logger.info("Scan %s completed with %d pages", scan_id, len(page_rows))
    except Exception:
        logger.exception("Scan %s failed unexpectedly", scan_id)
        db.session.rollback()
        _finish_failed(scan, "An unexpected error occurred during the scan.")
    finally:
        http.close()


def _store_finding(page_row, vuln, result):
    evidence = result.evidence
    if result.detail:
        evidence = f"{evidence}\n\n{result.detail}".strip()
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


def _finish_failed(scan, reason):
    scan.Status = SCAN_STATUS_FAILED
    scan.FinishedAt = datetime.utcnow()
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
