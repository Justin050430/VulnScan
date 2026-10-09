"""
Scan management service - creates and manages vulnerability scans.

Scans execute in a background worker thread so the API can return immediately
and the UI can poll the scan status (Pending -> Running -> Completed/Failed).
"""
import logging
import threading
from datetime import datetime
from urllib.parse import parse_qsl, urlparse

from flask import current_app
from sqlalchemy import func

from app.extensions import db
from app.models import DiscoveredPage, Finding, Scan, ScanProfile, Vulnerability
from app.services.audit_service import write_audit
from app.scanner.engine import ScanValidationError, run_scan, validate_scan_request
from app.utils.constants import (
    AUDIT_CATEGORY_REPORT,
    AUDIT_CATEGORY_SCAN,
    FINDING_STATUSES,
    SCAN_STATUS_CANCELLED,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUSES,
    SEVERITIES,
)

logger = logging.getLogger("vulnscan.scans")


class ScanServiceError(Exception):
    pass


class ScanNotFoundError(ScanServiceError):
    pass


class ScanAccessError(ScanServiceError):
    """Raised when a user attempts to access another user's scan."""


def get_scan(scan_id):
    return db.session.get(Scan, int(scan_id))


def _default_scan_name(target_url):
    from urllib.parse import urlparse

    host = urlparse(target_url).netloc
    return f"Vulnerability Scan - {host}"


def start_scan(user, target_url, scan_profile_id, scan_name=None, ip_address=None,
               run_async=True):
    """
    Validate and start a scan.  Returns the created Scan.
    When run_async is False the scan runs synchronously (used by tests).
    """
    profile = db.session.get(ScanProfile, int(scan_profile_id)) if scan_profile_id else None
    try:
        normalised_target = validate_scan_request(target_url, profile)
    except ScanValidationError as exc:
        raise ScanServiceError(str(exc)) from exc

    if not scan_name or not str(scan_name).strip():
        scan_name = _default_scan_name(normalised_target)
    scan_name = str(scan_name).strip()
    if len(scan_name) > 100:
        scan_name = scan_name[:100]

    scan = Scan(
        ScanName=scan_name,
        TargetURL=normalised_target,
        Status=SCAN_STATUS_PENDING,
        StartedAt=datetime.utcnow(),
        UserID=user.UserID,
        ScanProfileID=profile.ScanProfileID,
    )
    db.session.add(scan)
    db.session.flush()
    write_audit(
        category=AUDIT_CATEGORY_SCAN,
        action="SCAN_CREATED",
        description=f"Vulnerability scan '{scan.ScanName}' created for target "
                    f"{scan.TargetURL} using profile '{profile.Name}'.",
        user=user,
        entity_type="Scan",
        entity_id=scan.ScanID,
        ip_address=ip_address,
        commit=True,
    )

    if run_async:
        _spawn_scan_worker(scan.ScanID)
    else:
        _execute_in_context(scan.ScanID)
        # Synchronous run: refresh so callers observe the final status.
        db.session.expire(scan)
    return scan


def _spawn_scan_worker(scan_id):
    app = current_app._get_current_object()
    thread = threading.Thread(
        target=_execute_in_context,
        args=(scan_id,),
        kwargs={"app": app},
        daemon=True,
        name=f"scan-{scan_id}",
    )
    thread.start()


def _execute_in_context(scan_id, app=None):
    app = app or current_app._get_current_object()
    try:
        with app.app_context():
            run_scan(scan_id)
    except Exception:
        logger.exception("Scan worker %s crashed", scan_id)
        try:
            from app.scanner import progress

            progress.finish(scan_id, "failed", error="Scan worker crashed")
        except Exception:
            pass
        try:
            with app.app_context():
                scan = db.session.get(Scan, int(scan_id))
                if scan and scan.Status not in (SCAN_STATUS_COMPLETED,):
                    scan.Status = "Failed"
                    scan.FinishedAt = datetime.utcnow()
                    db.session.commit()
        except Exception:
            logger.exception("Failed to mark scan %s as failed", scan_id)


def _finding_stats(scan_ids):
    """Return {scan_id: {total, by_severity:{...}, pages}} aggregates."""
    if not scan_ids:
        return {}
    page_count_rows = (
        db.session.query(DiscoveredPage.ScanID, func.count(DiscoveredPage.PageID))
        .filter(DiscoveredPage.ScanID.in_(scan_ids))
        .group_by(DiscoveredPage.ScanID)
        .all()
    )
    sev_rows = (
        db.session.query(DiscoveredPage.ScanID, Finding.Severity, func.count(Finding.FindingID))
        .join(Finding, Finding.PageID == DiscoveredPage.PageID)
        .filter(DiscoveredPage.ScanID.in_(scan_ids))
        .group_by(DiscoveredPage.ScanID, Finding.Severity)
        .all()
    )
    result = {}
    for scan_id in scan_ids:
        result[scan_id] = {
            "PageCount": 0,
            "FindingCount": 0,
            "SeverityCounts": {s: 0 for s in SEVERITIES},
        }
    for scan_id, count in page_count_rows:
        result[scan_id]["PageCount"] = count
    for scan_id, severity, count in sev_rows:
        bucket = result[scan_id]
        bucket["FindingCount"] += count
        bucket["SeverityCounts"][severity] = bucket["SeverityCounts"].get(severity, 0) + count
    return result


def list_scans(user, include_all=False, search=None, status=None, page=1, per_page=20):
    query = Scan.query
    if not include_all and not user.is_administrator:
        query = query.filter_by(UserID=user.UserID)
    if status and status in SCAN_STATUSES:
        query = query.filter_by(Status=status)
    if search:
        like = f"%{search.strip()}%"
        query = query.filter(
            db.or_(Scan.ScanName.ilike(like), Scan.TargetURL.ilike(like))
        )
    total = query.count()
    items = (
        query.order_by(Scan.StartedAt.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    stats = _finding_stats([s.ScanID for s in items])
    result = []
    for scan in items:
        data = scan.to_dict(include_relations=False)
        data.update(stats.get(scan.ScanID, {
            "PageCount": 0, "FindingCount": 0,
            "SeverityCounts": {s: 0 for s in SEVERITIES},
        }))
        result.append(data)
    return result, total


def get_scan_detail(scan_id):
    scan = get_scan(scan_id)
    if scan is None:
        raise ScanNotFoundError("Scan not found.")
    findings = sorted(
        scan.findings,
        key=lambda f: (f.severity_rank, f.DetectedAt or datetime.min),
        reverse=True,
    )
    pages = [p.to_dict() for p in sorted(scan.pages, key=lambda p: p.DiscoveryOrder)]
    data = scan.to_dict(include_relations=False)
    data["Pages"] = pages
    data["Findings"] = [f.to_dict() for f in findings]
    data["SeverityCounts"] = {s: 0 for s in SEVERITIES}
    for f in findings:
        data["SeverityCounts"][f.Severity] = data["SeverityCounts"].get(f.Severity, 0) + 1
    data["FindingCount"] = len(findings)
    data["PageCount"] = len(pages)
    # Overall risk label from the most severe finding.
    data["OverallRisk"] = _overall_risk(findings)

    # ---------------------------------------------------- coverage (B2)
    analysed_pages = [
        p for p in scan.pages
        if p.HTTPStatus is not None and p.HTTPStatus < 400
    ]
    skipped_pages = [
        p for p in scan.pages
        if p.HTTPStatus is None or p.HTTPStatus >= 400
    ]
    tested_parameters = set()
    for p in analysed_pages:
        for name, _value in parse_qsl(urlparse(p.URL).query,
                                      keep_blank_values=True):
            tested_parameters.add(name)
    data["AnalysedPages"] = len(analysed_pages)
    data["SkippedPages"] = [
        {"PageID": p.PageID, "URL": p.URL, "HTTPStatus": p.HTTPStatus}
        for p in skipped_pages
    ]
    data["TestedParameters"] = sorted(tested_parameters)
    data["CoverageNote"] = (
        f"{len(analysed_pages)} of {len(scan.pages)} discovered page(s) were "
        "analysed. Only GET query-string parameters are tested (no POST "
        "bodies, form submission, JavaScript-rendered content or "
        "authenticated pages); pages skipped due to a non-success HTTP "
        "status are listed in SkippedPages and were not tested."
    )
    return data


def _overall_risk(findings):
    if not findings:
        return "None"
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return max((f.Severity for f in findings), key=lambda s: order.get(s, 0))


def get_scan_progress(scan):
    """
    Live progress for a scan (B1).

    Live counters come from the in-memory progress registry when the scan ran
    in this process; otherwise the response is derived from the database and
    `LiveAvailable` is false.  Values that cannot be measured reliably
    (e.g. request counts after a restart) are returned as null - never
    fabricated.
    """
    from app.scanner.progress import snapshot

    page_count = (
        db.session.query(func.count(DiscoveredPage.PageID))
        .filter(DiscoveredPage.ScanID == scan.ScanID)
        .scalar()
        or 0
    )
    finding_count = (
        db.session.query(func.count(Finding.FindingID))
        .join(DiscoveredPage, Finding.PageID == DiscoveredPage.PageID)
        .filter(DiscoveredPage.ScanID == scan.ScanID)
        .scalar()
        or 0
    )
    by_module = (
        db.session.query(Vulnerability.Name, func.count(Finding.FindingID))
        .join(Finding, Finding.VulnerabilityID == Vulnerability.VulnerabilityID)
        .join(DiscoveredPage, Finding.PageID == DiscoveredPage.PageID)
        .filter(DiscoveredPage.ScanID == scan.ScanID)
        .group_by(Vulnerability.Name)
        .all()
    )

    terminal = scan.Status in (
        SCAN_STATUS_COMPLETED, SCAN_STATUS_FAILED, SCAN_STATUS_CANCELLED,
    )
    live = snapshot(scan.ScanID)
    if live is not None:
        live_available = True
        stage = live["stage"]
        pages_found = live["pages_found"]
        pages_analysed = live["pages_done"]
        requests_issued = live["requests"]
        errors = live["errors"]
        failure_reason = live["error"]
    else:
        live_available = False
        stage = (scan.Status or "unknown").lower()
        pages_found = page_count
        pages_analysed = page_count if terminal else None
        requests_issued = None
        errors = []
        failure_reason = None

    if scan.FinishedAt and scan.StartedAt:
        elapsed = (scan.FinishedAt - scan.StartedAt).total_seconds()
    elif scan.StartedAt:
        elapsed = (datetime.utcnow() - scan.StartedAt).total_seconds()
    else:
        elapsed = None

    return {
        "ScanID": scan.ScanID,
        "Status": scan.Status,
        "Stage": stage,
        "LiveAvailable": live_available,
        "PagesFound": pages_found,
        "PagesAnalysed": pages_analysed,
        "PageCount": page_count,
        "FindingCount": finding_count,
        "FindingsByModule": [
            {"Name": name, "Count": count} for name, count in by_module
        ],
        "RequestsIssued": requests_issued,
        "Errors": errors,
        "FailureReason": failure_reason,
        "StartedAt": scan.StartedAt.isoformat() if scan.StartedAt else None,
        "FinishedAt": scan.FinishedAt.isoformat() if scan.FinishedAt else None,
        "ElapsedSeconds": round(elapsed, 1) if elapsed is not None else None,
    }


def ensure_scan_accessible(user, scan):
    """Admins may view any scan; developers only their own."""
    if scan is None:
        raise ScanNotFoundError("Scan not found.")
    if user.is_administrator or scan.UserID == user.UserID:
        return True
    raise ScanAccessError("You do not have access to this scan.")


def update_finding_status(scan, finding_id, status, user, ip_address=None):
    if status not in FINDING_STATUSES:
        raise ScanServiceError(
            f"Status must be one of: {', '.join(FINDING_STATUSES)}."
        )
    finding = db.session.get(Finding, int(finding_id))
    if finding is None:
        raise ScanServiceError("Finding not found.")
    if finding.page is None or finding.page.ScanID != scan.ScanID:
        raise ScanServiceError("Finding does not belong to this scan.")
    finding.Status = status
    db.session.commit()
    write_audit(
        category=AUDIT_CATEGORY_SCAN,
        action="FINDING_STATUS_UPDATED",
        description=f"Finding {finding.FindingID} ({finding.vulnerability.Name}) "
                    f"on scan {scan.ScanID} marked as {status}.",
        user=user,
        entity_type="Finding",
        entity_id=finding.FindingID,
        ip_address=ip_address,
        commit=True,
    )
    return finding


def export_report(scan, user, ip_address=None):
    """Record a report-export audit event (caller performs the generation)."""
    write_audit(
        category=AUDIT_CATEGORY_REPORT,
        action="REPORT_EXPORTED",
        description=f"Scan report exported for scan '{scan.ScanName}' "
                    f"(scan {scan.ScanID}).",
        user=user,
        entity_type="Scan",
        entity_id=scan.ScanID,
        ip_address=ip_address,
        commit=True,
    )
