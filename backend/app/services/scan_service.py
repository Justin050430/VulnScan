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
from app.models import (
    DiscoveredPage,
    Finding,
    Scan,
    ScanProfile,
    TrustProjectMembership,
    TrustScanContext,
    Vulnerability,
)
from app.services.audit_service import write_audit
from app.scanner.engine import ScanValidationError, run_scan, validate_scan_request
from app.utils.constants import (
    AUDIT_CATEGORY_REPORT,
    AUDIT_CATEGORY_SCAN,
    AUDIT_CATEGORY_SYSTEM,
    AUDIT_STATUS_FAILURE,
    FINDING_STATUSES,
    SCAN_STATUS_CANCELLED,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
    SCAN_STATUSES,
    SEVERITIES,
)

logger = logging.getLogger("vulnscan.scans")

#: Upper bound on the locations one group-retest request may re-verify, so a
#: single call cannot turn into an unbounded burst of network work.
MAX_GROUP_RETEST_LOCATIONS = 25
#: Bound on the finding IDs quoted in one group audit record.
MAX_AUDIT_FINDING_IDS = 50


class ScanServiceError(Exception):
    pass


class ScanNotFoundError(ScanServiceError):
    pass


class ScanGroupNotFoundError(ScanNotFoundError):
    """Raised when a logical finding group does not exist in this scan."""


class ScanAccessError(ScanServiceError):
    """Raised when a user attempts to access another user's scan."""


def get_scan(scan_id):
    return db.session.get(Scan, int(scan_id))


def _default_scan_name(target_url):
    from urllib.parse import urlparse

    host = urlparse(target_url).netloc
    return f"Vulnerability Scan - {host}"


def _active_scans_query():
    return Scan.query.filter(
        Scan.Status.in_((SCAN_STATUS_PENDING, SCAN_STATUS_RUNNING))
    )


def _enforce_active_scan_caps(user):
    """
    Reject a new scan when the configured concurrency caps are reached (F2).

    Counts are read from the database, so they hold across workers; scans
    orphaned by a restart are failed at startup (F1) and therefore never
    block new work.
    """
    per_user = int(current_app.config.get("SCAN_MAX_ACTIVE_PER_USER", 3) or 0)
    global_cap = int(current_app.config.get("SCAN_MAX_ACTIVE_GLOBAL", 5) or 0)
    if per_user > 0:
        mine = _active_scans_query().filter(Scan.UserID == user.UserID).count()
        if mine >= per_user:
            raise ScanServiceError(
                f"You already have {mine} active scan(s); wait for one to "
                f"finish before starting another (limit {per_user})."
            )
    if global_cap > 0:
        total = _active_scans_query().count()
        if total >= global_cap:
            raise ScanServiceError(
                f"The scanner is busy with {total} active scan(s); try again "
                f"shortly (limit {global_cap})."
            )


def recover_orphan_scans():
    """
    Fail scans left Pending/Running by a previous process (F1).

    A scan is only recovered when the in-memory progress registry has no
    unfinished entry for it - scans running in this process are never touched.
    Returns the list of recovered scan IDs.
    """
    from app.scanner import progress

    orphans = (
        Scan.query
        .filter(Scan.Status.in_((SCAN_STATUS_PENDING, SCAN_STATUS_RUNNING)))
        .all()
    )
    recovered = []
    for scan in orphans:
        snap = progress.snapshot(scan.ScanID)
        if snap is not None and not snap.get("finished"):
            continue  # alive in this process
        scan.Status = SCAN_STATUS_FAILED
        scan.FinishedAt = datetime.utcnow()
        recovered.append(scan.ScanID)
    if recovered:
        write_audit(
            category=AUDIT_CATEGORY_SYSTEM,
            action="ORPHAN_SCANS_RECOVERED",
            description=(
                f"Startup recovery marked {len(recovered)} orphaned scan(s) "
                f"as Failed (interrupted before the last restart): {recovered}."
            ),
            entity_type="Scan",
            status=AUDIT_STATUS_FAILURE,
            commit=False,
        )
        db.session.commit()
        _release_orphaned_credits(recovered)
    return recovered


def _release_orphaned_credits(scan_ids):
    """Return credits reserved for scans that were orphaned before starting."""
    try:
        from app.services.scan_gate_service import release_if_never_started

        for scan_id in scan_ids:
            release_if_never_started(scan_id, "Scan was orphaned before starting")
    except Exception:
        logger.exception("Failed to release credits for orphaned scans")


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

    _enforce_active_scan_caps(user)

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


def spawn_scan_worker(scan_id):
    """Public entry point used by the Trust Boundary scan gate."""
    _spawn_scan_worker(scan_id)


def execute_scan_sync(scan_id):
    """Run a scan synchronously (tests / synchronous deployments)."""
    _execute_in_context(scan_id)


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

    # Consolidated issue counts for the same page of scans (P3, additive).
    from app.services import grouping_service

    issues = grouping_service.issue_counts_for_scans(scan_ids)
    for scan_id, bucket in result.items():
        extra = issues.get(scan_id) or {}
        bucket["IssueCount"] = extra.get("IssueCount", 0)
        bucket["IssueSeverityCounts"] = extra.get("IssueSeverityCounts", {})
    return result


def list_scans(user, include_all=False, search=None, status=None, page=1, per_page=20):
    query = Scan.query
    if include_all and user.is_administrator:
        # Administrators see legacy scans plus only the trust-scoped scans of
        # projects they belong to (no cross-tenant exposure).
        accessible = _accessible_project_ids(user)
        accessible_scan_ids = db.session.query(TrustScanContext.ScanID).filter(
            TrustScanContext.ProjectID.in_(accessible)
        )
        trust_scan_ids = db.session.query(TrustScanContext.ScanID)
        query = query.filter(
            db.or_(
                ~Scan.ScanID.in_(trust_scan_ids),
                Scan.ScanID.in_(accessible_scan_ids),
            )
        )
    elif not include_all and not user.is_administrator:
        query = query.filter_by(UserID=user.UserID)
    elif not include_all:
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

    # Logical consolidation (P3): the flat finding list stays the source of
    # truth, and the group view is derived from it on every request.
    from app.services import grouping_service

    groups, identities = grouping_service.build_groups(findings)
    finding_dicts = []
    for finding in findings:
        entry = finding.to_dict()
        key, size = identities.get(finding.FindingID, (None, 1))
        entry["GroupKey"] = key
        entry["GroupSize"] = size
        finding_dicts.append(entry)
    data["Findings"] = finding_dicts
    data["FindingGroups"] = groups
    data["IssueCount"] = len(groups)
    data["IssueSeverityCounts"] = {s: 0 for s in SEVERITIES}
    for group in groups:
        data["IssueSeverityCounts"][group["Severity"]] = (
            data["IssueSeverityCounts"].get(group["Severity"], 0) + 1
        )
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

    from app.services import coverage_service, credential_service

    credential = credential_service.credential_for_scan(scan.ScanID)
    if credential is None:
        data["Authentication"] = {"Mode": coverage_service.AUTH_ANONYMOUS}
    else:
        data["Authentication"] = {
            "Mode": (
                coverage_service.AUTH_FAILED
                if credential.FailureReason
                else coverage_service.AUTH_AUTHENTICATED
            ),
            "CredentialID": credential.CredentialID,
            "CredentialName": credential.Name,
            "ApprovedByUserID": credential.ApprovedByUserID,
            "ExpiresAt": (
                credential.ExpiresAt.isoformat() if credential.ExpiresAt else None
            ),
            "AvailableForRetest": credential.is_available_for_retest(),
        }

    # One structured description of what this scan actually covered; the
    # reports render the same structure so they cannot contradict it.
    coverage = coverage_service.build_coverage(scan, pages=scan.pages)
    data["Coverage"] = coverage
    data["CoverageNote"] = coverage_service.coverage_note(coverage)
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
    """Admins may view any legacy scan; developers only their own.

    Trust-scoped scans are additionally protected by project membership and
    tenant isolation: a platform administrator without membership is denied.
    """
    if scan is None:
        raise ScanNotFoundError("Scan not found.")
    context = db.session.get(TrustScanContext, scan.ScanID)
    if context is not None:
        from app.trust.constants import PERM_SCAN_READ
        from app.trust.permissions import TrustError, resolve_project

        try:
            access = resolve_project(user, context.ProjectID)
        except TrustError:
            raise ScanAccessError("You do not have access to this scan.") from None
        if access.has(PERM_SCAN_READ) or scan.UserID == user.UserID:
            return True
        raise ScanAccessError("You do not have access to this scan.")
    if user.is_administrator or scan.UserID == user.UserID:
        return True
    raise ScanAccessError("You do not have access to this scan.")


def ensure_scan_permission(user, scan, permission):
    """Enforce a specific project permission for a trust-scoped scan.

    Legacy (non-trust) scans keep the historical owner/administrator rule.
    """
    if scan is None:
        raise ScanNotFoundError("Scan not found.")
    context = db.session.get(TrustScanContext, scan.ScanID)
    if context is None:
        if user.is_administrator or scan.UserID == user.UserID:
            return True
        raise ScanAccessError("You do not have access to this scan.")

    from app.trust.permissions import TrustError, resolve_project

    try:
        access = resolve_project(user, context.ProjectID)
    except TrustError:
        raise ScanAccessError("You do not have access to this scan.") from None
    if access.has(permission):
        return True
    raise ScanAccessError(
        "You do not have permission to perform this action on this scan."
    )


def _accessible_project_ids(user):
    return [
        row.ProjectID
        for row in TrustProjectMembership.query.filter_by(
            UserID=user.UserID, Status="Active"
        ).all()
    ]


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


def retest_finding(scan, finding_id, user, ip_address=None):
    """
    Synchronously re-verify one finding against its exact page (D1).

    Returns (finding, retest_result); commits the evidence/status changes
    and writes an audit record.
    """
    from app.scanner.retest import RetestError, retest_finding as run_retest

    finding = db.session.get(Finding, int(finding_id))
    if finding is None:
        raise ScanServiceError("Finding not found.")
    if finding.page is None or finding.page.ScanID != scan.ScanID:
        raise ScanServiceError("Finding does not belong to this scan.")
    try:
        result = run_retest(finding)
    except RetestError as exc:
        raise ScanServiceError(str(exc)) from exc
    db.session.commit()
    write_audit(
        category=AUDIT_CATEGORY_SCAN,
        action="FINDING_RETESTED",
        description=f"Finding {finding.FindingID} "
                    f"({finding.vulnerability.Name}) on scan {scan.ScanID} "
                    f"re-tested: {result['Verdict']}.",
        user=user,
        entity_type="Finding",
        entity_id=finding.FindingID,
        ip_address=ip_address,
        commit=True,
    )
    return finding, result


# ---------------------------------------------------------------- groups (P3)
def _resolve_group(scan, group_key):
    """
    Resolve a logical finding group inside `scan` (never across scans).

    Returns ``(group, members)``; raises `ScanGroupNotFoundError` when the key
    does not match any finding of this scan.
    """
    from app.services import grouping_service

    key = (group_key or "").strip()
    group = members = None
    if key:
        group, members = grouping_service.find_group(scan.findings, key)
    if group is None:
        raise ScanGroupNotFoundError(
            "Finding group not found in this scan."
        )
    return group, members


def _refresh_group(scan, group_key):
    """Rebuild the group from committed data (after a write)."""
    from app.services import grouping_service

    db.session.expire_all()
    group, _members = grouping_service.find_group(scan.findings, group_key)
    return group


def _audit_id_list(finding_ids):
    ids = [str(finding_id) for finding_id in finding_ids]
    if len(ids) > MAX_AUDIT_FINDING_IDS:
        remaining = len(ids) - MAX_AUDIT_FINDING_IDS
        ids = ids[:MAX_AUDIT_FINDING_IDS] + [f"+{remaining} more"]
    return ", ".join(ids)


def update_finding_group_status(scan, group_key, status, user, ip_address=None):
    """
    Apply one triage status to every record of a logical group (P3).

    The group itself stores nothing: its status stays derived from the member
    records, so a group can never be reported resolved while a location is
    still open.  One audit record lists the findings that actually changed.
    """
    if status not in FINDING_STATUSES:
        raise ScanServiceError(
            f"Status must be one of: {', '.join(FINDING_STATUSES)}."
        )
    group, members = _resolve_group(scan, group_key)
    previous = {member.FindingID: member.Status for member in members}
    changed = [member for member in members if member.Status != status]
    for member in changed:
        member.Status = status
    db.session.commit()

    refreshed = _refresh_group(scan, group["GroupKey"])
    write_audit(
        category=AUDIT_CATEGORY_SCAN,
        action="FINDING_GROUP_STATUS_UPDATED",
        description=(
            f"Finding group '{group['GroupKey']}' "
            f"({group['VulnerabilityName']}) on scan {scan.ScanID} marked as "
            f"{status}: {len(changed)} of {len(members)} finding(s) updated. "
            "Findings: "
            + (
                ", ".join(
                    f"{member.FindingID} ({previous[member.FindingID]} -> "
                    f"{status})"
                    for member in changed
                ) or "none (all already had that status)"
            )
        ),
        user=user,
        entity_type="Scan",
        entity_id=scan.ScanID,
        ip_address=ip_address,
        commit=True,
    )
    return refreshed, changed, previous


def retest_finding_group(scan, group_key, user, ip_address=None):
    """
    Re-verify a logical group, one record at a time (P3).

    Each location is re-tested with the existing per-finding logic and its
    result is committed immediately, so no database transaction is held open
    across network work and an unexpected failure later cannot discard the
    results already obtained.  Locations beyond
    `MAX_GROUP_RETEST_LOCATIONS` are reported as ``Not Run`` - never as
    resolved.
    """
    from app.scanner.retest import retest_finding as run_retest

    from app.services import grouping_service

    group, members = _resolve_group(scan, group_key)
    members = sorted(members, key=lambda finding: finding.FindingID or 0)
    attempted = members[:MAX_GROUP_RETEST_LOCATIONS]
    skipped = members[MAX_GROUP_RETEST_LOCATIONS:]

    results = []
    completed = 0
    failed = 0
    for finding in attempted:
        finding_id = finding.FindingID
        page_url = finding.page.URL if finding.page else None
        try:
            result = run_retest(finding)
            # Persist this location before touching the network again.
            db.session.commit()
            completed += 1
            results.append({
                "FindingID": finding_id,
                "URL": page_url,
                "Verdict": result["Verdict"],
                "Message": result["Message"],
                "Status": result["FindingStatus"],
                "Failed": False,
            })
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            # Discard only this location's partial work; earlier commits stand.
            db.session.rollback()
            failed += 1
            logger.exception(
                "Group retest of %s failed on finding %s", group_key, finding_id
            )
            results.append({
                "FindingID": finding_id,
                "URL": page_url,
                "Verdict": "Inconclusive",
                "Message": f"Unexpected failure during the retest: {exc}",
                "Status": None,
                "Failed": True,
            })

    for finding in skipped:
        results.append({
            "FindingID": finding.FindingID,
            "URL": finding.page.URL if finding.page else None,
            "Verdict": "Not Run",
            "Message": (
                "Not retested: this request re-verifies at most "
                f"{MAX_GROUP_RETEST_LOCATIONS} locations; run the retest "
                "again to continue."
            ),
            "Status": None,
            "Failed": False,
        })

    verdict = grouping_service.aggregate_verdict(
        [entry["Verdict"] for entry in results]
    )
    partial = bool(failed or skipped)
    if verdict == "Resolved" and partial:
        # Never claim a group is resolved when part of it was not verified.
        verdict = "Inconclusive"
    refreshed = _refresh_group(scan, group["GroupKey"])
    write_audit(
        category=AUDIT_CATEGORY_SCAN,
        action="FINDING_GROUP_RETESTED",
        description=(
            f"Finding group '{group['GroupKey']}' "
            f"({group['VulnerabilityName']}) on scan {scan.ScanID} re-tested: "
            f"{completed} completed, {failed} failed, {len(skipped)} not "
            f"attempted (limit {MAX_GROUP_RETEST_LOCATIONS}); aggregate "
            f"verdict {verdict}. Completed findings: "
            + (
                _audit_id_list([
                    entry["FindingID"] for entry in results
                    if not entry["Failed"] and entry["Verdict"] != "Not Run"
                ]) or "none"
            )
        ),
        user=user,
        entity_type="Scan",
        entity_id=scan.ScanID,
        ip_address=ip_address,
        commit=True,
    )
    return refreshed, {
        "AggregateVerdict": verdict,
        "Partial": partial,
        "Completed": completed,
        "Failed": failed,
        "NotAttempted": len(skipped),
        "Limit": MAX_GROUP_RETEST_LOCATIONS,
        "Results": results,
    }


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
