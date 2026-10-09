"""Vulnerability scan endpoints."""
from flask import Blueprint, current_app, jsonify, request, send_file

from app.models import Scan
from app.services import report_service, scan_service
from app.utils.security import any_authenticated, get_current_user, roles_required

scans_bp = Blueprint("scans", __name__, url_prefix="/scans")


def _per_page():
    try:
        return max(1, min(int(request.args.get("per_page", 20)), 100))
    except (TypeError, ValueError):
        return 20


def _page():
    try:
        return max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        return 1


@scans_bp.post("")
@roles_required("Developer")
def start_scan():
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url")
    scan_profile_id = data.get("scan_profile_id")
    scan_name = data.get("scan_name")
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr

    if not scan_profile_id:
        return jsonify({"message": "A scan profile must be selected.", "code": "bad_request"}), 400

    try:
        scan = scan_service.start_scan(
            user, target_url, scan_profile_id,
            scan_name=scan_name, ip_address=ip,
            run_async=bool(current_app.config.get("SCAN_ASYNC", True)),
        )
    except scan_service.ScanServiceError as exc:
        return jsonify({"message": str(exc), "code": "invalid_target"}), 400

    return jsonify({
        "message": "Scan started.",
        "Scan": scan.to_dict(include_relations=False),
    }), 202


@scans_bp.get("")
@any_authenticated
def list_scans():
    user = get_current_user()
    include_all = user.is_administrator
    status = request.args.get("status")
    search = request.args.get("search")
    items, total = scan_service.list_scans(
        user,
        include_all=include_all,
        search=search,
        status=status,
        page=_page(),
        per_page=_per_page(),
    )
    return jsonify({
        "Scans": items,
        "Total": total,
        "Page": _page(),
        "PerPage": _per_page(),
    }), 200


@scans_bp.get("/<int:scan_id>")
@any_authenticated
def scan_detail(scan_id):
    user = get_current_user()
    try:
        scan = scan_service.get_scan(scan_id)
        scan_service.ensure_scan_accessible(user, scan)
        detail = scan_service.get_scan_detail(scan_id)
    except scan_service.ScanNotFoundError as exc:
        return jsonify({"message": str(exc)}), 404
    except scan_service.ScanServiceError as exc:
        return jsonify({"message": str(exc)}), 403
    return jsonify({"Scan": detail}), 200


@scans_bp.get("/<int:scan_id>/progress")
@any_authenticated
def scan_progress(scan_id):
    """Live scan progress (B1): stage, counters and errors, honestly sourced."""
    user = get_current_user()
    try:
        scan = scan_service.get_scan(scan_id)
        scan_service.ensure_scan_accessible(user, scan)
        progress = scan_service.get_scan_progress(scan)
    except scan_service.ScanNotFoundError as exc:
        return jsonify({"message": str(exc)}), 404
    except scan_service.ScanServiceError as exc:
        return jsonify({"message": str(exc)}), 403
    return jsonify({"Progress": progress}), 200


@scans_bp.put("/<int:scan_id>/findings/<int:finding_id>")
@any_authenticated
def update_finding_status(scan_id, finding_id):
    """
    Update a finding's triage status (Open/Resolved/False Positive).
    Extension of the documented scan management API to satisfy FR-08/UI.
    """
    user = get_current_user()
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
    try:
        scan = scan_service.get_scan(scan_id)
        scan_service.ensure_scan_accessible(user, scan)
        finding = scan_service.update_finding_status(
            scan, finding_id, status, user, ip_address=ip
        )
    except scan_service.ScanNotFoundError as exc:
        return jsonify({"message": str(exc)}), 404
    except scan_service.ScanAccessError as exc:
        return jsonify({"message": str(exc)}), 403
    except scan_service.ScanServiceError as exc:
        return jsonify({"message": str(exc)}), 400
    return jsonify({"message": "Finding updated.", "Finding": finding.to_dict()}), 200


@scans_bp.get("/<int:scan_id>/report")
@any_authenticated
def scan_report(scan_id):
    """Export a scan report in PDF (default) or CSV format (FR-13)."""
    user = get_current_user()
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
    fmt = (request.args.get("format") or "pdf").lower()
    try:
        scan = scan_service.get_scan(scan_id)
        scan_service.ensure_scan_accessible(user, scan)
    except scan_service.ScanNotFoundError as exc:
        return jsonify({"message": str(exc)}), 404
    except scan_service.ScanServiceError as exc:
        return jsonify({"message": str(exc)}), 403

    if fmt == "csv":
        content = report_service.build_csv(scan, scan.findings, scan.pages)
        scan_service.export_report(scan, user, ip_address=ip)
        from io import BytesIO

        buf = BytesIO(content.encode("utf-8-sig"))
        return send_file(
            buf,
            mimetype="text/csv",
            as_attachment=True,
            download_name=f"vulnscan-scan-{scan.ScanID}.csv",
        )
    elif fmt == "pdf":
        pdf = report_service.build_pdf(scan, scan.findings, scan.pages)
        scan_service.export_report(scan, user, ip_address=ip)
        from io import BytesIO

        buf = BytesIO(pdf)
        return send_file(
            buf,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"vulnscan-scan-{scan.ScanID}.pdf",
        )
    return jsonify({"message": "format must be 'pdf' or 'csv'."}), 400
