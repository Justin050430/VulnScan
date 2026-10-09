"""
Finding retest / verification (D1).

Re-runs the original detection module against the finding's exact page,
synchronously, and classifies the outcome:

  * Resolved          - the module ran and the original parameter shows no
                        detectable signal any more (verified absence),
  * Still Detected    - the module ran and re-detected the same parameter,
  * Inconclusive      - the verification attempt could not reach a conclusion
                        (the module itself failed while re-testing),
  * Unable to Verify  - the page is unreachable / no longer analysable, or the
                        finding's vulnerability has no implemented module.

The outcome is appended to the finding's evidence as a RETEST stanza; the
finding status changes only when the outcome justifies it (verified absence
-> Resolved, re-detection -> Open).  Nothing is fabricated: every verdict
states the concrete reason it was reached.
"""
import logging
from datetime import datetime

from flask import current_app

from app.scanner.base import PageInfo
from app.scanner.client import HttpClient
from app.scanner.engine import make_url_validator
from app.scanner.registry import get_module_class
from app.utils.constants import FINDING_STATUS_OPEN, FINDING_STATUS_RESOLVED

logger = logging.getLogger("vulnscan.retest")

VERDICT_RESOLVED = "Resolved"
VERDICT_STILL_DETECTED = "Still Detected"
VERDICT_INCONCLUSIVE = "Inconclusive"
VERDICT_UNABLE = "Unable to Verify"

_STANZA_SEPARATOR = "-" * 60


class RetestError(Exception):
    """The retest request itself is invalid (bad finding/scan data)."""


def retest_finding(finding):
    """
    Verify one stored finding synchronously.  Returns a result dict; the
    evidence/status updates are applied to `finding` (caller commits).
    """
    vuln = finding.vulnerability
    page = finding.page
    scan = page.scan if page is not None else None
    if vuln is None or page is None or scan is None:
        raise RetestError("Finding data is incomplete - cannot retest.")

    checked_at = datetime.utcnow()
    module_class = get_module_class(vuln.module_key)
    if module_class is None:
        return _finish(
            finding, checked_at, VERDICT_UNABLE, {},
            "No verification module is implemented for this vulnerability.",
        )

    profile = scan.scan_profile
    allow_private = bool(
        current_app.config.get("SCANNER_ALLOW_PRIVATE_TARGETS", True)
    )
    timeout = float(current_app.config.get("SCANNER_DEFAULT_TIMEOUT", 10))
    verify_ssl = current_app.config.get("SCANNER_VERIFY_SSL", True)
    # Keep the scan's politeness delay, but cap it so a retest stays fast.
    delay_ms = min((profile.RequestDelayMs if profile else 0) or 0, 1000)
    http = HttpClient(
        timeout=timeout,
        delay_ms=delay_ms,
        verify_ssl=verify_ssl,
        url_validator=make_url_validator(
            scan.TargetURL,
            bool(profile.FollowExternalLinks) if profile else False,
            allow_private,
        ),
    )
    try:
        probe = http.get(page.URL)
        if probe is None or probe.status_code is None:
            error = getattr(probe, "error", None) if probe is not None else None
            return _finish(
                finding, checked_at, VERDICT_UNABLE,
                {"RequestsIssued": http.request_count},
                "The page could not be reached for verification"
                + (f": {error}" if error else "."),
            )
        if probe.status_code >= 400:
            return _finish(
                finding, checked_at, VERDICT_UNABLE,
                {"RequestsIssued": http.request_count},
                f"The page now responds with HTTP {probe.status_code}; "
                "it is no longer analysable.",
            )

        try:
            module = module_class(http=http, page=PageInfo(url=page.URL))
            results = module.detect()
        except Exception as exc:
            logger.exception(
                "Retest module %s failed on %s", module_class.key, page.URL
            )
            return _finish(
                finding, checked_at, VERDICT_INCONCLUSIVE,
                {"RequestsIssued": http.request_count},
                f"The verification module failed while re-testing: {exc}.",
            )

        matches = [r for r in results if r.parameter == finding.Parameter]
        if matches:
            best = max(matches, key=lambda r: r.confidence or 0)
            return _finish(
                finding, checked_at, VERDICT_STILL_DETECTED,
                {
                    "Technique": best.technique or "",
                    "Confidence": float(best.confidence or 0),
                    "RequestsIssued": http.request_count,
                },
                f"The original parameter '{finding.Parameter}' was re-detected.",
            )
        return _finish(
            finding, checked_at, VERDICT_RESOLVED,
            {"RequestsIssued": http.request_count},
            f"No detectable signal for parameter '{finding.Parameter}' "
            "in the re-test.",
        )
    finally:
        http.close()


def _finish(finding, checked_at, verdict, extra, message):
    """Append the RETEST stanza, apply the status change and build the result."""
    lines = [
        _STANZA_SEPARATOR,
        f"RETEST {checked_at.strftime('%Y-%m-%d %H:%M')} UTC - {verdict}",
        f"RETEST DETAILS: {message}",
    ]
    if extra.get("Technique"):
        lines.append(f"RETEST TECHNIQUE: {extra['Technique']}")
    if extra.get("Confidence") is not None:
        lines.append(f"RETEST CONFIDENCE: {round(float(extra['Confidence']), 2)}")
    if extra.get("RequestsIssued") is not None:
        lines.append(f"RETEST REQUESTS ISSUED: {extra['RequestsIssued']}")

    if verdict == VERDICT_RESOLVED:
        finding.Status = FINDING_STATUS_RESOLVED
        lines.append(
            "STATUS: finding auto-marked Resolved after verified absence."
        )
    elif verdict == VERDICT_STILL_DETECTED:
        finding.Status = FINDING_STATUS_OPEN
        lines.append(
            "STATUS: finding re-opened (the vulnerability is still present)."
        )
    else:
        lines.append("STATUS: unchanged (manual review recommended).")

    finding.Evidence = (finding.Evidence or "").rstrip() + "\n\n" + "\n".join(lines)
    return {
        "Verdict": verdict,
        "Message": message,
        "CheckedAt": checked_at.isoformat(),
        "Technique": extra.get("Technique"),
        "Confidence": extra.get("Confidence"),
        "RequestsIssued": extra.get("RequestsIssued"),
        "FindingStatus": finding.Status,
    }
