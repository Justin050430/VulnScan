"""
Scan report generation (PDF and CSV) - FR-13.

Produces a structured report summarising detected vulnerabilities, risk levels
and remediation guidance for a completed scan.
"""
import csv
import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.utils.constants import SEVERITY_ORDER, SEVERITIES

SEVERITY_COLORS = {
    "None": colors.grey,
    "Low": colors.blue,
    "Medium": colors.orange,
    "High": colors.HexColor("#E67E22"),
    "Critical": colors.HexColor("#C0392B"),
}


def build_csv(scan, findings, pages):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["VulnScan Scan Report"])
    writer.writerow(["Generated At", datetime.utcnow().isoformat()])
    writer.writerow(["Scan ID", scan.ScanID])
    writer.writerow(["Scan Name", scan.ScanName])
    writer.writerow(["Target URL", scan.TargetURL])
    writer.writerow(["Scan Profile", scan.scan_profile.Name if scan.scan_profile else ""])
    writer.writerow(["Status", scan.Status])
    writer.writerow(["Started At", scan.StartedAt.isoformat() if scan.StartedAt else ""])
    writer.writerow(["Finished At", scan.FinishedAt.isoformat() if scan.FinishedAt else ""])
    writer.writerow(["Started By", scan.user.Email if scan.user else ""])
    writer.writerow([])
    writer.writerow(["DISCOVERED PAGES"])
    writer.writerow(["Order", "URL", "Title", "HTTP Status", "Depth"])
    for p in sorted(pages, key=lambda x: x.DiscoveryOrder):
        writer.writerow([p.DiscoveryOrder, p.URL, p.PageTitle or "", p.HTTPStatus, p.CrawlDepth])
    writer.writerow([])
    writer.writerow(["FINDINGS"])
    writer.writerow([
        "Finding ID", "Vulnerability", "OWASP Category", "Severity",
        "CVSS Score", "Confidence", "Classification", "Method", "Parameter",
        "Payload", "Status", "URL", "Evidence",
        "Technique", "CVSS Vector", "Latest Verdict", "Retest Count",
    ])
    for f in findings:
        retests = f.retest_entries()
        writer.writerow([
            f.FindingID,
            f.vulnerability.Name if f.vulnerability else "",
            f.vulnerability.OWASPCategory if f.vulnerability else "",
            f.Severity,
            f.RiskScore if f.RiskScore is not None else "",
            f.Confidence if f.Confidence is not None else "",
            f.classification,
            f.RequestMethod or "",
            f.Parameter or "",
            (f.Payload or "").replace("\n", " ")[:500],
            f.Status,
            f.page.URL if f.page else "",
            (f.Evidence or "").replace("\n", " ")[:1000],
            f.evidence_technique() or "",
            f.evidence_vector() or "",
            retests[-1]["Verdict"] if retests else "",
            len(retests),
        ])
    writer.writerow([])
    writer.writerow(["VERIFICATION (RETESTS)"])
    writer.writerow([
        "Finding ID", "Vulnerability", "Parameter", "Checked At", "Verdict",
        "Confidence", "Requests Issued",
    ])
    for f in findings:
        for r in f.retest_entries():
            writer.writerow([
                f.FindingID,
                f.vulnerability.Name if f.vulnerability else "",
                f.Parameter or "",
                r["At"],
                r["Verdict"],
                r["Confidence"] if r["Confidence"] is not None else "",
                r["RequestsIssued"] if r["RequestsIssued"] is not None else "",
            ])
    return output.getvalue()


def build_pdf(scan, findings, pages):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        title=f"VulnScan Scan Report - {scan.ScanName}",
        author="VulnScan",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleX", parent=styles["Title"], fontSize=18, spaceAfter=6
    )
    h2 = ParagraphStyle("H2X", parent=styles["Heading2"], fontSize=12, spaceBefore=10)
    small = ParagraphStyle(
        "SmallX", parent=styles["Normal"], fontSize=9, leading=12
    )

    story = []
    story.append(Paragraph("VulnScan Vulnerability Scan Report", title_style))
    story.append(Spacer(1, 4))
    meta = [
        ["Scan ID", f"#{scan.ScanID}", "Scan Name", scan.ScanName],
        ["Target URL", scan.TargetURL, "Scan Profile",
         scan.scan_profile.Name if scan.scan_profile else "-"],
        ["Status", scan.Status, "Started By",
         scan.user.Email if scan.user else "-"],
        ["Started At", scan.StartedAt.isoformat() if scan.StartedAt else "-",
         "Finished At", scan.FinishedAt.isoformat() if scan.FinishedAt else "-"],
    ]
    meta_tbl = Table(meta, colWidths=[28 * mm, 67 * mm, 28 * mm, 67 * mm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0B2447")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#0B2447")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(meta_tbl)

    # Summary
    story.append(Paragraph("Summary", h2))
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.Severity] = counts.get(f.Severity, 0) + 1
    summary_rows = [["Severity", "Count"]]
    for s in SEVERITIES:
        summary_rows.append([s, counts[s]])
    summary_rows.append(["Total", len(findings)])
    sum_tbl = Table(summary_rows, colWidths=[50 * mm, 40 * mm])
    sum_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B2447")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(sum_tbl)

    # --------------------------------------------------------- risk overview
    story.append(Paragraph("Risk Overview", h2))
    confirmed = [f for f in findings if f.classification == "Confirmed"]
    suspected = [f for f in findings if f.classification == "Suspected"]
    overall = "None"
    for s in reversed(SEVERITIES):
        if counts.get(s):
            overall = s
            break
    overview = [
        f"<b>Overall risk:</b> {overall}",
        f"<b>Evidence quality:</b> {len(confirmed)} confirmed, "
        f"{len(suspected)} suspected",
    ]
    if findings:
        top = max(findings, key=lambda f: float(f.RiskScore or 0))
        overview.append(
            f"<b>Highest-risk finding:</b> "
            f"{top.vulnerability.Name if top.vulnerability else 'Finding'} "
            f"(CVSS {float(top.RiskScore):.1f}) on {top.page.URL if top.page else '-'}"
        )
    retested = [f for f in findings if f.retest_entries()]
    resolved = [f for f in retested if f.retest_entries()[-1]["Verdict"] == "Resolved"]
    still = [f for f in retested
             if f.retest_entries()[-1]["Verdict"] == "Still Detected"]
    if retested:
        overview.append(
            f"<b>Verification:</b> {len(retested)} finding(s) re-tested - "
            f"{len(resolved)} resolved, {len(still)} still detected, "
            f"{len(retested) - len(resolved) - len(still)} inconclusive/other"
        )
    else:
        overview.append("<b>Verification:</b> no findings have been re-tested yet")
    for line in overview:
        story.append(Paragraph(line, small))

    # ------------------------------------------------- methodology & coverage
    story.append(Paragraph("Methodology and Coverage", h2))
    profile = scan.scan_profile
    if profile is not None:
        story.append(Paragraph(
            f"<b>Crawl limits:</b> depth up to {profile.MaxDepth}, at most "
            f"{profile.MaxPages} page(s), at least {profile.RequestDelayMs} ms "
            "between requests. Only the target's own host is in scope unless "
            "external links are enabled in the profile.", small))
    from urllib.parse import parse_qsl, urlparse

    analysed = [p for p in pages if p.HTTPStatus is not None and p.HTTPStatus < 400]
    skipped = [p for p in pages if p.HTTPStatus is None or p.HTTPStatus >= 400]
    params = set()
    for p in analysed:
        for name, _v in parse_qsl(urlparse(p.URL).query, keep_blank_values=True):
            params.add(name)
    story.append(Paragraph(
        f"<b>Coverage:</b> {len(analysed)} of {len(pages)} discovered page(s) "
        f"analysed; {len(skipped)} page(s) stored but skipped (non-success "
        "HTTP status) and not tested.", small))
    if params:
        story.append(Paragraph(
            f"<b>Tested GET query parameters:</b> {', '.join(sorted(params))}", small))
    techniques = sorted({
        f.evidence_technique() for f in findings if f.evidence_technique()
    })
    if techniques:
        story.append(Paragraph(
            f"<b>Detection techniques used:</b> {', '.join(techniques)}", small))
    story.append(Paragraph("<b>Limitations:</b>", small))
    for limitation in (
        "POST/PUT/DELETE request bodies and form submissions are not tested.",
        "JavaScript is not executed, so script-rendered content is not analysed.",
        "Authenticated or login-protected pages are not tested.",
        "Only GET query-string parameters are fuzzed (no headers, cookies or JSON bodies).",
        "Time-based blind SQL injection runs only when enabled by the operator.",
    ):
        story.append(Paragraph(f"- {limitation}", small))

    # --------------------------------------------------------- verification
    if retested:
        story.append(Paragraph("Verification (Retests)", h2))
        vdata = [["Finding", "Parameter", "Verdict", "Checked At",
                  "Confidence", "Requests"]]
        for f in retested:
            for r in f.retest_entries():
                vdata.append([
                    f.vulnerability.Name if f.vulnerability else "-",
                    f.Parameter or "-",
                    r["Verdict"],
                    r["At"],
                    f"{r['Confidence'] * 100:.0f}%" if r["Confidence"] is not None else "-",
                    r["RequestsIssued"] if r["RequestsIssued"] is not None else "-",
                ])
        vt = Table(vdata, colWidths=[45 * mm, 30 * mm, 28 * mm, 32 * mm, 20 * mm, 15 * mm])
        vt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B2447")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(vt)

    # Findings
    story.append(Paragraph(f"Findings ({len(findings)})", h2))
    if findings:
        data = [["#", "Vulnerability", "Severity", "Risk", "Status", "Location"]]
        for i, f in enumerate(findings, 1):
            data.append([
                i,
                f.vulnerability.Name if f.vulnerability else "-",
                f.Severity,
                f"{float(f.RiskScore):.1f}" if f.RiskScore is not None else "-",
                f.Status,
                f.page.URL if f.page else "-",
            ])
        ft = Table(data, colWidths=[10 * mm, 60 * mm, 30 * mm, 15 * mm, 25 * mm, 50 * mm])
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B2447")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for row_idx, row in enumerate(data[1:], start=1):
            sev = row[2]
            colour = SEVERITY_COLORS.get(sev, colors.grey)
            style.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), colour))
        ft.setStyle(TableStyle(style))
        story.append(ft)
        story.append(PageBreak())

        for i, f in enumerate(findings, 1):
            story.append(Paragraph(
                f"{i}. {f.vulnerability.Name if f.vulnerability else 'Finding'} "
                f"({f.Severity})", h2))
            detail = []
            detail.append(f"<b>Location:</b> {f.page.URL if f.page else '-'}")
            if f.Parameter:
                detail.append(f"<b>Parameter:</b> {f.Parameter}")
            if f.Payload:
                detail.append(f"<b>Payload:</b> <font face='Courier' size='8'>{f.Payload}</font>")
            detail.append(f"<b>Status:</b> {f.Status}")
            risk = f"{float(f.RiskScore):.1f}" if f.RiskScore is not None else "-"
            conf = f"{float(f.Confidence) * 100:.0f}%" if f.Confidence is not None else "-"
            detail.append(
                f"<b>Evidence class:</b> {f.classification} "
                f"(CVSS {risk}, confidence {conf})"
            )
            if f.evidence_vector():
                detail.append(f"<b>CVSS Vector:</b> {f.evidence_vector()}")
            if f.evidence_technique():
                detail.append(f"<b>Detection technique:</b> {f.evidence_technique()}")
            for r in f.retest_entries():
                conf_str = (
                    f", confidence {r['Confidence'] * 100:.0f}%"
                    if r["Confidence"] is not None else ""
                )
                req_str = (
                    f", {r['RequestsIssued']} request(s)"
                    if r["RequestsIssued"] is not None else ""
                )
                detail.append(
                    f"<b>Retest {r['At']}:</b> {r['Verdict']}"
                    f"{conf_str}{req_str} - {r['Message']}"
                )
            if f.vulnerability:
                if f.vulnerability.Description:
                    detail.append(f"<b>Description:</b> {f.vulnerability.Description}")
                if f.vulnerability.Impact:
                    detail.append(f"<b>Impact:</b> {f.vulnerability.Impact}")
                if f.vulnerability.Recommendation:
                    detail.append(f"<b>Remediation:</b> {f.vulnerability.Recommendation}")
            if f.Evidence:
                detail.append(f"<b>Evidence:</b> {f.Evidence}")
            for d in detail:
                story.append(Paragraph(d, small))
            story.append(Spacer(1, 8))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
