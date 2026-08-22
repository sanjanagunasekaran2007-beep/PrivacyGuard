import io
import os
import re
import uuid
from datetime import datetime

from flask import (
    Flask,
    request,
    render_template,
    send_file,
    abort
)

from werkzeug.utils import secure_filename

from scanner import scan_file

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024


# ============================================================
# FOLDERS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)


# ============================================================
# ALLOWED FILES
# ============================================================

ALLOWED_EXTENSIONS = {
    ".txt",
    ".log",
    ".csv",
    ".pdf",
    ".docx",
    ".xlsx",
    ".xlsm",
    ".pptx",
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".bmp",
    ".tiff",
    ".tif"
}


def allowed_file(filename):

    extension = os.path.splitext(
        filename
    )[1].lower()

    return extension in ALLOWED_EXTENSIONS


# ============================================================
# MASKING / REDACTION
# ------------------------------------------------------------
# Used both to show masked values in the results page (with a
# per-item "reveal" toggle) and to redact the downloaded PDF
# report, so sensitive values are never exposed by default.
# ============================================================

def _mask_generic(value):

    if len(value) <= 4:
        return "*" * len(value)

    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def mask_value(category, value):

    value = str(value).strip()

    if not value:
        return value

    if category == "Email Address" and "@" in value:

        local, domain = value.split("@", 1)

        if len(local) <= 2:
            masked_local = "*" * len(local)
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]

        return f"{masked_local}@{domain}"

    if category == "UPI ID" and "@" in value:

        local, handle = value.split("@", 1)

        if len(local) <= 2:
            masked_local = "*" * len(local)
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]

        return f"{masked_local}@{handle}"

    if category in ("Credit Card", "Bank Account", "Aadhaar Number"):

        digits = re.sub(r"\D", "", value)

        if len(digits) <= 4:
            return "*" * len(digits)

        masked_digits = "*" * (len(digits) - 4) + digits[-4:]

        groups = [
            masked_digits[i:i + 4]
            for i in range(0, len(masked_digits), 4)
        ]

        return " ".join(groups)

    if category == "Phone Number":

        digits = re.sub(r"\D", "", value)

        if len(digits) <= 4:
            return "*" * len(digits)

        return "*" * (len(digits) - 4) + digits[-4:]

    if category in (
        "Password",
        "Private Key",
        "Cloud Access Key",
        "JWT Token"
    ):
        return "********** (redacted)"

    return _mask_generic(value)


def redact_extracted_text(text, findings):

    redacted = text

    seen_values = set()
    unique_findings = []

    for finding in findings:

        value = finding.get("value", "")

        if value and value not in seen_values:
            seen_values.add(value)
            unique_findings.append(finding)

    # Longest values first, so partial matches don't get
    # replaced before the full sensitive value is masked.
    unique_findings.sort(
        key=lambda item: len(item.get("value", "")),
        reverse=True
    )

    for finding in unique_findings:

        value = finding.get("value", "")

        if not value:
            continue

        masked = mask_value(
            finding.get("category", ""),
            value
        )

        redacted = redacted.replace(value, masked)

    return redacted


# ============================================================
# IN-MEMORY SCAN STORE
# ------------------------------------------------------------
# Keeps the most recent scan results in memory so the results
# page and the "Download Report" button can both refer back to
# them by id, without re-uploading or re-scanning the file.
#
# NOTE: this is process-local storage meant for a single-user
# / demo deployment. For multi-user production use, replace
# this with a database or a short-lived cache (e.g. Redis).
# ============================================================

SCANS = {}
MAX_STORED_SCANS = 50


def store_scan(result, filename):

    scan_id = uuid.uuid4().hex

    SCANS[scan_id] = {
        "result": result,
        "filename": filename,
        "scanned_at": datetime.now()
    }

    # Keep memory bounded - drop the oldest entries.
    if len(SCANS) > MAX_STORED_SCANS:

        oldest_id = min(
            SCANS,
            key=lambda key: SCANS[key]["scanned_at"]
        )

        SCANS.pop(oldest_id, None)

    return scan_id


# ============================================================
# HOME (UPLOAD FORM)
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
def home():

    return render_template("index.html")


# ============================================================
# SCAN
# ============================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    uploaded_file = request.files.get(
        "file"
    )

    if uploaded_file is None or not uploaded_file.filename:

        return render_template(
            "index.html",
            error="Please select a file."
        )

    if not allowed_file(
        uploaded_file.filename
    ):

        return render_template(
            "index.html",
            error="Unsupported file format."
        )

    original_name = secure_filename(
        uploaded_file.filename
    )

    unique_name = (
        str(uuid.uuid4())
        + "_"
        + original_name
    )

    file_path = os.path.join(
        UPLOAD_FOLDER,
        unique_name
    )

    try:

        uploaded_file.save(
            file_path
        )

        result = scan_file(
            file_path
        )

        if not result.get("success"):

            return render_template(
                "index.html",
                error=result.get(
                    "error",
                    "Unable to scan the file."
                )
            )

        # Attach a masked version of every finding so the
        # results page can show masked-by-default values with
        # a per-item "reveal" toggle.
        for finding in result.get("findings", []):
            finding["masked"] = mask_value(
                finding.get("category", ""),
                finding.get("value", "")
            )

        scan_id = store_scan(
            result,
            original_name
        )

        return render_template(
            "results.html",
            result=result,
            filename=original_name,
            scan_id=scan_id
        )

    except Exception as error:

        print(
            "Application error:",
            error
        )

        return render_template(
            "index.html",
            error=(
                "Unable to scan the document. "
                "Please try another file."
            )
        )

    finally:

        # Keep uploaded file temporarily
        # for the current scan.
        #
        # It can be deleted later after
        # adding the clean-file feature.

        pass


# ============================================================
# DOWNLOAD PDF REPORT
# ============================================================

@app.route(
    "/download/<scan_id>",
    methods=["GET"]
)
def download_report(scan_id):

    entry = SCANS.get(scan_id)

    if entry is None:
        abort(404, description="This report is no longer available.")

    pdf_buffer = build_pdf_report(
        entry["result"],
        entry["filename"],
        entry["scanned_at"]
    )

    download_name = (
        "PrivacyGuard_Report_"
        + os.path.splitext(entry["filename"])[0]
        + ".pdf"
    )

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=download_name
    )


# ============================================================
# PDF REPORT BUILDER
# ------------------------------------------------------------
# Premium layout: a branded navy header band + slim footer with
# page numbers are drawn directly on the canvas on every page
# (via onPage callbacks), while the flowables below render the
# actual report content inside the safe content area.
# ============================================================

RISK_HEX = {
    "Critical": "ff4d6d",
    "High": "ff9f43",
    "Medium": "ffd166",
    "Low": "4ade80",
}

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#7f1d1d"),
    "High": colors.HexColor("#7c2d12"),
    "Medium": colors.HexColor("#713f12"),
    "Low": colors.HexColor("#14532d"),
}

SEVERITY_TINTS = {
    "Critical": colors.HexColor("#fff1f2"),
    "High": colors.HexColor("#fff7ed"),
    "Medium": colors.HexColor("#fefce8"),
    "Low": colors.HexColor("#f0fdf4"),
}

NAVY = colors.HexColor("#0a1626")
NAVY_DEEP = colors.HexColor("#050b14")
CYAN = colors.HexColor("#06b6d4")
CYAN_LIGHT = colors.HexColor("#38bdf8")
VIOLET = colors.HexColor("#7c3aed")
MUTED = colors.HexColor("#64748b")
INK = colors.HexColor("#0f172a")
HAIRLINE = colors.HexColor("#e2e8f0")
PANEL = colors.HexColor("#f8fafc")

MAX_EXTRACTED_TEXT_CHARS = 6000

PAGE_W, PAGE_H = A4
HEADER_HEIGHT = 24 * mm
FOOTER_HEIGHT = 16 * mm
SIDE_MARGIN = 18 * mm


def _draw_page_frame(canvas, doc, risk_level="Low", generated_label=""):
    """Draws the navy header band and the footer rule + page number
    on every page. Bound via onFirstPage / onLaterPages so it never
    has to be repeated inside the flowable story."""

    canvas.saveState()

    # ---- header band ----
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - HEADER_HEIGHT, PAGE_W, HEADER_HEIGHT, fill=1, stroke=0)

    # thin cyan accent line under the band
    canvas.setFillColor(CYAN)
    canvas.rect(0, PAGE_H - HEADER_HEIGHT - 0.6 * mm, PAGE_W, 0.6 * mm, fill=1, stroke=0)

    # shield glyph
    shield_cx = SIDE_MARGIN + 3.4 * mm
    shield_cy = PAGE_H - HEADER_HEIGHT / 2
    canvas.setFillColor(colors.HexColor("#132743"))
    canvas.circle(shield_cx, shield_cy, 6.4 * mm, fill=1, stroke=0)
    canvas.setStrokeColor(CYAN_LIGHT)
    canvas.setLineWidth(1.1)
    p = canvas.beginPath()
    p.moveTo(shield_cx, shield_cy + 4.2 * mm)
    p.lineTo(shield_cx - 3.4 * mm, shield_cy + 2.6 * mm)
    p.lineTo(shield_cx - 3.4 * mm, shield_cy - 1.2 * mm)
    p.curveTo(shield_cx - 3.4 * mm, shield_cy - 4.2 * mm,
              shield_cx - 1.2 * mm, shield_cy - 5.8 * mm,
              shield_cx, shield_cy - 6.4 * mm)
    p.curveTo(shield_cx + 1.2 * mm, shield_cy - 5.8 * mm,
              shield_cx + 3.4 * mm, shield_cy - 4.2 * mm,
              shield_cx + 3.4 * mm, shield_cy - 1.2 * mm)
    p.lineTo(shield_cx + 3.4 * mm, shield_cy + 2.6 * mm)
    p.close()
    canvas.drawPath(p, fill=0, stroke=1)

    # wordmark
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 15)
    canvas.drawString(SIDE_MARGIN + 10 * mm, PAGE_H - HEADER_HEIGHT / 2 - 1.5 * mm, "PrivacyGuard")
    canvas.setFillColor(colors.HexColor("#94a3b8"))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(SIDE_MARGIN + 10 * mm, PAGE_H - HEADER_HEIGHT / 2 + 3.6 * mm,
                       "DIGITAL PRIVACY RISK ANALYZER")

    # right-aligned confidential + risk chip
    canvas.setFont("Helvetica-Bold", 8)
    risk_hex = RISK_HEX.get(risk_level, RISK_HEX["Low"])
    chip_text = f"{risk_level.upper()} RISK"
    chip_w = canvas.stringWidth(chip_text, "Helvetica-Bold", 8) + 8 * mm
    chip_x = PAGE_W - SIDE_MARGIN - chip_w
    chip_y = PAGE_H - HEADER_HEIGHT / 2 - 3.2 * mm
    canvas.setFillColor(colors.HexColor("#132743"))
    canvas.roundRect(chip_x, chip_y, chip_w, 6.4 * mm, 3.2 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor(f"#{risk_hex}"))
    canvas.circle(chip_x + 5 * mm, chip_y + 3.2 * mm, 1.1 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.drawString(chip_x + 8 * mm, chip_y + 2.1 * mm, chip_text)

    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(PAGE_W - SIDE_MARGIN, PAGE_H - HEADER_HEIGHT - 4 * mm,
                            "CONFIDENTIAL")

    # ---- footer ----
    canvas.setStrokeColor(HAIRLINE)
    canvas.setLineWidth(0.6)
    canvas.line(SIDE_MARGIN, FOOTER_HEIGHT, PAGE_W - SIDE_MARGIN, FOOTER_HEIGHT)

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(SIDE_MARGIN, FOOTER_HEIGHT - 5.5 * mm,
                       f"Generated by PrivacyGuard \u00b7 {generated_label}")
    canvas.drawRightString(PAGE_W - SIDE_MARGIN, FOOTER_HEIGHT - 5.5 * mm,
                            f"Page {canvas.getPageNumber()}")

    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#94a3b8"))
    canvas.drawCentredString(PAGE_W / 2, FOOTER_HEIGHT - 10.5 * mm,
                              "Machine-generated report \u00b7 informational use only")

    canvas.restoreState()


def build_pdf_report(result, filename, scanned_at):

    buffer = io.BytesIO()

    risk_level = result.get("risk_level", "Low")
    generated_label = scanned_at.strftime("%d %b %Y, %I:%M %p")

    def on_page(canvas, doc):
        _draw_page_frame(canvas, doc, risk_level=risk_level, generated_label=generated_label)

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=HEADER_HEIGHT + 12 * mm,
        bottomMargin=FOOTER_HEIGHT + 8 * mm,
        leftMargin=SIDE_MARGIN,
        rightMargin=SIDE_MARGIN,
        title="PrivacyGuard Security Report",
        author="PrivacyGuard"
    )

    styles = getSampleStyleSheet()

    report_title_style = ParagraphStyle(
        "PGReportTitle",
        parent=styles["Title"],
        alignment=TA_LEFT,
        textColor=NAVY,
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        spaceAfter=2
    )

    subtitle_style = ParagraphStyle(
        "PGSubtitle",
        parent=styles["Normal"],
        textColor=MUTED,
        fontSize=10.5,
        spaceAfter=16
    )

    heading_style = ParagraphStyle(
        "PGHeading",
        parent=styles["Heading2"],
        textColor=NAVY,
        fontName="Helvetica-Bold",
        fontSize=13.5,
        spaceBefore=18,
        spaceAfter=9
    )

    body_style = ParagraphStyle(
        "PGBody",
        parent=styles["Normal"],
        textColor=colors.HexColor("#1e293b"),
        fontSize=10,
        leading=15.5
    )

    note_style = ParagraphStyle(
        "PGNote",
        parent=styles["Normal"],
        textColor=MUTED,
        fontSize=8.5,
        leading=12,
        spaceAfter=10
    )

    mono_style = ParagraphStyle(
        "PGMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.8,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
        backColor=colors.HexColor("#f8fafc"),
        borderColor=HAIRLINE,
        borderWidth=0.75,
        borderPadding=10,
        borderRadius=4
    )

    risk_hex = RISK_HEX.get(risk_level, RISK_HEX["Low"])

    elements = []

    # ---------- REPORT TITLE ----------

    elements.append(Paragraph("Security &amp; Privacy Report", report_title_style))
    elements.append(
        Paragraph(
            "A detailed breakdown of the sensitive information detected in your document, "
            "with severity ratings and remediation guidance.",
            subtitle_style
        )
    )

    # ---------- FILE INFO ----------

    info_table = Table(
        [
            ["File Name", filename],
            ["Scan Date", generated_label],
            ["File Type", str(result.get("file_type", "-")).upper()],
        ],
        colWidths=[38 * mm, 122 * mm]
    )

    info_table.setStyle(
        TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
            ("TEXTCOLOR", (1, 0), (1, -1), INK),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("BACKGROUND", (0, 0), (-1, -1), PANEL),
            ("BOX", (0, 0), (-1, -1), 0.75, HAIRLINE),
            ("LINEBELOW", (0, 0), (-1, -2), 0.5, HAIRLINE),
        ])
    )

    elements.append(info_table)

    # ---------- RISK SCORE ----------

    elements.append(Paragraph("Privacy Risk Score", heading_style))

    accent_cell = Table([[""]], colWidths=[4 * mm], rowHeights=[26 * mm])
    accent_cell.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(f"#{risk_hex}")),
    ]))

    score_content = Table(
        [[
            Paragraph(
                f'<font size="36" color="#{risk_hex}">'
                f'<b>{result.get("risk_score", 0)}</b></font>'
                f'<font size="12" color="#64748b"> / 100</font>',
                body_style
            ),
            Paragraph(
                f'<font size="13" color="#{risk_hex}">'
                f'<b>{risk_level.upper()} RISK</b></font><br/>'
                f'<font size="9.5" color="#64748b">'
                f'{result.get("total_findings", 0)} sensitive findings '
                f'across {len(result.get("risk_breakdown", {}))} categories'
                f'</font>',
                body_style
            )
        ]],
        colWidths=[56 * mm, 100 * mm]
    )

    score_content.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ])
    )

    score_wrapper = Table(
        [[accent_cell, score_content]],
        colWidths=[4 * mm, 156 * mm]
    )
    score_wrapper.setStyle(
        TableStyle([
            ("BACKGROUND", (1, 0), (1, 0), PANEL),
            ("BOX", (0, 0), (-1, -1), 0.75, HAIRLINE),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (0, 0), 0),
            ("RIGHTPADDING", (0, 0), (0, 0), 0),
            ("TOPPADDING", (0, 0), (0, 0), 0),
            ("BOTTOMPADDING", (0, 0), (0, 0), 0),
        ])
    )

    elements.append(score_wrapper)

    # ---------- VERDICT ----------

    verdict_text = {
        "Critical": "<b>DO NOT SHARE</b> this document without removing or "
                    "masking the detected sensitive information.",
        "High": "This document contains significant privacy risks. "
                "Review and redact the detected information before sharing.",
        "Medium": "Some privacy-sensitive information was detected. "
                  "Review the findings before sharing.",
        "Low": "No major privacy risks were detected. The document "
               "appears relatively safe to share based on the detected patterns."
    }.get(risk_level, "")

    elements.append(Paragraph("Verdict", heading_style))
    elements.append(Paragraph(verdict_text, body_style))

    # ---------- FINDINGS (MASKED) ----------

    elements.append(Paragraph("Detected Privacy Risks", heading_style))
    elements.append(
        Paragraph(
            "For your protection, sensitive values below are masked. "
            "Open the live results page to review full values before "
            "sharing this document.",
            note_style
        )
    )

    findings = result.get("findings", [])

    if findings:

        finding_rows = [["Category", "Detected Value (masked)", "Severity"]]

        for finding in findings:

            masked_value = mask_value(
                finding.get("category", ""),
                finding.get("value", "")
            )

            finding_rows.append([
                finding.get("category", ""),
                masked_value,
                finding.get("severity", "")
            ])

        findings_table = Table(
            finding_rows,
            colWidths=[42 * mm, 90 * mm, 28 * mm],
            repeatRows=1
        )

        table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("GRID", (0, 0), (-1, -1), 0.4, HAIRLINE),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, PANEL]),
        ]

        for row_index, finding in enumerate(findings, start=1):
            severity = finding.get("severity", "Low")
            table_style.append((
                "TEXTCOLOR",
                (2, row_index),
                (2, row_index),
                SEVERITY_COLORS.get(severity, MUTED)
            ))
            table_style.append((
                "FONTNAME",
                (2, row_index),
                (2, row_index),
                "Helvetica-Bold"
            ))
            table_style.append((
                "BACKGROUND",
                (2, row_index),
                (2, row_index),
                SEVERITY_TINTS.get(severity, PANEL)
            ))

        findings_table.setStyle(TableStyle(table_style))

        elements.append(findings_table)

    else:

        elements.append(
            Paragraph(
                "No sensitive information detected.",
                body_style
            )
        )

    # ---------- RISK BREAKDOWN ----------

    risk_breakdown = result.get("risk_breakdown", {})

    if risk_breakdown:

        elements.append(Paragraph("Risk Breakdown", heading_style))

        max_count = max(risk_breakdown.values())

        breakdown_rows = []
        for category, count in risk_breakdown.items():
            bar_width_mm = 60 * (count / max_count)
            bar = Table([[""]], colWidths=[bar_width_mm * mm], rowHeights=[2.6 * mm])
            bar.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), CYAN),
            ]))
            breakdown_rows.append([
                Paragraph(f'<font size="9" color="#1e293b"><b>{category}</b></font>', body_style),
                Paragraph(f'<font size="9" color="#64748b">{count}</font>', body_style),
                bar
            ])

        breakdown_table = Table(
            breakdown_rows,
            colWidths=[70 * mm, 14 * mm, 76 * mm]
        )
        breakdown_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LINEBELOW", (0, 0), (-1, -2), 0.4, HAIRLINE),
        ]))

        elements.append(breakdown_table)

    # ---------- RECOMMENDATIONS ----------

    elements.append(Paragraph("Security Recommendations", heading_style))

    recommendation_rows = []
    for recommendation in result.get("recommendations", []):
        recommendation_rows.append([
            Paragraph('<font color="#06b6d4"><b>&#10003;</b></font>', body_style),
            Paragraph(recommendation, body_style)
        ])

    if recommendation_rows:
        recommendations_table = Table(
            recommendation_rows,
            colWidths=[7 * mm, 153 * mm]
        )
        recommendations_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        elements.append(recommendations_table)

    # ---------- EXTRACTED TEXT (REDACTED) ----------

    elements.append(Paragraph("Extracted Text (redacted excerpt)", heading_style))
    elements.append(
        Paragraph(
            "Sensitive values detected above are masked wherever they "
            "appear in this excerpt.",
            note_style
        )
    )

    raw_text = str(result.get("extracted_text", "")).strip()

    redacted_text = redact_extracted_text(raw_text, findings)

    if len(redacted_text) > MAX_EXTRACTED_TEXT_CHARS:
        redacted_text = (
            redacted_text[:MAX_EXTRACTED_TEXT_CHARS]
            + "\n\n[... truncated in PDF report ...]"
        )

    safe_text = (
        redacted_text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    ) or "(No extracted text)"

    # NOTE: intentionally a plain Paragraph, not a single-row Table.
    # Tables can't split a cell across pages, so a long extracted-text
    # cell (e.g. a multi-page source document) would overflow the frame
    # and raise a LayoutError. A Paragraph with backColor/borderWidth
    # gives the same "boxed" look but splits across pages natively.
    elements.append(Paragraph(safe_text, mono_style))

    document.build(elements, onFirstPage=on_page, onLaterPages=on_page)

    buffer.seek(0)

    return buffer


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    print("")
    print("=" * 60)
    print("PRIVACYGUARD")
    print("Digital Privacy Risk Analyzer")
    print("=" * 60)
    print("")
    print("Supported formats:")
    print("TXT / CSV / PDF / DOCX / XLSX / PPTX")
    print("JPG / JPEG / PNG / WEBP / BMP / TIFF")
    print("")
    print("Server: http://127.0.0.1:5000")
    print("=" * 60)
    print("")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )