"""
ExplainPhish SOC Incident Report Exporter (PDF & Word DOCX)
============================================================
Compiles comprehensive, enterprise-ready incident response reports
into downloadable PDF and Microsoft Word (.docx) formats.
"""

from __future__ import annotations

import html
import io
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import docx
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Inches, Pt, RGBColor

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class NumberedCanvas(canvas.Canvas):
    """Adds Page X of Y and SOC confidentiality header/footer to each page."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Header
        self.drawString(54, 755, "EXPLAINPHISH AUTONOMOUS SOC WORKSTATION — THREAT DOSSIER")
        self.drawRightString(612 - 54, 755, "STRICTLY CONFIDENTIAL // TLP:AMBER")

        # Top rule
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 748, 612 - 54, 748)

        # Bottom rule
        self.line(54, 45, 612 - 54, 45)

        # Running Footer
        self.setFont("Helvetica", 8)
        self.drawString(54, 32, "ExplainPhish Autonomous Incident Response Pipeline v2.0")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 32, page_str)

        self.restoreState()


logger = logging.getLogger("ExplainPhish.Exporter")


def _safe_xml(text: Any) -> str:
    """
    Escapes text so that it can be safely rendered inside a ReportLab Paragraph.
    Replaces &, <, > with XML entities so paraparser NEVER encounters unclosed tags.
    """
    if text is None:
        return ""
    return html.escape(str(text), quote=False)


def _safe_markdown_to_paragraph_xml(text: str) -> str:
    """
    Safely converts markdown formatting to ReportLab-compliant XML:
    - Escapes all raw &, <, > first to prevent XML paraparser crashes
    - Re-applies safe <b>, <i>, and <font> tags from markdown tokens
    """
    if not text:
        return ""
    # 1. Escape all XML entities first
    s = html.escape(str(text), quote=False)

    # 2. Convert markdown bold **text** to <b>text</b>
    s = re.sub(r"\*\*([^\*\n]+?)\*\*", r"<b>\1</b>", s)

    # 3. Convert markdown italic *text* to <i>text</i>
    s = re.sub(r"(?<!\*)\*([^\*\n]+?)\*(?!\*)", r"<i>\1</i>", s)

    # 4. Convert markdown inline code `text` to Courier font
    s = re.sub(r"`([^`\n]+?)`", r"<font name='Courier' size='7.5'>\1</font>", s)

    return s.strip()


def _make_safe_paragraph(text: Any, style: ParagraphStyle, is_markdown: bool = False) -> Paragraph:
    """
    Constructs a ReportLab Paragraph guaranteed not to crash with XML paraparser errors.
    If any XML paraparser error still occurs, falls back to raw plain-text escaping.
    """
    try:
        content = _safe_markdown_to_paragraph_xml(text) if is_markdown else _safe_xml(text)
        return Paragraph(content, style)
    except Exception:
        raw_escaped = html.escape(str(text or ""), quote=False)
        return Paragraph(raw_escaped, style)


def _clean_markdown_text(text: str) -> str:
    """Strips raw markdown formatting tokens for plain text insertion in Word."""
    if not text:
        return ""
    t = re.sub(r"^###+\s*", "", text)
    t = re.sub(r"\*\*([^*]+)\*\*", r"\1", t)
    t = re.sub(r"\*([^*]+)\*", r"\1", t)
    t = re.sub(r"`([^`]+)`", r"\1", t)
    return t.strip()


# ─────────────────────────────────────────────────────────────────────────────
# 1. PDF Report Generation (ReportLab)
# ─────────────────────────────────────────────────────────────────────────────


def generate_pdf_report(state: Dict[str, Any]) -> bytes:
    """Generates an executive-ready PDF Incident Report as raw bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom Palette & Styles
    c_navy = colors.HexColor("#0F172A")
    c_slate = colors.HexColor("#334155")
    c_blue = colors.HexColor("#0284C7")
    c_gray_bg = colors.HexColor("#F8FAFC")
    c_border = colors.HexColor("#E2E8F0")

    verdict = state.get("final_verdict") or state.get("ensemble_verdict", "UNKNOWN")
    threat = state.get("threat_level", "UNKNOWN")
    is_malicious = "MALICIOUS" in verdict
    is_suspicious = "SUSPICIOUS" in verdict

    badge_bg = colors.HexColor("#DC2626") if is_malicious else (colors.HexColor("#EA580C") if is_suspicious else colors.HexColor("#059669"))

    style_title = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=c_navy,
        spaceAfter=4,
    )

    style_subtitle = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=c_slate,
        spaceAfter=12,
    )

    style_h2 = ParagraphStyle(
        "Heading2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=c_navy,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )

    style_h3 = ParagraphStyle(
        "Heading3",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=c_navy,
        spaceBefore=8,
        spaceAfter=3,
        keepWithNext=True,
    )

    style_body = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=5,
    )

    style_bullet = ParagraphStyle(
        "BulletItem",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1E293B"),
        leftIndent=14,
        spaceAfter=3,
    )

    style_cell = ParagraphStyle(
        "Cell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1E293B"),
    )

    style_cell_bold = ParagraphStyle(
        "CellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
    )

    style_cell_header = ParagraphStyle(
        "CellHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.white,
    )

    story = []
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    filename = state.get("file_name", "artifact")
    sha256 = state.get("file_hash_sha256", "N/A")
    conf = state.get("confidence_score", 0.0)

    # Document Title & Classification Header
    story.append(Paragraph(f"SOC Incident Response Report — {_safe_xml(filename)}", style_title))
    story.append(Paragraph(f"Generated: {timestamp} | Classification: <b>{_safe_xml(threat)}</b> | Pipeline: ExplainPhish v2.0", style_subtitle))

    # Executive Verdict Banner Table
    banner_data = [
        [
            Paragraph(f"<font color='white'><b>VERDICT: {_safe_xml(verdict.upper())}</b></font>", style_cell_header),
            Paragraph(f"<font color='white'><b>THREAT LEVEL: {_safe_xml(threat)}</b></font>", style_cell_header),
            Paragraph(f"<font color='white'><b>CONFIDENCE: {conf:.1%}</b></font>", style_cell_header),
        ]
    ]
    t_banner = Table(banner_data, colWidths=[200, 150, 154])
    t_banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), badge_bg),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_banner)
    story.append(Spacer(1, 10))

    # 1. Executive Summary Table
    story.append(Paragraph("1. Executive Incident Summary", style_h2))
    size_str = f"{state.get('file_size_bytes', 0):,} bytes"
    summary_data = [
        [Paragraph("Artifact File Name", style_cell_bold), _make_safe_paragraph(str(filename), style_cell)],
        [Paragraph("Document Format", style_cell_bold), _make_safe_paragraph(str(state.get("format_display", state.get("file_format", "Unknown"))), style_cell)],
        [Paragraph("File Size & Hashes", style_cell_bold), _make_safe_paragraph(f"{size_str} | SHA256: {sha256[:24]}...", style_cell)],
        [Paragraph("Full SHA-256", style_cell_bold), Paragraph(f"<font name='Courier' size=7>{_safe_xml(sha256)}</font>", style_cell)],
    ]
    if state.get("source_url"):
        summary_data.append([Paragraph("Source Target URL", style_cell_bold), _make_safe_paragraph(str(state["source_url"]), style_cell)])

    t_summary = Table(summary_data, colWidths=[140, 364])
    t_summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c_gray_bg),
        ("GRID", (0, 0), (-1, -1), 0.5, c_border),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_summary)
    story.append(Spacer(1, 8))

    # 2. AI Threat Intelligence Narrative
    llm = state.get("llm_triage") or {}
    raw_narrative = llm.get("executive_threat_narrative") or state.get("llm_narrative", "")
    if raw_narrative:
        story.append(Paragraph("2. AI Threat Intelligence & Cognitive Forensics", style_h2))
        provider_name = _safe_xml(llm.get("provider", "ExplainPhish AI"))
        model_name = _safe_xml(llm.get("model", "Cognitive Reasoner"))
        story.append(Paragraph(f"<i>Analysis synthesized by <b>{provider_name}</b> ({model_name})</i>", style_subtitle))

        # Parse narrative line by line for structured formatting and strict XML safety
        lines = raw_narrative.split("\n")
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            # Heading (e.g. ### 3. Section Title)
            if line.startswith("#"):
                clean_heading = re.sub(r"^#+\s*", "", line)
                story.append(_make_safe_paragraph(f"<b>{_safe_xml(clean_heading)}</b>", style_h3, is_markdown=False))
                continue

            # Bullet or numbered item (e.g. * ... or 1. ...)
            if re.match(r"^(\*|-|\d+\.)\s+", line):
                m_num = re.match(r"^(\d+\.)\s*", line)
                cleaned_item = re.sub(r"^(\*|-|\d+\.)\s*", "", line)
                prefix = f"{m_num.group(1)} " if m_num else "• "
                story.append(_make_safe_paragraph(f"{prefix}{cleaned_item}", style_bullet, is_markdown=True))
                continue

            # Standard narrative body
            story.append(_make_safe_paragraph(line, style_body, is_markdown=True))

        story.append(Spacer(1, 8))

    # 3. Model Consensus Table
    preds = state.get("model_predictions", [])
    if preds:
        story.append(Paragraph("3. Multi-Model ML Ensemble Consensus", style_h2))
        pred_table_data = [[
            Paragraph("Architecture Model", style_cell_header),
            Paragraph("Verdict Vote", style_cell_header),
            Paragraph("Phishing Probability", style_cell_header),
        ]]
        for p in preds:
            pl = "MALICIOUS" if p.get("prediction") == 1 else "BENIGN"
            prob_val = p.get("probability", 0.0)
            pred_table_data.append([
                _make_safe_paragraph(str(p.get("model", "-")), style_cell_bold),
                _make_safe_paragraph(pl, style_cell),
                _make_safe_paragraph(f"{prob_val:.1%}", style_cell),
            ])
        t_preds = Table(pred_table_data, colWidths=[200, 150, 154])
        t_preds.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_navy),
            ("GRID", (0, 0), (-1, -1), 0.5, c_border),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_gray_bg]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_preds)
        story.append(Spacer(1, 8))

    # 4. Explainable AI Decision Drivers
    drivers = state.get("top_risk_drivers", [])
    if drivers:
        story.append(Paragraph("4. Explainable AI (XAI) — Top Decision Drivers", style_h2))
        xai_data = [[
            Paragraph("Feature", style_cell_header),
            Paragraph("Operational Description", style_cell_header),
            Paragraph("Impact Direction", style_cell_header),
            Paragraph("Risk Weight", style_cell_header),
        ]]
        for d in drivers[:5]:
            is_risk = d.get("direction") == "↑"
            dir_text = "Increases Risk" if is_risk else "Reduces Risk"
            feat_name = _safe_xml(str(d.get("feature", "-")))
            xai_data.append([
                Paragraph(f"<font name='Courier'><b>{feat_name}</b></font>", style_cell_bold),
                _make_safe_paragraph(str(d.get("description", "-")), style_cell),
                _make_safe_paragraph(f"{d.get('direction', '')} {dir_text}", style_cell),
                _make_safe_paragraph(f"{d.get('impact', 0.0):+.4f}", style_cell),
            ])
        t_xai = Table(xai_data, colWidths=[130, 204, 100, 70])
        t_xai.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_navy),
            ("GRID", (0, 0), (-1, -1), 0.5, c_border),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_gray_bg]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_xai)
        story.append(Spacer(1, 8))

    # 5. IOCs
    iocs = state.get("indicators_of_compromise", [])
    if iocs:
        story.append(Paragraph("5. Extracted Indicators of Compromise (IOCs)", style_h2))
        ioc_data = [[
            Paragraph("Indicator Category", style_cell_header),
            Paragraph("Extracted Value / Target URI", style_cell_header),
        ]]
        for ioc in iocs[:8]:
            ioc_val = _safe_xml(str(ioc.get("value", "-")))
            ioc_data.append([
                _make_safe_paragraph(str(ioc.get("type", "-")), style_cell_bold),
                Paragraph(f"<font size=7 name='Courier'>{ioc_val}</font>", style_cell),
            ])
        t_ioc = Table(ioc_data, colWidths=[150, 354])
        t_ioc.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_navy),
            ("GRID", (0, 0), (-1, -1), 0.5, c_border),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_gray_bg]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_ioc)
        story.append(Spacer(1, 8))

    # 6. MITRE & Playbooks
    playbook = state.get("soc_playbook_actions", [])
    if playbook:
        story.append(Paragraph("6. Prescriptive SOAR Incident Response Playbook", style_h2))
        soar_data = [[
            Paragraph("Stage", style_cell_header),
            Paragraph("Response Tier", style_cell_header),
            Paragraph("Prescribed Operational Action", style_cell_header),
        ]]
        for a in playbook:
            tier_val = _safe_xml(str(a.get("tier", "-")))
            soar_data.append([
                _make_safe_paragraph(str(a.get("stage", "-")), style_cell_bold),
                Paragraph(f"<font color='#0284C7'><b>{tier_val}</b></font>", style_cell),
                _make_safe_paragraph(str(a.get("action", "-")), style_cell),
            ])
        t_soar = Table(soar_data, colWidths=[100, 120, 284])
        t_soar.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_navy),
            ("GRID", (0, 0), (-1, -1), 0.5, c_border),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_gray_bg]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_soar)

    try:
        doc.build(story, canvasmaker=NumberedCanvas)
    except Exception as exc:
        logger.warning(f"ReportLab primary build encountered error: {exc}. Retrying with strict plain text fallback.")
        fallback_buffer = io.BytesIO()
        fallback_doc = SimpleDocTemplate(fallback_buffer, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=54, bottomMargin=54)
        safe_story = []
        for flowable in story:
            if isinstance(flowable, Paragraph):
                plain_txt = re.sub(r"<[^>]+>", "", flowable.text)
                safe_story.append(Paragraph(_safe_xml(plain_txt), flowable.style))
            else:
                safe_story.append(flowable)
        fallback_doc.build(safe_story, canvasmaker=NumberedCanvas)
        return fallback_buffer.getvalue()

    return buffer.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Microsoft Word (.docx) Report Generation (python-docx)
# ─────────────────────────────────────────────────────────────────────────────


def generate_docx_report(state: Dict[str, Any]) -> bytes:
    """Generates an executive-ready Microsoft Word (.docx) Incident Report as raw bytes."""
    doc = docx.Document()

    # Set 0.75 inch margins
    for section in doc.sections:
        section.top_margin = Inches(0.75)
        section.bottom_margin = Inches(0.75)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)

    verdict = state.get("final_verdict") or state.get("ensemble_verdict", "UNKNOWN")
    threat = state.get("threat_level", "UNKNOWN")
    conf = state.get("confidence_score", 0.0)
    filename = state.get("file_name", "artifact")
    sha256 = state.get("file_hash_sha256", "N/A")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Document Header Title
    title = doc.add_paragraph()
    r_title = title.add_run(f"SOC Incident Response Report — {filename}")
    r_title.bold = True
    r_title.font.size = Pt(18)
    r_title.font.color.rgb = RGBColor(15, 23, 42)  # Navy
    title.paragraph_format.space_after = Pt(2)

    sub = doc.add_paragraph()
    r_sub = sub.add_run(f"Generated: {timestamp} | Classification: {threat} | Pipeline: ExplainPhish Autonomous SOC Agent v2.0")
    r_sub.font.size = Pt(9)
    r_sub.font.color.rgb = RGBColor(100, 116, 139)
    sub.paragraph_format.space_after = Pt(12)

    # 1. Executive Summary Table
    h1 = doc.add_heading("1. Executive Incident Summary", level=2)
    h1.paragraph_format.space_before = Pt(8)
    h1.paragraph_format.space_after = Pt(4)

    t_sum = doc.add_table(rows=5, cols=2)
    t_sum.style = "Table Grid"
    t_sum.alignment = WD_TABLE_ALIGNMENT.CENTER

    summary_rows = [
        ("Artifact File Name", str(filename)),
        ("Final Incident Verdict", f"{verdict} (Threat Level: {threat})"),
        ("Multi-Model Confidence", f"{conf:.1%}"),
        ("Document Format & Size", f"{state.get('format_display', state.get('file_format', 'Unknown'))} | {state.get('file_size_bytes', 0):,} bytes"),
        ("Cryptographic Hash (SHA-256)", sha256),
    ]

    for idx, (lbl, val) in enumerate(summary_rows):
        r = t_sum.rows[idx]
        _set_cell_text(r.cells[0], lbl, bold=True, bg_color="F1F5F9")
        _set_cell_text(r.cells[1], val, bold=(idx == 1))
        r.cells[0].width = Inches(2.2)
        r.cells[1].width = Inches(4.8)

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # 2. AI Threat Intelligence Narrative
    llm = state.get("llm_triage") or {}
    raw_narrative = llm.get("executive_threat_narrative") or state.get("llm_narrative", "")
    if raw_narrative:
        h2 = doc.add_heading("2. AI Threat Intelligence & Cognitive Forensics", level=2)
        h2.paragraph_format.space_before = Pt(10)
        h2.paragraph_format.space_after = Pt(4)

        provider_name = llm.get("provider", "ExplainPhish AI")
        model_name = llm.get("model", "Cognitive Reasoner")
        p_note = doc.add_paragraph()
        r_note = p_note.add_run(f"Cognitive triage generated by {provider_name} ({model_name}):")
        r_note.italic = True
        r_note.font.size = Pt(8.5)
        p_note.paragraph_format.space_after = Pt(4)

        paragraphs = raw_narrative.split("\n\n")
        for p in paragraphs:
            clean_p = _clean_markdown_text(p)
            if clean_p:
                p_body = doc.add_paragraph()
                p_body.paragraph_format.space_after = Pt(4)
                r_body = p_body.add_run(clean_p)
                r_body.font.size = Pt(9.5)

    # 3. Model Predictions Table
    preds = state.get("model_predictions", [])
    if preds:
        h3 = doc.add_heading("3. Multi-Model ML Ensemble Consensus", level=2)
        h3.paragraph_format.space_before = Pt(10)
        h3.paragraph_format.space_after = Pt(4)

        t_pred = doc.add_table(rows=len(preds) + 1, cols=3)
        t_pred.style = "Table Grid"
        t_pred.alignment = WD_TABLE_ALIGNMENT.CENTER

        headers = ["Architecture Model", "Predicted Classification", "Phishing Probability"]
        for j, h in enumerate(headers):
            _set_cell_text(t_pred.rows[0].cells[j], h, bold=True, bg_color="0F172A", text_color="FFFFFF")

        for i, p in enumerate(preds):
            row = t_pred.rows[i + 1]
            pl = "MALICIOUS" if p.get("prediction") == 1 else "BENIGN"
            prob_val = p.get("probability", 0.0)
            _set_cell_text(row.cells[0], str(p.get("model", "-")), bold=True)
            _set_cell_text(row.cells[1], pl, bold=(pl == "MALICIOUS"))
            _set_cell_text(row.cells[2], f"{prob_val:.1%}")

        doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # 4. Explainability Decision Drivers
    drivers = state.get("top_risk_drivers", [])
    if drivers:
        h4 = doc.add_heading("4. Explainable AI (XAI) — Top Decision Drivers", level=2)
        h4.paragraph_format.space_before = Pt(10)
        h4.paragraph_format.space_after = Pt(4)

        t_drv = doc.add_table(rows=len(drivers[:5]) + 1, cols=4)
        t_drv.style = "Table Grid"
        t_drv.alignment = WD_TABLE_ALIGNMENT.CENTER

        headers = ["Feature", "Operational Description", "Impact Direction", "Risk Weight"]
        for j, h in enumerate(headers):
            _set_cell_text(t_drv.rows[0].cells[j], h, bold=True, bg_color="0F172A", text_color="FFFFFF")

        for i, d in enumerate(drivers[:5]):
            row = t_drv.rows[i + 1]
            is_risk = d.get("direction") == "↑"
            dir_text = "Increases Risk" if is_risk else "Reduces Risk"
            _set_cell_text(row.cells[0], str(d.get("feature", "-")), bold=True)
            _set_cell_text(row.cells[1], str(d.get("description", "-")))
            _set_cell_text(row.cells[2], f"{d.get('direction', '')} {dir_text}")
            _set_cell_text(row.cells[3], f"{d.get('impact', 0.0):+.4f}")

        doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # 5. Indicators of Compromise (IOCs)
    iocs = state.get("indicators_of_compromise", [])
    if iocs:
        h5 = doc.add_heading("5. Extracted Indicators of Compromise (IOCs)", level=2)
        h5.paragraph_format.space_before = Pt(10)
        h5.paragraph_format.space_after = Pt(4)

        t_ioc = doc.add_table(rows=len(iocs[:10]) + 1, cols=2)
        t_ioc.style = "Table Grid"
        t_ioc.alignment = WD_TABLE_ALIGNMENT.CENTER

        headers = ["Indicator Type", "Extracted Target / IOC Value"]
        for j, h in enumerate(headers):
            _set_cell_text(t_ioc.rows[0].cells[j], h, bold=True, bg_color="0F172A", text_color="FFFFFF")

        for i, item in enumerate(iocs[:10]):
            row = t_ioc.rows[i + 1]
            _set_cell_text(row.cells[0], str(item.get("type", "-")), bold=True)
            _set_cell_text(row.cells[1], str(item.get("value", "-")))

        doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # 6. SOAR Playbooks
    playbook = state.get("soc_playbook_actions", [])
    if playbook:
        h6 = doc.add_heading("6. Prescriptive SOAR Incident Response Playbook", level=2)
        h6.paragraph_format.space_before = Pt(10)
        h6.paragraph_format.space_after = Pt(4)

        t_soar = doc.add_table(rows=len(playbook) + 1, cols=3)
        t_soar.style = "Table Grid"
        t_soar.alignment = WD_TABLE_ALIGNMENT.CENTER

        headers = ["Stage", "Action Tier", "Prescribed Incident Mitigation"]
        for j, h in enumerate(headers):
            _set_cell_text(t_soar.rows[0].cells[j], h, bold=True, bg_color="0F172A", text_color="FFFFFF")

        for i, a in enumerate(playbook):
            row = t_soar.rows[i + 1]
            _set_cell_text(row.cells[0], str(a.get("stage", "-")), bold=True)
            _set_cell_text(row.cells[1], str(a.get("tier", "-")), bold=True)
            _set_cell_text(row.cells[2], str(a.get("action", "-")))

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _set_cell_text(cell, text: str, bold: bool = False, bg_color: Optional[str] = None, text_color: Optional[str] = None):
    """Utility to style table cells with typography, color, and background shading."""
    cell.text = text
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    for run in p.runs:
        run.font.name = "Arial"
        run.font.size = Pt(8.5)
        run.bold = bold
        if text_color:
            r = int(text_color[0:2], 16)
            g = int(text_color[2:4], 16)
            b = int(text_color[4:6], 16)
            run.font.color.rgb = RGBColor(r, g, b)

    if bg_color:
        shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{bg_color}"/>')
        cell._tc.get_or_add_tcPr().append(shading)
