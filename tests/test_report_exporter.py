"""
Unit Tests for Incident Report Exporter (PDF & DOCX)
=====================================================
Tests ReportLab XML escaping, markdown sanitization, NumberedCanvas footers,
and document generation across standard, minimal, and edge-case state payloads.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from InterfaceExplainPhish import report_exporter


# ─────────────────────────────────────────────────────────────────────────────
# 1. XML Safety and Markdown Conversion Utilities
# ─────────────────────────────────────────────────────────────────────────────


class TestReportLabSanitizers:
    """Tests for XML entity escaping and ReportLab paraparser protection."""

    def test_safe_xml_entities(self):
        """Verify XML special characters (&, <, >) are properly escaped."""
        raw = "Alert: <script>if (a && b) alert('xss');</script>"
        escaped = report_exporter._safe_xml(raw)
        assert "<script>" not in escaped
        assert "&lt;script&gt;" in escaped
        assert "&&" not in escaped
        assert "&amp;&amp;" in escaped

    def test_safe_xml_none_and_numbers(self):
        """None returns empty string, numeric values converted cleanly."""
        assert report_exporter._safe_xml(None) == ""
        assert report_exporter._safe_xml(12345) == "12345"
        assert report_exporter._safe_xml(0.987) == "0.987"

    def test_safe_markdown_to_paragraph_xml(self):
        """Markdown bold, italic, and inline code converted to valid XML tags."""
        md = "This is **critical** and *suspicious* with `sha256_hash` code."
        xml = report_exporter._safe_markdown_to_paragraph_xml(md)
        assert "<b>critical</b>" in xml
        assert "<i>suspicious</i>" in xml
        assert "<font name='Courier' size='7.5'>sha256_hash</font>" in xml

    def test_safe_markdown_unclosed_tags_do_not_crash(self):
        """Unclosed markdown asterisks or code backticks do not produce broken XML."""
        broken_md = "Unclosed **bold and unclosed `backtick & special <tag>"
        xml = report_exporter._safe_markdown_to_paragraph_xml(broken_md)
        assert "&lt;tag&gt;" in xml
        assert "&amp;" in xml

    def test_clean_markdown_text_strips_tokens(self):
        """Markdown headings and emphasis stripped for plain-text insertion in Word."""
        md = "### Threat Analysis: **MALICIOUS** artifact with `vba_macro`"
        cleaned = report_exporter._clean_markdown_text(md)
        assert "###" not in cleaned
        assert "**" not in cleaned
        assert "`" not in cleaned
        assert "Threat Analysis: MALICIOUS artifact with vba_macro" in cleaned


# ─────────────────────────────────────────────────────────────────────────────
# 2. PDF Report Generation
# ─────────────────────────────────────────────────────────────────────────────


class TestPdfReportGeneration:
    """Tests for generate_pdf_report."""

    @pytest.fixture
    def full_state(self):
        """Complete 8-section SOC incident state fixture."""
        return {
            "file_name": "malicious_dropper.pdf",
            "file_format": "PDF Document",
            "format_display": "PDF Document",
            "file_size_bytes": 1048576,
            "file_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "file_hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
            "final_verdict": "MALICIOUS",
            "ensemble_verdict": "MALICIOUS",
            "threat_level": "HIGH",
            "confidence_score": 0.942,
            "confidence_band": "HIGH",
            "unanimous": True,
            "source_url": "https://company.sharepoint.com/dropper.pdf",
            "applied_rules": {
                "intake_safety": "Rule 1: Sandbox checks passed",
                "ml_ensemble": "Rule 3: 5/5 models voted malicious",
                "analyst_review": "Rule 7A: Signed off by Tier 2",
            },
            "deep_analysis": {
                "rationale": "High-risk auto-execution script trigger detected",
                "indicators": ["/OpenAction auto-executes upon PDF load"],
            },
            "llm_triage": {
                "provider": "ExplainPhish Cognitive Reasoner",
                "model": "symbolic-v2",
                "status_badge": "Live Cognitive Forensics",
                "executive_threat_narrative": "### Threat Intelligence\n\nArtifact contains **weaponized scripts** targeting Adobe Acrobat.",
            },
            "model_predictions": [
                {"model": "Random Forest", "prediction": 1, "probability": 0.95},
                {"model": "XGBoost", "prediction": 1, "probability": 0.98},
            ],
            "top_risk_drivers": [
                {
                    "feature": "entropy_of_streams",
                    "description": "Stream Shannon entropy",
                    "raw_value": 7.99,
                    "std_value": 2.1,
                    "direction": "↑",
                    "impact": 0.42,
                }
            ],
            "indicators_of_compromise": [
                {"type": "SHA-256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
            ],
            "mitre_tactics": [
                {
                    "id": "T1566.001",
                    "tactic": "Initial Access",
                    "technique": "Spearphishing Attachment",
                    "description": "Weaponized email attachment",
                }
            ],
            "soc_playbook_actions": [
                {
                    "stage": "Containment",
                    "tier": "Tier 1 - Endpoint Isolation",
                    "action": "Isolate endpoint on EDR",
                }
            ],
            "analyst_review": {
                "status": "APPROVED",
                "decision": "APPROVE",
                "analyst_id": "SOC-Analyst-Tier2",
                "reviewed_at": "2026-10-15 04:36:45 UTC",
                "notes": "Verified malicious payload.",
            },
        }

    def test_generate_pdf_full_state(self, full_state):
        """Generate PDF from full state and verify binary output structure."""
        pdf_bytes = report_exporter.generate_pdf_report(full_state)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 5000
        assert pdf_bytes.startswith(b"%PDF-")

    def test_generate_pdf_minimal_empty_state(self):
        """Minimal or empty state payload generates valid PDF without crashing."""
        minimal_state = {"file_name": "unknown_file"}
        pdf_bytes = report_exporter.generate_pdf_report(minimal_state)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")

    def test_generate_pdf_malformed_xml_narrative_recovery(self, full_state):
        """Narrative containing invalid unescaped XML triggers fallback without crash."""
        full_state["llm_triage"]["executive_threat_narrative"] = (
            "Broken XML tag <unclosed_tag and raw ampersand & that breaks parser"
        )
        pdf_bytes = report_exporter.generate_pdf_report(full_state)
        assert isinstance(pdf_bytes, bytes)
        assert pdf_bytes.startswith(b"%PDF-")


# ─────────────────────────────────────────────────────────────────────────────
# 3. Microsoft Word (.docx) Report Generation
# ─────────────────────────────────────────────────────────────────────────────


class TestDocxReportGeneration:
    """Tests for generate_docx_report."""

    def test_generate_docx_full_state(self):
        """Generate Word document from full state and verify OOXML zip structure."""
        state = {
            "file_name": "sample_invoice.docx",
            "final_verdict": "BENIGN",
            "threat_level": "LOW",
            "confidence_score": 0.99,
            "confidence_band": "HIGH",
            "file_size_bytes": 45000,
            "file_hash_sha256": "abc123sha256",
            "file_hash_md5": "md5hash123",
            "applied_rules": {"intake_safety": "Clean document"},
            "deep_analysis": {"rationale": "0 macros detected"},
            "model_predictions": [{"model": "Random Forest", "prediction": 0, "probability": 0.01}],
            "top_risk_drivers": [
                {
                    "feature": "macro_present",
                    "description": "VBA macro indicator",
                    "raw_value": 0,
                    "std_value": -0.5,
                    "direction": "↓",
                    "impact": -0.3,
                }
            ],
            "analyst_review": {
                "status": "APPROVED",
                "decision": "APPROVE",
                "analyst_id": "SOC-Analyst-Tier1",
            },
        }

        docx_bytes = report_exporter.generate_docx_report(state)
        assert isinstance(docx_bytes, bytes)
        assert len(docx_bytes) > 5000

        # Verify it is a valid docx zip archive containing word/document.xml
        with zipfile.ZipFile(io.BytesIO(docx_bytes), "r") as zf:
            assert "word/document.xml" in zf.namelist()

    def test_generate_docx_empty_state(self):
        """Empty state payload generates valid DOCX without crashing."""
        docx_bytes = report_exporter.generate_docx_report({})
        assert isinstance(docx_bytes, bytes)
        with zipfile.ZipFile(io.BytesIO(docx_bytes), "r") as zf:
            assert "word/document.xml" in zf.namelist()
