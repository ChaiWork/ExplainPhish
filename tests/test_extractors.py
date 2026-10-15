"""
Unit Tests for Static Feature Extractors & Safety Guards
=========================================================
Tests base safety limits, output validation, and format-specific extractors
(HTML, PDF, Word, Excel) covering normal, boundary, and error scenarios.
"""

from __future__ import annotations

import io
import math
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from InterfaceExplainPhish.extractors import base
from InterfaceExplainPhish.extractors import html_extractor
from InterfaceExplainPhish.extractors import pdf_extractor
from InterfaceExplainPhish.extractors import word_extractor
from InterfaceExplainPhish.extractors import excel_extractor

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "InterfaceExplainPhish" / "Sample"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Base Extractor & Safety Pre-checks
# ─────────────────────────────────────────────────────────────────────────────


class TestBaseExtractorSafety:
    """Tests for base.py security limits, zip bombs, and output validation."""

    def test_check_file_safety_nonexistent_file(self, tmp_path):
        """Non-existent file should raise ExtractionError."""
        fake_path = tmp_path / "does_not_exist.pdf"
        with pytest.raises(base.ExtractionError, match="File not found"):
            base.check_file_safety(fake_path)

    def test_check_file_safety_oversized_file(self, tmp_path):
        """Files exceeding MAX_FILE_SIZE_MB should be rejected."""
        large_file = tmp_path / "oversized.bin"
        large_file.write_bytes(b"A" * 1024)

        # Mock stat().st_size to pretend it is 60 MB (> 50 MB limit) with valid st_mode
        with patch.object(Path, "stat") as mock_stat:
            mock_res = MagicMock()
            mock_res.st_size = 60 * 1024 * 1024
            mock_res.st_mode = 0o100644  # Regular file mode
            mock_stat.return_value = mock_res
            with pytest.raises(base.ExtractionError, match="File too large"):
                base.check_file_safety(large_file)

    def test_check_file_safety_valid_normal_file(self, tmp_path):
        """Normal small file passes safety checks."""
        normal_file = tmp_path / "safe.txt"
        normal_file.write_text("Hello security sandbox", encoding="utf-8")
        # Should not raise
        base.check_file_safety(normal_file, check_zip_bomb=False)

    def test_zip_bomb_excessive_expansion_ratio(self, tmp_path):
        """Zip archive with compressed:uncompressed ratio > 100x is rejected."""
        bomb_path = tmp_path / "ratio_bomb.zip"
        # Create a zip containing highly compressible zeroes (ratio > 100x)
        with zipfile.ZipFile(bomb_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeroes.bin", b"\x00" * 500_000)

        # The compressed size will be ~500 bytes, uncompressed 500,000 bytes (~1000x ratio)
        with pytest.raises(base.ExtractionError, match="ZIP bomb rejected"):
            base.check_file_safety(bomb_path, check_zip_bomb=True)

    def test_zip_bomb_non_zip_file_handled_gracefully(self, tmp_path):
        """Non-zip file checked with check_zip_bomb=True does not raise unhandled crash."""
        text_file = tmp_path / "not_a_zip.txt"
        text_file.write_text("Just plain text", encoding="utf-8")
        # Should not raise since is_zipfile is False
        base.check_file_safety(text_file, check_zip_bomb=True)

    def test_validate_output_success(self):
        """Outputs containing all required numeric keys pass validation."""
        req = ["feat_a", "feat_b"]
        raw = {"feat_a": 10, "feat_b": 0.5, "extra": "ignored"}
        res = base.validate_output(raw, req, "test")
        assert res == {"feat_a": 10, "feat_b": 0.5}
        assert "extra" not in res

    def test_validate_output_missing_key(self):
        """Missing required keys trigger ExtractionError."""
        req = ["feat_a", "feat_b"]
        raw = {"feat_a": 10}
        with pytest.raises(base.ExtractionError, match="Missing keys"):
            base.validate_output(raw, req, "test")

    def test_validate_output_non_numeric_key(self):
        """Non-numeric feature values trigger ExtractionError."""
        req = ["feat_a"]
        raw = {"feat_a": "not_a_number"}
        with pytest.raises(base.ExtractionError, match="Non-numeric values"):
            base.validate_output(raw, req, "test")


# ─────────────────────────────────────────────────────────────────────────────
# 2. HTML Feature Extractor
# ─────────────────────────────────────────────────────────────────────────────


class TestHtmlExtractor:
    """Tests for html_extractor.py logic."""

    def test_extract_html_normal_file(self, tmp_path):
        """Extract features from standard HTML content."""
        html_file = tmp_path / "page.html"
        html_file.write_text(
            """<!DOCTYPE html>
            <html>
            <head><title>Secure Portal</title></head>
            <body>
                <form action="https://evil.com/login" method="POST">
                    <input type="text" name="user"/>
                    <input type="password" name="pass"/>
                    <input type="submit" value="Log In"/>
                </form>
                <a href="https://legit.com/home">Home</a>
                <a href="http://untrusted.org/phish">Click here</a>
                <script>console.log('hi');</script>
            </body>
            </html>""",
            encoding="utf-8",
        )

        features = html_extractor.extract(html_file)
        assert isinstance(features, dict)
        for k in html_extractor.REQUIRED_KEYS:
            assert k in features, f"Missing key {k}"
            assert isinstance(features[k], (int, float)), f"Feature {k} must be numeric, got {type(features[k])}"
        assert features["form_count"] == 1
        assert features["external_link_count"] >= 1

    def test_extract_html_empty_file(self, tmp_path):
        """Extract features from empty HTML file without crashing."""
        empty_html = tmp_path / "empty.html"
        empty_html.write_text("", encoding="utf-8")
        features = html_extractor.extract(empty_html)
        assert isinstance(features, dict)
        for k in html_extractor.REQUIRED_KEYS:
            assert k in features


# ─────────────────────────────────────────────────────────────────────────────
# 3. PDF Feature Extractor
# ─────────────────────────────────────────────────────────────────────────────


class TestPdfExtractor:
    """Tests for pdf_extractor.py logic."""

    def test_entropy_calculation(self):
        """Entropy of empty data is 0; random bytes have high entropy."""
        assert pdf_extractor._entropy(b"") == 0.0
        # Single repeated byte has zero entropy
        assert pdf_extractor._entropy(b"AAAA") == 0.0
        # Diverse bytes have higher entropy
        varied = bytes(range(256))
        assert math.isclose(pdf_extractor._entropy(varied), 8.0, rel_tol=1e-3)

    def test_extract_pdf_sample_or_synthetic(self, tmp_path):
        """Extract static features from PDF sample file."""
        sample_pdf = next(SAMPLE_DIR.glob("pbenign_pdf/*.pdf"), None)
        if sample_pdf and sample_pdf.exists():
            target_path = sample_pdf
        else:
            # Synthetic minimal valid PDF
            target_path = tmp_path / "minimal.pdf"
            target_path.write_bytes(
                b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nstream\nhello\nendstream\n%%EOF"
            )

        features = pdf_extractor.extract(target_path)
        assert isinstance(features, dict)
        for k in pdf_extractor.REQUIRED_KEYS:
            assert k in features
            assert isinstance(features[k], (int, float))

        assert features["valid_pdf_header"] in (0, 1)
        assert features["file_size"] > 0

    def test_extract_pdf_invalid_header(self, tmp_path):
        """PDF with corrupt header sets valid_pdf_header = 0."""
        corrupt_pdf = tmp_path / "corrupt.pdf"
        corrupt_pdf.write_bytes(b"NOT_A_PDF_CONTENT\nstream\nabc\nendstream")
        features = pdf_extractor.extract(corrupt_pdf)
        assert features["valid_pdf_header"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# 4. Word Feature Extractor
# ─────────────────────────────────────────────────────────────────────────────


class TestWordExtractor:
    """Tests for word_extractor.py logic."""

    def test_extract_word_sample(self, tmp_path):
        """Extract static features from real sample or minimal OOXML docx."""
        sample_docx = next(SAMPLE_DIR.glob("wBenign_word/*.docx"), None)
        if sample_docx and sample_docx.exists():
            features = word_extractor.extract(sample_docx)
            assert isinstance(features, dict)
            assert len(features) > 0
            for k, v in features.items():
                assert isinstance(v, (int, float)), f"Feature {k} must be numeric, got {type(v)}"
        else:
            pytest.skip("No sample docx available")

    def test_extract_word_non_zip_fallback(self, tmp_path):
        """Non-zip Word file produces numeric feature vector without unhandled exception."""
        dummy = tmp_path / "dummy.doc"
        dummy.write_bytes(b"This is a non-zip legacy/corrupt word document")
        features = word_extractor.extract(dummy)
        assert isinstance(features, dict)
        assert len(features) > 0
        for k, v in features.items():
            assert isinstance(v, (int, float)), f"Feature {k} must be numeric, got {type(v)}"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Excel Feature Extractor
# ─────────────────────────────────────────────────────────────────────────────


class TestExcelExtractor:
    """Tests for excel_extractor.py logic."""

    def test_extract_excel_sample(self):
        """Extract static features from real Excel benign sample."""
        sample_xlsx = next(SAMPLE_DIR.glob("eBenign_Excel/*.xlsx"), None)
        if sample_xlsx and sample_xlsx.exists():
            features = excel_extractor.extract(sample_xlsx)
            assert isinstance(features, dict)
            assert len(features) > 0
            for k, v in features.items():
                assert isinstance(v, (int, float))
        else:
            pytest.skip("No sample xlsx available")

    def test_extract_excel_corrupt_file(self, tmp_path):
        """Corrupt or non-zip Excel file returns zeroed feature vector without crash."""
        corrupt_xlsx = tmp_path / "corrupt.xlsx"
        corrupt_xlsx.write_bytes(b"NOT_A_ZIP_EXCEL")
        features = excel_extractor.extract(corrupt_xlsx)
        assert isinstance(features, dict)
        for k, v in features.items():
            assert isinstance(v, (int, float))
