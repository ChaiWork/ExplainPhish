"""
Unit Tests for ML Inference Engine & Forensic Decision Logic
=============================================================
Tests format detection, SSO/form safety checks, DOM origin inference,
multi-model bundle loading, feature standardization, XAI drivers,
and voting consensus logic.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from InterfaceExplainPhish import inference

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "InterfaceExplainPhish" / "Sample"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Format Sniffing & Magic Bytes
# ─────────────────────────────────────────────────────────────────────────────


class TestFormatDetection:
    """Tests for detect_format logic with extensions and magic byte fallbacks."""

    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("document.pdf", "pdf"),
            ("report.PDF", "pdf"),
            ("letter.docx", "word"),
            ("template.dotx", "word"),
            ("sheet.xlsx", "excel"),
            ("data.xlsm", "excel"),
            ("index.html", "html"),
            ("login.htm", "html"),
        ],
    )
    def test_detect_format_by_extension(self, tmp_path, filename, expected):
        p = tmp_path / filename
        p.touch()
        assert inference.detect_format(p) == expected

    def test_detect_format_pdf_magic_bytes(self, tmp_path):
        """File without extension detected as PDF by %PDF header."""
        p = tmp_path / "mystery_file"
        p.write_bytes(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj")
        assert inference.detect_format(p) == "pdf"

    def test_detect_format_html_magic_bytes(self, tmp_path):
        """File without extension detected as HTML by DOCTYPE."""
        p = tmp_path / "page_no_ext"
        p.write_bytes(b"<!DOCTYPE html>\n<html><head></head><body>Hello</body></html>")
        assert inference.detect_format(p) == "html"

    def test_detect_format_ooxml_word(self, tmp_path):
        """Zip archive with word/ folder detected as word."""
        p = tmp_path / "no_ext_word"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("word/document.xml", "<w:document/>")
        assert inference.detect_format(p) == "word"

    def test_detect_format_ooxml_excel(self, tmp_path):
        """Zip archive with xl/ folder detected as excel."""
        p = tmp_path / "no_ext_excel"
        with zipfile.ZipFile(p, "w") as zf:
            zf.writestr("xl/workbook.xml", "<workbook/>")
        assert inference.detect_format(p) == "excel"

    def test_detect_format_unknown(self, tmp_path):
        """Arbitrary binary data without known headers raises ValueError."""
        p = tmp_path / "blob.xyz"
        p.write_bytes(b"\x00\x01\x02\x03\x04\x05")
        with pytest.raises(ValueError, match="Unsupported file extension"):
            inference.detect_format(p)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Form Actions & SSO Whitelist
# ─────────────────────────────────────────────────────────────────────────────


class TestFormActionAndSSO:
    """Tests for external form action checking and SSO authentication validation."""

    @pytest.mark.parametrize(
        "sso_host,expected",
        [
            ("login.microsoftonline.com", True),
            ("accounts.google.com", True),
            ("auth.okta.com", True),
            ("mycompany.auth0.com", True),
            ("appleid.apple.com", True),
            ("evil-phish-portal.com", False),
            ("malicious-harvest.xyz", False),
        ],
    )
    def test_is_trusted_sso_host(self, sso_host, expected):
        assert inference.is_trusted_sso_host(sso_host) == expected

    def test_is_external_form_action_relative(self):
        """Relative actions within the same site are never external."""
        assert not inference.is_external_form_action("/auth/login.php", "portal.company.com")
        assert not inference.is_external_form_action("submit", "portal.company.com")
        assert not inference.is_external_form_action("", "portal.company.com")

    def test_is_external_form_action_same_host(self):
        """Absolute URLs targeting the identical host are internal."""
        assert not inference.is_external_form_action("https://portal.company.com/api/login", "portal.company.com")

    def test_is_external_form_action_subdomain(self):
        """Subdomains or shared organization parent domains are recognized."""
        assert not inference.is_external_form_action("https://auth.company.com/login", "company.com")
        assert not inference.is_external_form_action("https://company.com/login", "auth.company.com")

    def test_is_external_form_action_external_evil_host(self):
        """External destination on untrusted host is flagged as external form exfiltration."""
        assert inference.is_external_form_action("https://evil-credential-harvester.com/steal", "portal.company.com")

    def test_is_external_form_action_trusted_sso_exception(self):
        """External destination on trusted corporate SSO is not an untrusted exfiltration."""
        assert not inference.is_external_form_action("https://login.microsoftonline.com/common/login", "portal.company.com")


# ─────────────────────────────────────────────────────────────────────────────
# 3. DOM Origin Inference
# ─────────────────────────────────────────────────────────────────────────────


class TestDomOriginInference:
    """Tests for extracting the intended authority/origin from document markup."""

    def test_infer_from_base_href(self):
        html = '<html><head><base href="https://secure.bankofamerica.com/login/"></head></html>'
        assert inference.extract_html_origin(html) == "secure.bankofamerica.com"

    def test_infer_from_og_url(self):
        html = '<html><head><meta property="og:url" content="https://www.paypal.com/signin"></head></html>'
        assert inference.extract_html_origin(html) == "www.paypal.com"

    def test_infer_from_favicon(self):
        html = '<html><head><link rel="shortcut icon" href="https://assets.netflix.com/favicon.ico"></head></html>'
        assert inference.extract_html_origin(html) == "assets.netflix.com"

    def test_infer_from_cms_config(self):
        html = '<script>var M = { wwwroot: "https://learning.university.edu" };</script>'
        assert inference.extract_html_origin(html) == "learning.university.edu"

    def test_infer_empty_when_no_clues(self):
        html = '<html><body><p>Just plain text with no links.</p></body></html>'
        assert inference.extract_html_origin(html) == ""


# ─────────────────────────────────────────────────────────────────────────────
# 4. Model Loading & Feature Standardization
# ─────────────────────────────────────────────────────────────────────────────


class TestModelBundleAndStandardization:
    """Tests for loading bundles, standardizing features, and computing XAI drivers."""

    @pytest.mark.parametrize("fmt", ["pdf", "html", "word", "excel"])
    def test_load_model_bundle_structure(self, fmt):
        """Ensure all required model bundles exist and contain standard components."""
        bundle = inference.load_model_bundle(fmt)
        assert bundle["fmt"] == fmt
        assert bundle["rf_model"] is not None
        assert bundle["dt_model"] is not None
        assert bundle["scaler"] is not None
        assert isinstance(bundle["selected_features"], list)
        assert len(bundle["selected_features"]) > 0

    def test_standardize_features(self):
        """Standardization outputs 2D array and dictionary of float z-scores."""
        bundle = inference.load_model_bundle("pdf")
        sel_features = bundle["selected_features"]
        raw = {k: 50.0 for k in sel_features}

        sample_std, std_dict = inference.standardize_features(raw, sel_features, bundle["scaler"])
        assert isinstance(sample_std, np.ndarray)
        assert sample_std.shape == (1, len(sel_features))
        assert isinstance(std_dict, dict)
        for k in sel_features:
            assert k in std_dict
            assert isinstance(std_dict[k], float)

    def test_compute_risk_drivers(self):
        """XAI drivers compute feature impacts and directional risk indicators."""
        bundle = inference.load_model_bundle("pdf")
        sel_features = bundle["selected_features"]
        raw = {k: 10.0 for k in sel_features}

        sample_std, std_dict = inference.standardize_features(raw, sel_features, bundle["scaler"])
        drivers = inference.compute_risk_drivers(bundle, raw, std_dict, sample_std=sample_std, fmt="pdf", n_top=4)

        assert len(drivers) == 4
        for d in drivers:
            assert "feature" in d
            assert "description" in d
            assert "impact" in d
            assert "direction" in d
            assert d["direction"] in ("↑", "↓")


# ─────────────────────────────────────────────────────────────────────────────
# 5. Multi-Model Inference Execution
# ─────────────────────────────────────────────────────────────────────────────


class TestRunInference:
    """Tests for run_inference pipeline execution."""

    def test_run_inference_pdf_sample(self):
        """Execute full inference pipeline on PDF benign sample."""
        sample_pdf = next(SAMPLE_DIR.glob("pbenign_pdf/*.pdf"), None)
        if not sample_pdf:
            pytest.skip("No PDF sample found")

        res = inference.run_inference(sample_pdf, fmt="pdf")
        assert res["format"] == "pdf"
        assert len(res["model_predictions"]) >= 3
        assert "vote" in res
        assert res["vote"]["verdict"] in ("BENIGN", "MALICIOUS")
        assert 0.0 <= res["vote"]["confidence"] <= 1.0
        assert res["vote"]["confidence_band"] in ("HIGH", "MEDIUM", "LOW")

    def test_run_inference_target_model_selection(self):
        """Selecting a specific target model isolates that architecture's prediction."""
        sample_pdf = next(SAMPLE_DIR.glob("pbenign_pdf/*.pdf"), None)
        if not sample_pdf:
            pytest.skip("No PDF sample found")

        res = inference.run_inference(sample_pdf, fmt="pdf", target_model="Random Forest")
        assert res["vote"]["target_model"] == "Random Forest"
        assert res["vote"]["verdict"] in ("BENIGN", "MALICIOUS")

    def test_run_inference_invalid_target_model(self):
        """Requesting an invalid architecture raises ValueError."""
        sample_pdf = next(SAMPLE_DIR.glob("pbenign_pdf/*.pdf"), None)
        if not sample_pdf:
            pytest.skip("No PDF sample found")

        with pytest.raises(ValueError, match="not available"):
            inference.run_inference(sample_pdf, fmt="pdf", target_model="NonExistentArchitecture")

    def test_run_inference_missing_file_raises(self, tmp_path):
        """Missing input file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            inference.run_inference(tmp_path / "ghost.pdf", fmt="pdf")
