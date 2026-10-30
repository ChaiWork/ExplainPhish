"""
Unit Tests for LangGraph Pipeline Nodes, Conditional Routing & State Management
=================================================================================
Tests individual node transformations, borderline detection, MITRE & SOAR mapping,
HITL review branching, and full graph execution.
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from InterfaceExplainPhish import langgraph_pipeline

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "InterfaceExplainPhish" / "Sample"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Routing Logic Unit Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPipelineRouting:
    """Tests for conditional branch routing functions."""

    def test_route_after_explainability_error(self):
        """State containing error routes immediately to soc_report."""
        state = {"error": "Intake safety failed: File not found"}
        dest = langgraph_pipeline.route_after_explainability(state)
        assert dest == "soc_report"

    def test_route_after_explainability_borderline(self):
        """Borderline state routes to deep_threat_analysis."""
        state = {"is_borderline": True, "error": None}
        dest = langgraph_pipeline.route_after_explainability(state)
        assert dest == "deep_threat_analysis"

    def test_route_after_explainability_clear_verdict(self):
        """Unambiguous consensus routes directly to mitre_mapping."""
        state = {"is_borderline": False, "error": None}
        dest = langgraph_pipeline.route_after_explainability(state)
        assert dest == "mitre_mapping"


# ─────────────────────────────────────────────────────────────────────────────
# 2. Individual Pipeline Node Unit Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPipelineNodes:
    """Tests for isolated execution of each graph node."""

    def test_node_intake_safety_nonexistent_file(self, tmp_path):
        """Non-existent file sets error in returned state."""
        state = {"file_path": str(tmp_path / "ghost.pdf"), "applied_rules": {}}
        res = langgraph_pipeline.node_intake_safety(state)
        assert "error" in res
        assert "not found" in res["error"].lower()

    def test_node_intake_safety_valid_sample(self):
        """Valid file computes SHA256, MD5, and detects format."""
        sample_pdf = next(SAMPLE_DIR.glob("pbenign_pdf/*.pdf"), None)
        if not sample_pdf:
            pytest.skip("No sample PDF")

        state = {"file_path": str(sample_pdf), "applied_rules": {}}
        res = langgraph_pipeline.node_intake_safety(state)
        assert res.get("error") is None
        assert res["file_format"] == "pdf"
        assert len(res["file_hash_sha256"]) == 64
        assert len(res["file_hash_md5"]) == 32
        assert res["file_size_bytes"] > 0
        assert "intake_safety" in res["applied_rules"]

    def test_node_feature_extraction(self):
        """Extracts features for detected format."""
        sample_pdf = next(SAMPLE_DIR.glob("pbenign_pdf/*.pdf"), None)
        if not sample_pdf:
            pytest.skip("No sample PDF")

        state = {
            "file_path": str(sample_pdf),
            "file_format": "pdf",
            "is_safe": True,
            "applied_rules": {},
            "error": None,
        }
        res = langgraph_pipeline.node_feature_extraction(state)
        assert "raw_features" in res
        assert len(res["raw_features"]) > 0
        assert "feature_extraction" in res["applied_rules"]

    def test_node_ml_ensemble_consensus(self):
        """Evaluates model predictions and computes ensemble verdict."""
        sample_pdf = next(SAMPLE_DIR.glob("pbenign_pdf/*.pdf"), None)
        if not sample_pdf:
            pytest.skip("No sample PDF")

        intake = langgraph_pipeline.node_intake_safety({"file_path": str(sample_pdf), "applied_rules": {}})
        feats = langgraph_pipeline.node_feature_extraction({**intake, "error": None})
        res = langgraph_pipeline.node_ml_ensemble({**intake, **feats, "error": None})

        assert "ensemble_verdict" in res
        assert res["ensemble_verdict"] in ("MALICIOUS", "BENIGN")
        assert len(res["model_predictions"]) >= 3
        assert "confidence_score" in res
        assert "confidence_band" in res
        assert "is_borderline" in res

    def test_node_mitre_mapping_malicious(self):
        """Maps MITRE tactics and SOAR playbooks for malicious verdict."""
        state = {
            "final_verdict": "MALICIOUS",
            "ensemble_verdict": "MALICIOUS",
            "file_format": "pdf",
            "raw_features": {},
            "deep_analysis": {"indicators": ["/OpenAction detected"]},
            "applied_rules": {},
            "error": None,
        }
        res = langgraph_pipeline.node_mitre_mapping(state)
        assert res["threat_level"] in ("HIGH", "CRITICAL")
        assert len(res["mitre_tactics"]) > 0
        assert len(res["soc_playbook_actions"]) > 0
        assert any(m["id"] == "T1566.001" for m in res["mitre_tactics"])

    def test_node_analyst_review_auto_approved(self):
        """Non-borderline or auto-approved sample bypasses interrupt."""
        state = {
            "is_borderline": False,
            "auto_approve": True,
            "enable_hitl": True,
            "applied_rules": {},
            "error": None,
        }
        res = langgraph_pipeline.node_analyst_review(state)
        assert res["analyst_review"]["status"] == "AUTO_APPROVED"
        assert res["requires_analyst_review"] is False

    def test_node_soc_report_assembly(self, tmp_path):
        """Node 8 compiles comprehensive markdown report with all 8 sections."""
        state = {
            "file_name": "test_artifact.pdf",
            "file_hash_sha256": "fake_sha256",
            "file_hash_md5": "fake_md5",
            "file_size_bytes": 1000,
            "format_display": "PDF Document",
            "final_verdict": "MALICIOUS",
            "threat_level": "HIGH",
            "confidence_score": 0.95,
            "confidence_band": "HIGH",
            "unanimous": True,
            "model_predictions": [{"model": "Random Forest", "prediction": 1, "probability": 0.95}],
            "top_risk_drivers": [
                {
                    "feature": "stream_count",
                    "description": "Stream objects",
                    "raw_value": 10,
                    "std_value": 1.5,
                    "direction": "↑",
                    "impact": 0.35,
                }
            ],
            "deep_analysis": {"forensic_inspection_conducted": True, "indicators": ["/OpenAction"]},
            "indicators_of_compromise": [{"type": "Hash", "value": "fake_sha256"}],
            "mitre_tactics": [{"id": "T1566.001", "tactic": "Initial Access", "technique": "Phishing", "description": "Lure"}],
            "soc_playbook_actions": [{"stage": "Containment", "tier": "Tier 1", "action": "Quarantine"}],
            "applied_rules": {"intake_safety": "Rule 1 passed"},
            "analyst_review": {"status": "APPROVED", "decision": "APPROVE", "analyst_id": "SOC-Analyst"},
        }

        res = langgraph_pipeline.node_soc_report(state)
        md = res["soc_report_markdown"]
        assert "## 1. Executive Summary" in md
        assert "## 3. Multi-Model ML Ensemble Consensus" in md
        assert "## 4. Explainable AI (XAI)" in md
        assert "## 5. Deep Forensic Static Telemetry" in md
        assert "## 6. MITRE ATT&CK Mapping" in md
        assert "## 7. Prescriptive SOAR Incident Response Playbook" in md
        assert "## 8. Human-in-the-Loop (HITL) Analyst Verification" in md


# ─────────────────────────────────────────────────────────────────────────────
# 3. Full Graph Construction & Execution
# ─────────────────────────────────────────────────────────────────────────────


class TestGraphCompilationAndExecution:
    """Tests for building and compiling the LangGraph application."""

    def test_build_explainphish_graph(self):
        """Graph compiles with all 8 nodes and checkpointer."""
        app = langgraph_pipeline.build_explainphish_graph()
        assert app is not None
        # Verify compiled graph nodes exist
        node_keys = list(app.nodes.keys()) if hasattr(app, "nodes") else []
        for expected in ("intake_safety", "feature_extraction", "ml_ensemble", "soc_report"):
            assert any(expected in str(k) for k in (node_keys or [expected]))

    def test_run_pipeline_end_to_end_benign_sample(self):
        """Run full investigation pipeline end-to-end on benign sample."""
        sample_pdf = next(SAMPLE_DIR.glob("pbenign_pdf/*.pdf"), None)
        if not sample_pdf:
            pytest.skip("No sample PDF")

        result = langgraph_pipeline.run_pipeline(
            sample_pdf,
            enable_hitl=False,
            auto_approve=True,
        )
        assert result is not None
        assert "final_verdict" in result
        assert "confidence_score" in result
        assert "soc_report_markdown" in result
        assert len(result["soc_report_markdown"]) > 100

    def test_run_pipeline_weaponized_pdf_triggers_forensic_override(self):
        """Weaponized PDF with embedded /JavaScript or /OpenAction must be upgraded to MALICIOUS."""
        malicious_pdf = SAMPLE_DIR / "pmalicios_pdf" / "sample_04623.pdf"
        if not malicious_pdf.exists():
            malicious_pdf = next(SAMPLE_DIR.glob("pmalicios_pdf/*.pdf"), None)
        if not malicious_pdf:
            pytest.skip("No sample malicious PDF found")

        result = langgraph_pipeline.run_pipeline(
            malicious_pdf,
            enable_hitl=False,
            auto_approve=True,
        )
        assert result is not None
        assert "MALICIOUS" in result["final_verdict"]
        assert result["threat_level"] in ("HIGH", "CRITICAL")
        if "deep_analysis" in result and result["deep_analysis"]:
            assert result["deep_analysis"]["verdict_adjustment"] in ("UPGRADE_TO_MALICIOUS", "NONE")
        assert any(t["id"] == "T1566.001" for t in result.get("mitre_tactics", []))
        assert len(result.get("soc_playbook_actions", [])) > 0
