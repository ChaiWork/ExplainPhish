"""
ExplainPhish Desktop SOC Analyst Console
=========================================
Production-Grade Enterprise Incident Response & Threat Investigation Workstation.
Built with PySide6 (Qt 6) adhering to strict enterprise SOC design standards:
  - Restrained, accessible dark cyber intelligence palette (#0B1120 base)
  - Master-Detail split architecture with responsive QSplitter
  - Zero-emoji professional iconography and typographic status indicators
  - Prominent Executive Verdict and Prescriptive Next Action engine
  - Non-blocking multi-threaded LangGraph pipeline execution (QThread)
  - Responsive vertical timeline tracker with dynamic branch detection
  - Dedicated tabs: Overview, Model Consensus, Explainable AI, Forensics & IOCs,
    MITRE ATT&CK & SOAR, and Incident Response Report.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from PySide6.QtCore import QPoint, QRect, QSize, Qt, QThread, Signal
from PySide6.QtGui import (
    QAction,
    QClipboard,
    QColor,
    QCursor,
    QDragEnterEvent,
    QDropEvent,
    QFont,
    QKeySequence,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

# Ensure local imports work cleanly
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from langgraph_pipeline import ExplainPhishState, get_explainphish_graph

# ─────────────────────────────────────────────────────────────────────────────
# Enterprise SOC Design System Stylesheet
# ─────────────────────────────────────────────────────────────────────────────

SOC_ENTERPRISE_STYLESHEET = """
/* ────────────────────────── Global Application Canvas ────────────────────────── */
QMainWindow, QWidget {
    background-color: #0B1120;
    color: #F1F5F9;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Inter', Roboto, sans-serif;
    font-size: 13px;
}

/* ────────────────────────── Typography Tokens ────────────────────────── */
.app-brand {
    color: #F8FAFC;
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 0.5px;
}
.app-subtitle {
    color: #94A3B8;
    font-size: 11px;
}
.section-header {
    color: #38BDF8;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}
.mono-label {
    font-family: 'Consolas', 'Cascadia Code', 'Fira Code', 'Monaco', monospace;
    font-size: 11px;
    color: #94A3B8;
}
.mono-val {
    font-family: 'Consolas', 'Cascadia Code', 'Fira Code', 'Monaco', monospace;
    font-size: 12px;
    color: #F1F5F9;
}

/* ────────────────────────── Surface & Container Cards ────────────────────────── */
QFrame.panel-card {
    background-color: #111827;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
}
QFrame.panel-card-inset {
    background-color: #172033;
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-radius: 6px;
}
QFrame.verdict-banner-neutral {
    background-color: #111827;
    border: 1px solid rgba(255, 255, 255, 0.10);
    border-radius: 6px;
}
QFrame.verdict-banner-malicious {
    background-color: #1A0D12;
    border: 1px solid #EF4444;
    border-radius: 6px;
}
QFrame.verdict-banner-suspicious {
    background-color: #1C150A;
    border: 1px solid #F59E0B;
    border-radius: 6px;
}
QFrame.verdict-banner-benign {
    background-color: #0B1914;
    border: 1px solid #10B981;
    border-radius: 6px;
}

/* ────────────────────────── Buttons & Interactive Controls ────────────────────────── */
QPushButton {
    background-color: #1E293B;
    color: #F8FAFC;
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 5px;
    padding: 6px 14px;
    font-weight: 600;
    font-size: 12px;
}
QPushButton:hover {
    background-color: #334155;
    border-color: rgba(255, 255, 255, 0.24);
}
QPushButton:pressed {
    background-color: #0F172A;
}
QPushButton:disabled {
    background-color: #0F172A;
    color: #475569;
    border-color: rgba(255, 255, 255, 0.04);
}

QPushButton.btn-primary {
    background-color: #2563EB;
    color: #FFFFFF;
    border: 1px solid #3B82F6;
    padding: 7px 18px;
    font-weight: 700;
}
QPushButton.btn-primary:hover {
    background-color: #1D4ED8;
    border-color: #60A5FA;
}
QPushButton.btn-primary:pressed {
    background-color: #1E40AF;
}
QPushButton.btn-primary:disabled {
    background-color: #1E293B;
    color: #64748B;
    border-color: transparent;
}

QPushButton.btn-secondary {
    background-color: #172033;
    color: #E2E8F0;
    border: 1px solid rgba(255, 255, 255, 0.10);
    padding: 5px 12px;
}
QPushButton.btn-secondary:hover {
    background-color: #1E293B;
    border-color: #38BDF8;
}

QPushButton.btn-subtle {
    background-color: transparent;
    color: #94A3B8;
    border: 1px solid rgba(255, 255, 255, 0.08);
    padding: 4px 10px;
    font-size: 11px;
}
QPushButton.btn-subtle:hover {
    color: #F8FAFC;
    background-color: #172033;
    border-color: #38BDF8;
}

/* ────────────────────────── Inputs & Dropdowns ────────────────────────── */
QComboBox {
    background-color: #111827;
    color: #F8FAFC;
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 5px;
    padding: 5px 10px;
    font-size: 12px;
    min-height: 22px;
}
QComboBox:hover {
    border-color: #38BDF8;
}
QComboBox:focus {
    border-color: #2563EB;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #111827;
    color: #F8FAFC;
    selection-background-color: #2563EB;
    selection-color: #FFFFFF;
    border: 1px solid rgba(255, 255, 255, 0.15);
    padding: 4px;
}

/* ────────────────────────── Investigation Tab System ────────────────────────── */
QTabWidget::pane {
    border: 1px solid rgba(255, 255, 255, 0.08);
    background-color: #111827;
    border-radius: 6px;
    top: -1px;
}
QTabBar::tab {
    background-color: #0B1120;
    color: #94A3B8;
    padding: 8px 16px;
    margin-right: 3px;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    border: 1px solid transparent;
    font-weight: 600;
    font-size: 12px;
}
QTabBar::tab:hover {
    color: #F1F5F9;
    background-color: #172033;
}
QTabBar::tab:selected {
    color: #38BDF8;
    background-color: #111827;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-bottom: 2px solid #38BDF8;
}

/* ────────────────────────── Telemetry Tables ────────────────────────── */
QTableWidget {
    background-color: #0D1322;
    border: 1px solid rgba(255, 255, 255, 0.06);
    gridline-color: rgba(255, 255, 255, 0.04);
    color: #E2E8F0;
    border-radius: 5px;
    selection-background-color: #1E293B;
    selection-color: #38BDF8;
}
QTableWidget::item {
    padding: 6px 8px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.03);
}
QHeaderView::section {
    background-color: #111827;
    color: #94A3B8;
    padding: 6px 8px;
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border: none;
    border-bottom: 1px solid rgba(255, 255, 255, 0.10);
}

/* ────────────────────────── Text Display & Report Viewer ────────────────────────── */
QTextBrowser {
    background-color: #0D1322;
    border: 1px solid rgba(255, 255, 255, 0.06);
    color: #E2E8F0;
    font-family: 'Consolas', 'Cascadia Code', monospace;
    font-size: 12px;
    line-height: 1.5;
    border-radius: 5px;
    padding: 12px;
}

/* ────────────────────────── Splitter Styling ────────────────────────── */
QSplitter::handle {
    background-color: rgba(255, 255, 255, 0.05);
    width: 2px;
    height: 2px;
}
QSplitter::handle:hover {
    background-color: #38BDF8;
}

/* ────────────────────────── Scrollbars ────────────────────────── */
QScrollBar:vertical {
    background: #0B1120;
    width: 6px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #1E293B;
    min-height: 20px;
    border-radius: 3px;
}
QScrollBar::handle:vertical:hover {
    background: #334155;
}
QScrollBar:horizontal {
    background: #0B1120;
    height: 6px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: #1E293B;
    min-width: 20px;
    border-radius: 3px;
}
"""

# ─────────────────────────────────────────────────────────────────────────────
# Background LangGraph Pipeline Worker Thread
# ─────────────────────────────────────────────────────────────────────────────


class LangGraphWorker(QThread):
    """
    Executes ExplainPhish LangGraph StateGraph in a dedicated background worker thread.
    Streams incremental node completion updates, guaranteeing an ultra-responsive UI.
    """

    node_started_signal = Signal(str)
    node_completed_signal = Signal(str, dict)
    pipeline_finished_signal = Signal(dict)
    pipeline_error_signal = Signal(str)

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            graph = get_explainphish_graph()
            initial_state: ExplainPhishState = {"file_path": self.file_path}
            accumulated_state: Dict[str, Any] = dict(initial_state)

            for step in graph.stream(initial_state, stream_mode="updates"):
                for node_name, node_output in step.items():
                    accumulated_state.update(node_output)
                    self.node_completed_signal.emit(node_name, node_output)

            self.pipeline_finished_signal.emit(accumulated_state)

        except Exception as exc:
            import traceback

            err_msg = f"{str(exc)}\n\n{traceback.format_exc()}"
            self.pipeline_error_signal.emit(err_msg)


# ─────────────────────────────────────────────────────────────────────────────
# Investigation Progress: Vertical Timeline Stepper
# ─────────────────────────────────────────────────────────────────────────────


class VerticalPipelineStepper(QFrame):
    """
    Vertical investigation timeline tracker displaying execution state
    across all 7 LangGraph stages without horizontal crowding.
    """

    STAGES_METADATA = [
        ("intake_safety", "Intake & Safety", "Integrity, magic bytes & sandbox limits"),
        ("feature_extraction", "Feature Extraction", "Format-specific structural telemetry"),
        ("ml_ensemble", "ML Consensus", "5-model voting consensus"),
        ("explainability", "Explainability", "Z-score normalized risk drivers"),
        ("deep_threat_analysis", "Deep Forensics", "Static payload & macro inspection"),
        ("mitre_mapping", "MITRE & SOAR", "Technique mapping & response actions"),
        ("soc_report", "SOC Report", "Incident report markdown synthesis"),
    ]

    def __init__(self):
        super().__init__()
        self.setProperty("class", "panel-card")
        self.setObjectName("verticalStepper")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        # Header
        hdr_layout = QHBoxLayout()
        lbl_title = QLabel("INVESTIGATION PIPELINE")
        lbl_title.setProperty("class", "section-header")
        self.lbl_status = QLabel("Idle")
        self.lbl_status.setStyleSheet("color: #64748B; font-size: 11px;")
        hdr_layout.addWidget(lbl_title)
        hdr_layout.addStretch()
        hdr_layout.addWidget(self.lbl_status)
        layout.addLayout(hdr_layout)

        # Timeline rows
        self.row_widgets: Dict[str, Dict[str, QLabel]] = {}

        for node_id, stage_name, stage_desc in self.STAGES_METADATA:
            row_frame = QFrame()
            row_frame.setStyleSheet("background: transparent; border: none;")
            row_layout = QHBoxLayout(row_frame)
            row_layout.setContentsMargins(0, 3, 0, 3)
            row_layout.setSpacing(8)

            lbl_glyph = QLabel("[ ]")
            lbl_glyph.setStyleSheet(
                "font-family: monospace; font-size: 11px; font-weight: bold; color: #475569;"
            )
            lbl_glyph.setFixedWidth(24)

            text_box = QVBoxLayout()
            text_box.setSpacing(1)
            lbl_name = QLabel(stage_name)
            lbl_name.setStyleSheet("font-size: 12px; font-weight: 600; color: #94A3B8;")
            lbl_sub = QLabel(stage_desc)
            lbl_sub.setStyleSheet("font-size: 10px; color: #475569;")
            text_box.addWidget(lbl_name)
            text_box.addWidget(lbl_sub)

            row_layout.addWidget(lbl_glyph)
            row_layout.addLayout(text_box, 1)

            layout.addWidget(row_frame)
            self.row_widgets[node_id] = {
                "glyph": lbl_glyph,
                "name": lbl_name,
                "sub": lbl_sub,
            }

        layout.addStretch()

    def reset_timeline(self):
        self.lbl_status.setText("Awaiting document...")
        for node_id, _, stage_desc in self.STAGES_METADATA:
            r = self.row_widgets[node_id]
            r["glyph"].setText("[ ]")
            r["glyph"].setStyleSheet(
                "font-family: monospace; font-size: 11px; font-weight: bold; color: #475569;"
            )
            r["name"].setStyleSheet("font-size: 12px; font-weight: 600; color: #94A3B8;")
            r["sub"].setText(stage_desc)
            r["sub"].setStyleSheet("font-size: 10px; color: #475569;")

    def set_running(self, node_name: str):
        self.lbl_status.setText(f"Active: {node_name}")
        if node_name in self.row_widgets:
            r = self.row_widgets[node_name]
            r["glyph"].setText("[>]")
            r["glyph"].setStyleSheet(
                "font-family: monospace; font-size: 11px; font-weight: bold; color: #38BDF8;"
            )
            r["name"].setStyleSheet("font-size: 12px; font-weight: 700; color: #38BDF8;")
            r["sub"].setStyleSheet("font-size: 10px; color: #7DD3FC;")

    def set_completed(self, node_name: str, output: dict):
        if node_name not in self.row_widgets:
            return

        r = self.row_widgets[node_name]
        r["glyph"].setText("[v]")
        r["glyph"].setStyleSheet(
            "font-family: monospace; font-size: 11px; font-weight: bold; color: #10B981;"
        )
        r["name"].setStyleSheet("font-size: 12px; font-weight: 600; color: #F1F5F9;")

        if node_name == "intake_safety":
            fmt = output.get("format_display", "Verified")
            rule = output.get("applied_rule") or f"Rule 1: Format signature, container integrity, and size limits verified for {fmt}."
            r["sub"].setText(f"Verified {fmt} • Rule: Sandbox Integrity Passed")
            r["sub"].setToolTip(rule)
            r["name"].setToolTip(rule)
            r["sub"].setStyleSheet("font-size: 10px; color: #10B981;")

        elif node_name == "feature_extraction":
            n = len(output.get("raw_features", {}))
            rule = output.get("applied_rule") or f"Rule 2: Computed {n} structural, linguistic, and behavioral telemetry vectors."
            r["sub"].setText(f"Extracted {n} vectors • Rule: Static Telemetry")
            r["sub"].setToolTip(rule)
            r["name"].setToolTip(rule)
            r["sub"].setStyleSheet("font-size: 10px; color: #10B981;")

        elif node_name == "ml_ensemble":
            verdict = output.get("ensemble_verdict", "N/A")
            conf = output.get("confidence_score", 0.0)
            is_borderline = output.get("is_borderline", False)
            reasons = output.get("borderline_reasons", [])
            rule = output.get("applied_rule")
            if is_borderline:
                r["glyph"].setText("[!]")
                r["glyph"].setStyleSheet(
                    "font-family: monospace; font-size: 11px; font-weight: bold; color: #F59E0B;"
                )
                r["sub"].setText(f"{verdict} ({conf:.1%}) • Rule: Borderline Escalated")
                tip = f"Rule 3: Borderline criteria triggered -> Escalate to Deep Forensics.\nReasons:\n" + "\n".join(f"- {re}" for re in reasons)
                r["sub"].setToolTip(tip)
                r["name"].setToolTip(tip)
                r["sub"].setStyleSheet("font-size: 10px; color: #F59E0B;")
            else:
                r["sub"].setText(f"{verdict} ({conf:.1%}) • Rule: Unanimous Consensus")
                tip = rule or f"Rule 3: Unanimous multi-model agreement across all architectures ({conf:.1%} confidence)."
                r["sub"].setToolTip(tip)
                r["name"].setToolTip(tip)
                r["sub"].setStyleSheet("font-size: 10px; color: #10B981;")

        elif node_name == "explainability":
            n_d = len(output.get("top_risk_drivers", []))
            rule = output.get("applied_rule") or f"Rule 4: Ranked top {n_d} decision drivers using normalized z-score deviations."
            r["sub"].setText(f"Ranked {n_d} drivers • Rule: XAI Attribution")
            r["sub"].setToolTip(rule)
            r["name"].setToolTip(rule)
            r["sub"].setStyleSheet("font-size: 10px; color: #10B981;")

        elif node_name == "deep_threat_analysis":
            deep = output.get("deep_analysis", {})
            adj = deep.get("verdict_adjustment", "NONE")
            if adj == "DOWNGRADE_TO_BENIGN":
                r["glyph"].setText("[!]")
                r["glyph"].setStyleSheet(
                    "font-family: monospace; font-size: 11px; font-weight: bold; color: #F59E0B;"
                )
                r["sub"].setText("Calibrated • Rule: False-Positive Screened")
                tip = deep.get("rationale") or "Rule 5A: Verified 0 macros, 0 OLE, 0 DDE, and 0 remote templates. Calibrated to safe."
                r["sub"].setToolTip(tip)
                r["name"].setToolTip(tip)
                r["sub"].setStyleSheet("font-size: 10px; color: #F59E0B;")
            elif adj == "UPGRADE_TO_MALICIOUS":
                r["glyph"].setText("[!]")
                r["glyph"].setStyleSheet(
                    "font-family: monospace; font-size: 11px; font-weight: bold; color: #EF4444;"
                )
                r["sub"].setText("Overridden • Rule: Forensic Payload Detected")
                tip = deep.get("rationale") or f"Rule 5B: Discovered active execution indicators: {', '.join(deep.get('indicators', []))}."
                r["sub"].setToolTip(tip)
                r["name"].setToolTip(tip)
                r["sub"].setStyleSheet("font-size: 10px; color: #EF4444;")
            elif adj == "ESCALATE_TO_SUSPICIOUS":
                r["glyph"].setText("[!]")
                r["glyph"].setStyleSheet(
                    "font-family: monospace; font-size: 11px; font-weight: bold; color: #F97316;"
                )
                r["sub"].setText("Policy Violation • Rule: AUP Enforcement")
                tip = deep.get("rationale") or "Rule 5D: High-risk gambling/casino operations & mirror domain detected."
                r["sub"].setToolTip(tip)
                r["name"].setToolTip(tip)
                r["sub"].setStyleSheet("font-size: 10px; color: #F97316;")
            else:
                n_ind = len(deep.get("indicators", []))
                r["sub"].setText(f"{n_ind} findings • Rule: Deep Static Verification")
                tip = output.get("applied_rule") or f"Rule 5C: Verified {n_ind} static inspection indicators."
                r["sub"].setToolTip(tip)
                r["name"].setToolTip(tip)
                r["sub"].setStyleSheet("font-size: 10px; color: #10B981;")

        elif node_name == "mitre_mapping":
            n_m = len(output.get("mitre_tactics", []))
            rule = output.get("applied_rule") or f"Rule 6: Mapped {n_m} MITRE techniques & generated prescriptive SOAR playbooks."
            r["sub"].setText(f"{n_m} techniques • Rule: ATT&CK & SOAR")
            r["sub"].setToolTip(rule)
            r["name"].setToolTip(rule)
            r["sub"].setStyleSheet("font-size: 10px; color: #10B981;")

        elif node_name == "soc_report":
            rule = output.get("applied_rule") or "Rule 7: Executive incident report synthesized with MITRE mappings and playbooks."
            r["sub"].setText("Generated dossier • Rule: IR Synthesis")
            r["sub"].setToolTip(rule)
            r["name"].setToolTip(rule)
            r["sub"].setStyleSheet("font-size: 10px; color: #10B981;")

    def set_skipped(self, node_name: str, reason: str = "Bypassed (Clear Verdict)"):
        if node_name in self.row_widgets:
            r = self.row_widgets[node_name]
            r["glyph"].setText("[o]")
            r["glyph"].setStyleSheet(
                "font-family: monospace; font-size: 11px; font-weight: bold; color: #475569;"
            )
            r["name"].setStyleSheet("font-size: 12px; font-weight: 500; color: #475569;")
            r["sub"].setText("Bypassed • Rule: Fast-Track (Clear Consensus)")
            tip = "Rule: High-confidence unanimous consensus achieved; deep forensics bypassed."
            r["sub"].setToolTip(tip)
            r["name"].setToolTip(tip)
            r["sub"].setStyleSheet("font-size: 10px; color: #475569;")


# ─────────────────────────────────────────────────────────────────────────────
# Executive Verdict & Recommended Action Banner
# ─────────────────────────────────────────────────────────────────────────────


class ExecutiveVerdictBanner(QFrame):
    """
    High-visibility executive verdict header answering the core questions:
    'Is this document suspicious?', 'Why?', and 'What should I do next?'
    """

    def __init__(self):
        super().__init__()
        self.setProperty("class", "verdict-banner-neutral")
        self.setObjectName("verdictBanner")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(20)

        # 1. Final Classification
        v_col = QVBoxLayout()
        v_col.setSpacing(2)
        lbl_v_hdr = QLabel("TRIAGE CLASSIFICATION")
        lbl_v_hdr.setStyleSheet("font-size: 10px; font-weight: 700; color: #94A3B8; letter-spacing: 0.5px;")
        self.lbl_verdict = QLabel("READY TO SCAN")
        self.lbl_verdict.setStyleSheet("font-size: 20px; font-weight: 800; color: #38BDF8;")
        v_col.addWidget(lbl_v_hdr)
        v_col.addWidget(self.lbl_verdict)
        layout.addLayout(v_col, 2)

        # 2. Threat Level & Source
        s_col = QVBoxLayout()
        s_col.setSpacing(2)
        lbl_s_hdr = QLabel("SEVERITY & ORIGIN")
        lbl_s_hdr.setStyleSheet("font-size: 10px; font-weight: 700; color: #94A3B8; letter-spacing: 0.5px;")
        self.lbl_severity = QLabel("UNRANKED")
        self.lbl_severity.setStyleSheet("font-size: 14px; font-weight: 700; color: #E2E8F0;")
        self.lbl_origin = QLabel("Standard inspection")
        self.lbl_origin.setStyleSheet("font-size: 11px; color: #64748B;")
        s_col.addWidget(lbl_s_hdr)
        s_col.addWidget(self.lbl_severity)
        s_col.addWidget(self.lbl_origin)
        layout.addLayout(s_col, 2)

        # 3. Consensus Confidence Gauge
        c_col = QVBoxLayout()
        c_col.setSpacing(2)
        lbl_c_hdr = QLabel("CONSENSUS CONFIDENCE")
        lbl_c_hdr.setStyleSheet("font-size: 10px; font-weight: 700; color: #94A3B8; letter-spacing: 0.5px;")
        self.lbl_confidence = QLabel("0.0%")
        self.lbl_confidence.setStyleSheet("font-size: 18px; font-weight: 700; color: #F1F5F9;")
        self.bar_conf = QProgressBar()
        self.bar_conf.setRange(0, 100)
        self.bar_conf.setValue(0)
        self.bar_conf.setFixedHeight(6)
        self.bar_conf.setTextVisible(False)
        self.bar_conf.setStyleSheet("""
            QProgressBar { background: #1E293B; border-radius: 3px; }
            QProgressBar::chunk { background: #38BDF8; border-radius: 3px; }
        """)
        c_col.addWidget(lbl_c_hdr)
        c_col.addWidget(self.lbl_confidence)
        c_col.addWidget(self.bar_conf)
        layout.addLayout(c_col, 2)

        # 4. Prescriptive Next Action Box
        a_col = QVBoxLayout()
        a_col.setSpacing(2)
        lbl_a_hdr = QLabel("RECOMMENDED OPERATOR ACTION")
        lbl_a_hdr.setStyleSheet("font-size: 10px; font-weight: 700; color: #38BDF8; letter-spacing: 0.5px;")
        self.lbl_action = QLabel("Select or drop a target document to begin analysis.")
        self.lbl_action.setWordWrap(True)
        self.lbl_action.setStyleSheet("font-size: 11px; color: #CBD5E1; line-height: 1.3;")
        a_col.addWidget(lbl_a_hdr)
        a_col.addWidget(self.lbl_action)
        layout.addLayout(a_col, 4)

    def set_neutral(self, message: str = "Select or drop a target document to begin analysis."):
        self.setProperty("class", "verdict-banner-neutral")
        self.lbl_verdict.setText("READY TO SCAN")
        self.lbl_verdict.setStyleSheet("font-size: 20px; font-weight: 800; color: #38BDF8;")
        self.lbl_severity.setText("UNRANKED")
        self.lbl_severity.setStyleSheet("font-size: 14px; font-weight: 700; color: #E2E8F0;")
        self.lbl_origin.setText("Standard inspection")
        self.lbl_confidence.setText("0.0%")
        self.bar_conf.setValue(0)
        self.lbl_action.setText(message)
        self.style().polish(self)

    def set_analyzing(self):
        self.setProperty("class", "verdict-banner-neutral")
        self.lbl_verdict.setText("ANALYZING...")
        self.lbl_verdict.setStyleSheet("font-size: 20px; font-weight: 800; color: #38BDF8;")
        self.lbl_severity.setText("IN PROGRESS")
        self.lbl_origin.setText("Evaluating 5-model consensus & telemetry")
        self.lbl_confidence.setText("50.0%")
        self.bar_conf.setValue(50)
        self.lbl_action.setText("Investigation pipeline active. Streaming intermediate findings...")
        self.style().polish(self)

    def update_findings(
        self,
        verdict: str,
        threat: str,
        confidence: float,
        origin: str,
        prescribed_action: str,
    ):
        self.lbl_verdict.setText(verdict.upper())
        self.lbl_severity.setText(threat.upper())
        self.lbl_origin.setText(origin)
        self.lbl_confidence.setText(f"{confidence:.1%}")
        self.bar_conf.setValue(int(confidence * 100))
        self.lbl_action.setText(prescribed_action)

        if "MALICIOUS" in verdict:
            self.setProperty("class", "verdict-banner-malicious")
            self.lbl_verdict.setStyleSheet("font-size: 20px; font-weight: 800; color: #EF4444;")
            self.lbl_severity.setStyleSheet("font-size: 14px; font-weight: 700; color: #EF4444;")
            self.bar_conf.setStyleSheet("""
                QProgressBar { background: #261217; border-radius: 3px; }
                QProgressBar::chunk { background: #EF4444; border-radius: 3px; }
            """)
        elif "SUSPICIOUS" in verdict:
            self.setProperty("class", "verdict-banner-suspicious")
            self.lbl_verdict.setStyleSheet("font-size: 18px; font-weight: 800; color: #F97316;")
            self.lbl_severity.setStyleSheet("font-size: 14px; font-weight: 700; color: #F97316;")
            self.bar_conf.setStyleSheet("""
                QProgressBar { background: #2E1A0E; border-radius: 3px; }
                QProgressBar::chunk { background: #F97316; border-radius: 3px; }
            """)
        elif "BENIGN" in verdict:
            if "Screened" in verdict:
                self.setProperty("class", "verdict-banner-suspicious")
                self.lbl_verdict.setStyleSheet("font-size: 18px; font-weight: 800; color: #F59E0B;")
                self.lbl_severity.setStyleSheet("font-size: 14px; font-weight: 700; color: #F59E0B;")
                self.bar_conf.setStyleSheet("""
                    QProgressBar { background: #261E0E; border-radius: 3px; }
                    QProgressBar::chunk { background: #F59E0B; border-radius: 3px; }
                """)
            else:
                self.setProperty("class", "verdict-banner-benign")
                self.lbl_verdict.setStyleSheet("font-size: 20px; font-weight: 800; color: #10B981;")
                self.lbl_severity.setStyleSheet("font-size: 14px; font-weight: 700; color: #10B981;")
                self.bar_conf.setStyleSheet("""
                    QProgressBar { background: #0E2922; border-radius: 3px; }
                    QProgressBar::chunk { background: #10B981; border-radius: 3px; }
                """)
        else:
            self.setProperty("class", "verdict-banner-neutral")
            self.lbl_verdict.setStyleSheet("font-size: 20px; font-weight: 800; color: #38BDF8;")

        self.style().polish(self)


# ─────────────────────────────────────────────────────────────────────────────
# Compact Document Workbench / Drop Target
# ─────────────────────────────────────────────────────────────────────────────


class DocumentWorkbenchCard(QFrame):
    """
    Compact document ingestion card that transitions smoothly between
    drag-and-drop target and file metadata inspector.
    """

    file_selected_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.setProperty("class", "panel-card")
        self.setAcceptDrops(True)
        self.current_path: Optional[Path] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        hdr_row = QHBoxLayout()
        lbl_title = QLabel("TARGET DOCUMENT")
        lbl_title.setProperty("class", "section-header")
        self.btn_copy_hash = QPushButton("Copy Hash")
        self.btn_copy_hash.setProperty("class", "btn-subtle")
        self.btn_copy_hash.clicked.connect(self.copy_hash_to_clipboard)
        self.btn_copy_hash.setEnabled(False)

        hdr_row.addWidget(lbl_title)
        hdr_row.addStretch()
        hdr_row.addWidget(self.btn_copy_hash)
        layout.addLayout(hdr_row)

        # File primary name
        self.lbl_filename = QLabel("No document staged")
        self.lbl_filename.setStyleSheet("font-size: 13px; font-weight: 700; color: #F8FAFC;")
        layout.addWidget(self.lbl_filename)

        # Metadata line
        self.lbl_meta = QLabel("Drag & drop document or select from sample catalog above")
        self.lbl_meta.setStyleSheet("font-size: 11px; color: #94A3B8;")
        layout.addWidget(self.lbl_meta)

        # SHA-256 line
        self.lbl_hash = QLabel("SHA-256: —")
        self.lbl_hash.setProperty("class", "mono-label")
        layout.addWidget(self.lbl_hash)

        # Format tag
        self.lbl_format_tag = QLabel("Supported: HTML, PDF, Word, Excel, CSV")
        self.lbl_format_tag.setStyleSheet("font-size: 10px; color: #475569;")
        layout.addWidget(self.lbl_format_tag)

    def set_file(self, file_path: str):
        path = Path(file_path).resolve()
        if not path.is_file():
            return

        self.current_path = path
        size_kb = path.stat().st_size / 1024
        self.lbl_filename.setText(path.name)
        self.lbl_meta.setText(f"Size: {size_kb:.1f} KB | Folder: {path.parent.name}")
        self.lbl_hash.setText(f"File: {str(path)}")
        self.lbl_format_tag.setText(f"Extension: {path.suffix.upper()} | Ready for autonomous inspection")
        self.btn_copy_hash.setEnabled(True)

    def set_computed_hash(self, sha256: str, fmt_display: str, size_bytes: int):
        self.lbl_hash.setText(f"SHA-256: {sha256}")
        self.lbl_meta.setText(f"Format: {fmt_display} | Size: {size_bytes:,} bytes")
        self.btn_copy_hash.setEnabled(True)

    def copy_hash_to_clipboard(self):
        text = self.lbl_hash.text()
        if "SHA-256: " in text:
            hash_val = text.replace("SHA-256: ", "").strip()
            QApplication.clipboard().setText(hash_val)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setStyleSheet(
                "QFrame#docCard { background-color: #0E223D; border: 1px dashed #38BDF8; }"
            )

    def dragLeaveEvent(self, event):
        self.setStyleSheet("")

    def dropEvent(self, event: QDropEvent):
        self.setStyleSheet("")
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if os.path.isfile(path):
                self.file_selected_signal.emit(path)


# ─────────────────────────────────────────────────────────────────────────────
# Investigation Workspace Tabs
# ─────────────────────────────────────────────────────────────────────────────


class OverviewTab(QWidget):
    """Executive overview tab summarizing verdicts, model consensus, key drivers, and next actions."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        # KPI Stats Row
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(10)

        self.kpi_consensus = self.create_kpi_card("MODEL AGREEMENT", "—", "Across 5 architectures")
        self.kpi_threat = self.create_kpi_card("THREAT LEVEL", "—", "MITRE severity rank")
        self.kpi_drivers = self.create_kpi_card("RISK DRIVERS", "—", "Significant feature impacts")
        self.kpi_iocs = self.create_kpi_card("IOC ARTIFACTS", "—", "Extracted indicators")

        kpi_row.addWidget(self.kpi_consensus)
        kpi_row.addWidget(self.kpi_threat)
        kpi_row.addWidget(self.kpi_drivers)
        kpi_row.addWidget(self.kpi_iocs)
        layout.addLayout(kpi_row)

        # Narrative Summary Box
        self.card_narrative = QFrame()
        self.card_narrative.setProperty("class", "panel-card-inset")
        nar_layout = QVBoxLayout(self.card_narrative)
        nar_layout.setContentsMargins(14, 10, 14, 10)
        nar_layout.setSpacing(4)

        lbl_nar_hdr = QLabel("TRIAGE RATIONALE & AUTONOMOUS FINDINGS")
        lbl_nar_hdr.setProperty("class", "section-header")
        self.lbl_nar_body = QLabel("Awaiting document analysis to generate findings summary.")
        self.lbl_nar_body.setWordWrap(True)
        self.lbl_nar_body.setStyleSheet("font-size: 12px; color: #CBD5E1; line-height: 1.4;")
        nar_layout.addWidget(lbl_nar_hdr)
        nar_layout.addWidget(self.lbl_nar_body)
        layout.addWidget(self.card_narrative)

        # Top 3 Decision Drivers summary table
        lbl_top_hdr = QLabel("CRITICAL DECISION DRIVERS (TOP 3 ATTRIBUTIONS)")
        lbl_top_hdr.setProperty("class", "section-header")
        layout.addWidget(lbl_top_hdr)

        self.tbl_top_drivers = QTableWidget()
        self.tbl_top_drivers.setColumnCount(5)
        self.tbl_top_drivers.setHorizontalHeaderLabels([
            "Feature",
            "Security Context",
            "Observed Value",
            "Impact Direction",
            "Attribution Weight",
        ])
        self.tbl_top_drivers.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_top_drivers.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tbl_top_drivers.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tbl_top_drivers.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tbl_top_drivers.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.tbl_top_drivers.setFixedHeight(120)
        self.tbl_top_drivers.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.tbl_top_drivers)

        # Immediate Next Action
        self.card_action = QFrame()
        self.card_action.setProperty("class", "panel-card-inset")
        act_layout = QVBoxLayout(self.card_action)
        act_layout.setContentsMargins(14, 10, 14, 10)
        act_layout.setSpacing(4)

        lbl_act_hdr = QLabel("PRESCRIBED INCIDENT RESPONSE ACTION")
        lbl_act_hdr.setProperty("class", "section-header")
        self.lbl_act_body = QLabel("No active playbook actions prescribed yet.")
        self.lbl_act_body.setWordWrap(True)
        self.lbl_act_body.setStyleSheet("font-size: 12px; color: #CBD5E1; font-weight: 600;")
        act_layout.addWidget(lbl_act_hdr)
        act_layout.addWidget(self.lbl_act_body)
        layout.addWidget(self.card_action)

        layout.addStretch()

    def create_kpi_card(self, title: str, value: str, sub: str) -> QFrame:
        card = QFrame()
        card.setProperty("class", "panel-card-inset")
        card.setFixedHeight(68)
        c_lay = QVBoxLayout(card)
        c_lay.setContentsMargins(10, 8, 10, 8)
        c_lay.setSpacing(1)

        lbl_t = QLabel(title)
        lbl_t.setStyleSheet("font-size: 10px; font-weight: 700; color: #94A3B8; letter-spacing: 0.5px;")
        lbl_v = QLabel(value)
        lbl_v.setStyleSheet("font-size: 16px; font-weight: 800; color: #F8FAFC;")
        lbl_s = QLabel(sub)
        lbl_s.setStyleSheet("font-size: 9px; color: #64748B;")

        c_lay.addWidget(lbl_t)
        c_lay.addWidget(lbl_v)
        c_lay.addWidget(lbl_s)
        card.lbl_val = lbl_v  # type: ignore
        return card

    def update_overview(self, state: dict):
        preds = state.get("model_predictions", [])
        votes = state.get("vote_counts", {})
        mal_v = votes.get("malicious", 0)
        tot_v = len(preds) or 5
        self.kpi_consensus.lbl_val.setText(f"{mal_v}/{tot_v} Malicious")  # type: ignore

        threat = state.get("threat_level", "UNRANKED")
        self.kpi_threat.lbl_val.setText(threat.upper())  # type: ignore

        drivers = state.get("top_risk_drivers", [])
        self.kpi_drivers.lbl_val.setText(f"{len(drivers)} Active")  # type: ignore

        iocs = state.get("indicators_of_compromise", [])
        self.kpi_iocs.lbl_val.setText(f"{len(iocs)} Extracted")  # type: ignore

        deep = state.get("deep_analysis", {})
        rationale = deep.get("rationale") or state.get("executive_summary") or "Triage complete."
        self.lbl_nar_body.setText(rationale)

        # Top 3 drivers
        self.tbl_top_drivers.setRowCount(min(3, len(drivers)))
        for row, d in enumerate(drivers[:3]):
            dir_str = "(+) Increases Risk" if d.get("direction") == "↑" else "(-) Reduces Risk"
            self.tbl_top_drivers.setItem(row, 0, QTableWidgetItem(d.get("feature", "")))
            self.tbl_top_drivers.setItem(row, 1, QTableWidgetItem(d.get("description", "")))
            self.tbl_top_drivers.setItem(row, 2, QTableWidgetItem(str(d.get("raw_value", ""))))

            it_dir = QTableWidgetItem(dir_str)
            it_dir.setForeground(QColor("#EF4444" if d.get("direction") == "↑" else "#10B981"))
            it_dir.setFont(QFont("Segoe UI", 9, QFont.Bold))
            self.tbl_top_drivers.setItem(row, 3, it_dir)

            it_imp = QTableWidgetItem(f"{d.get('impact', 0.0):+.4f}")
            it_imp.setFont(QFont("Consolas", 10))
            self.tbl_top_drivers.setItem(row, 4, it_imp)

        # Top playbook action
        playbook = state.get("soc_playbook_actions", [])
        if playbook:
            first_action = f"{playbook[0].get('stage', '')} ({playbook[0].get('tier', '')}): {playbook[0].get('action', '')}"
            self.lbl_act_body.setText(first_action)
        else:
            self.lbl_act_body.setText("Standard release. No escalation required.")


class ModelConsensusTab(QWidget):
    """5-Model consensus voting comparison table with probability meters."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        lbl_desc = QLabel(
            "Consensus voting evaluated across 5 standardized model architectures with 100% feature parity:"
        )
        lbl_desc.setStyleSheet("color: #94A3B8; font-size: 12px;")
        layout.addWidget(lbl_desc)

        self.tbl = QTableWidget()
        self.tbl.setColumnCount(4)
        self.tbl.setHorizontalHeaderLabels([
            "Model Architecture",
            "Classification",
            "Phishing Probability",
            "Status Indicator",
        ])
        self.tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.tbl)

        self.lbl_tally = QLabel("Tally: Awaiting execution")
        self.lbl_tally.setStyleSheet("color: #64748B; font-size: 11px;")
        layout.addWidget(self.lbl_tally)

    def update_table(self, predictions: List[Dict[str, Any]], votes: Dict[str, int]):
        self.tbl.setRowCount(len(predictions))
        for row, p in enumerate(predictions):
            m_name = p.get("model", "Unknown")
            is_mal = p.get("prediction", 0) == 1
            prob = p.get("probability", p.get("probability_malicious", 0.0))

            it_name = QTableWidgetItem(m_name)
            it_name.setFont(QFont("Segoe UI", 10, QFont.Bold))

            it_pred = QTableWidgetItem("MALICIOUS" if is_mal else "BENIGN")
            it_pred.setForeground(QColor("#EF4444" if is_mal else "#10B981"))
            it_pred.setFont(QFont("Segoe UI", 10, QFont.Bold))

            it_prob = QTableWidgetItem(f"{prob:.1%}")
            it_prob.setFont(QFont("Consolas", 10))

            it_status = QTableWidgetItem("FLAGGED" if is_mal else "CLEAN")
            it_status.setForeground(QColor("#EF4444" if is_mal else "#10B981"))

            self.tbl.setItem(row, 0, it_name)
            self.tbl.setItem(row, 1, it_pred)
            self.tbl.setItem(row, 2, it_prob)
            self.tbl.setItem(row, 3, it_status)

        mal_c = votes.get("malicious", 0)
        ben_c = votes.get("benign", 0)
        self.lbl_tally.setText(f"Ensemble Voting Consensus: {mal_c} Malicious vs {ben_c} Benign across {len(predictions)} models.")


class ExplainableAiTab(QWidget):
    """Explainable AI feature attribution table with normalized Z-scores."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        lbl_desc = QLabel(
            "Feature impact on classification derived from training deviations (z = (x - mu) / sigma):"
        )
        lbl_desc.setStyleSheet("color: #94A3B8; font-size: 12px;")
        layout.addWidget(lbl_desc)

        self.tbl = QTableWidget()
        self.tbl.setColumnCount(6)
        self.tbl.setHorizontalHeaderLabels([
            "Feature Name",
            "Security Operational Context",
            "Observed Value",
            "Z-Score",
            "Impact Direction",
            "Risk Weight",
        ])
        self.tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.tbl)

    def update_table(self, drivers: List[Dict[str, Any]]):
        self.tbl.setRowCount(len(drivers))
        for row, d in enumerate(drivers):
            feat = d.get("feature", "")
            desc = d.get("description", feat)
            raw = str(d.get("raw_value", ""))
            z = d.get("std_value", 0.0)
            imp = d.get("impact", 0.0)
            dir_str = "(+) Increases Risk" if d.get("direction") == "↑" else "(-) Reduces Risk"

            it_feat = QTableWidgetItem(feat)
            it_feat.setFont(QFont("Consolas", 10))

            it_desc = QTableWidgetItem(desc)
            it_raw = QTableWidgetItem(raw)
            it_raw.setFont(QFont("Consolas", 10))

            it_z = QTableWidgetItem(f"{z:+.2f}")
            it_z.setFont(QFont("Consolas", 10))

            it_dir = QTableWidgetItem(dir_str)
            it_dir.setForeground(QColor("#EF4444" if d.get("direction") == "↑" else "#10B981"))
            it_dir.setFont(QFont("Segoe UI", 9, QFont.Bold))

            it_imp = QTableWidgetItem(f"{imp:+.4f}")
            it_imp.setFont(QFont("Consolas", 10))

            self.tbl.setItem(row, 0, it_feat)
            self.tbl.setItem(row, 1, it_desc)
            self.tbl.setItem(row, 2, it_raw)
            self.tbl.setItem(row, 3, it_z)
            self.tbl.setItem(row, 4, it_dir)
            self.tbl.setItem(row, 5, it_imp)


class ForensicsAndIocTab(QWidget):
    """Digital Forensics findings and Indicators of Compromise (IOC) inspection."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Rationale card
        self.card_rat = QFrame()
        self.card_rat.setProperty("class", "panel-card-inset")
        r_lay = QVBoxLayout(self.card_rat)
        r_lay.setContentsMargins(12, 10, 12, 10)
        lbl_r_hdr = QLabel("STATIC PAYLOAD FINDINGS & AUTONOMOUS RATIONALE")
        lbl_r_hdr.setProperty("class", "section-header")
        self.lbl_rationale = QLabel("No forensic inspection conducted yet.")
        self.lbl_rationale.setWordWrap(True)
        self.lbl_rationale.setStyleSheet("font-size: 12px; color: #E2E8F0;")
        r_lay.addWidget(lbl_r_hdr)
        r_lay.addWidget(self.lbl_rationale)
        layout.addWidget(self.card_rat)

        # Discovered indicators list
        lbl_ind_hdr = QLabel("DISCOVERED STATIC INDICATORS")
        lbl_ind_hdr.setProperty("class", "section-header")
        layout.addWidget(lbl_ind_hdr)

        self.txt_indicators = QTextBrowser()
        self.txt_indicators.setFixedHeight(90)
        layout.addWidget(self.txt_indicators)

        # IOCs Table with copy buttons
        lbl_ioc_hdr = QLabel("EXTRACTED INDICATORS OF COMPROMISE (IOCs)")
        lbl_ioc_hdr.setProperty("class", "section-header")
        layout.addWidget(lbl_ioc_hdr)

        self.tbl_iocs = QTableWidget()
        self.tbl_iocs.setColumnCount(3)
        self.tbl_iocs.setHorizontalHeaderLabels([
            "Indicator Type",
            "Artifact Value",
            "Action",
        ])
        self.tbl_iocs.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_iocs.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tbl_iocs.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tbl_iocs.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.tbl_iocs)

    def update_forensics(self, output: dict):
        deep = output.get("deep_analysis", {})
        rat = deep.get("rationale") or "Standard forensic inspection verified."
        self.lbl_rationale.setText(rat)

        indicators = deep.get("indicators", [])
        self.txt_indicators.setPlainText(
            "\n".join(f"- {ind}" for ind in indicators) or "No suspicious execution payload vectors identified."
        )

        iocs = output.get("indicators_of_compromise", [])
        self.tbl_iocs.setRowCount(len(iocs))
        for row, ioc in enumerate(iocs):
            val = ioc.get("value", "")
            self.tbl_iocs.setItem(row, 0, QTableWidgetItem(ioc.get("type", "")))
            it_val = QTableWidgetItem(val)
            it_val.setFont(QFont("Consolas", 10))
            self.tbl_iocs.setItem(row, 1, it_val)

            btn_copy = QPushButton("Copy")
            btn_copy.setProperty("class", "btn-subtle")
            btn_copy.clicked.connect(lambda _, text=val: QApplication.clipboard().setText(text))
            self.tbl_iocs.setCellWidget(row, 2, btn_copy)


class MitreAndSoarTab(QWidget):
    """Mapped MITRE ATT&CK techniques and 4-tier prescriptive SOAR playbooks."""

    def __init__(self):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        # Left Column: MITRE ATT&CK
        left_col = QVBoxLayout()
        lbl_m_hdr = QLabel("MITRE ATT&CK TECHNIQUE MAPPINGS")
        lbl_m_hdr.setProperty("class", "section-header")
        left_col.addWidget(lbl_m_hdr)

        self.tbl_mitre = QTableWidget()
        self.tbl_mitre.setColumnCount(3)
        self.tbl_mitre.setHorizontalHeaderLabels(["Technique ID", "Tactic", "Technique Name"])
        self.tbl_mitre.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_mitre.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tbl_mitre.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tbl_mitre.setEditTriggers(QAbstractItemView.NoEditTriggers)
        left_col.addWidget(self.tbl_mitre)
        layout.addLayout(left_col, 3)

        # Right Column: SOAR Playbooks
        right_col = QVBoxLayout()
        lbl_s_hdr = QLabel("PRESCRIPTIVE SOAR REMEDIATION PLAYBOOK")
        lbl_s_hdr.setProperty("class", "section-header")
        right_col.addWidget(lbl_s_hdr)

        self.tbl_soar = QTableWidget()
        self.tbl_soar.setColumnCount(2)
        self.tbl_soar.setHorizontalHeaderLabels(["Stage / Tier", "Prescribed Mitigation Action"])
        self.tbl_soar.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tbl_soar.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tbl_soar.setEditTriggers(QAbstractItemView.NoEditTriggers)
        right_col.addWidget(self.tbl_soar)

        lbl_disclaimer = QLabel(
            "Note: Prescribed remediation playbooks require manual SOC authorization before execution."
        )
        lbl_disclaimer.setStyleSheet("font-size: 10px; color: #64748B; font-style: italic;")
        right_col.addWidget(lbl_disclaimer)
        layout.addLayout(right_col, 4)

    def update_mitre_and_soar(self, output: dict):
        mitre = output.get("mitre_tactics", [])
        self.tbl_mitre.setRowCount(len(mitre))
        for row, m in enumerate(mitre):
            it_id = QTableWidgetItem(m.get("id", ""))
            it_id.setFont(QFont("Consolas", 10, QFont.Bold))
            self.tbl_mitre.setItem(row, 0, it_id)
            self.tbl_mitre.setItem(row, 1, QTableWidgetItem(m.get("tactic", "")))
            self.tbl_mitre.setItem(row, 2, QTableWidgetItem(m.get("technique", "")))

        playbook = output.get("soc_playbook_actions", [])
        self.tbl_soar.setRowCount(len(playbook))
        for row, a in enumerate(playbook):
            tier = f"{a.get('stage', '')} // {a.get('tier', '')}"
            it_tier = QTableWidgetItem(tier)
            it_tier.setFont(QFont("Segoe UI", 9, QFont.Bold))
            self.tbl_soar.setItem(row, 0, it_tier)
            self.tbl_soar.setItem(row, 1, QTableWidgetItem(a.get("action", "")))


class IncidentReportTab(QWidget):
    """Complete Markdown incident response report viewer and exporter."""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)

        btn_bar = QHBoxLayout()
        self.btn_copy = QPushButton("Copy Markdown")
        self.btn_copy.setProperty("class", "btn-secondary")
        self.btn_copy.clicked.connect(self.copy_to_clipboard)

        self.btn_open_file = QPushButton("Open Report File")
        self.btn_open_file.setProperty("class", "btn-secondary")
        self.btn_open_file.clicked.connect(self.open_report_file)
        self.btn_open_file.setEnabled(False)

        self.lbl_path = QLabel("")
        self.lbl_path.setProperty("class", "mono-label")

        btn_bar.addWidget(self.btn_copy)
        btn_bar.addWidget(self.btn_open_file)
        btn_bar.addSpacing(12)
        btn_bar.addWidget(self.lbl_path)
        btn_bar.addStretch()
        layout.addLayout(btn_bar)

        self.txt_browser = QTextBrowser()
        layout.addWidget(self.txt_browser)
        self.saved_path: Optional[str] = None

    def set_report(self, markdown_text: str, saved_path: Optional[str]):
        self.txt_browser.setPlainText(markdown_text)
        self.saved_path = saved_path
        if saved_path and os.path.isfile(saved_path):
            self.lbl_path.setText(f"Saved: {Path(saved_path).name}")
            self.btn_open_file.setEnabled(True)
        else:
            self.lbl_path.setText("")
            self.btn_open_file.setEnabled(False)

    def copy_to_clipboard(self):
        content = self.txt_browser.toPlainText()
        if content:
            QApplication.clipboard().setText(content)

    def open_report_file(self):
        if self.saved_path and os.path.isfile(self.saved_path):
            import subprocess

            if sys.platform == "win32":
                os.startfile(self.saved_path)
            else:
                subprocess.Popen(["xdg-open", self.saved_path])


# ─────────────────────────────────────────────────────────────────────────────
# Main Application Window: ExplainPhish Console
# ─────────────────────────────────────────────────────────────────────────────


class ExplainPhishDesktopApp(QMainWindow):
    """
    Main application window for ExplainPhish Enterprise SOC Console.
    Orchestrates the 2-pane workbench, LangGraph execution, and investigation views.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("ExplainPhish // Autonomous SOC Incident Response Console")
        self.resize(1280, 860)
        self.setMinimumSize(1024, 700)

        self.current_file_path: Optional[str] = None
        self.active_state: Dict[str, Any] = {}
        self.worker: Optional[LangGraphWorker] = None

        self.init_ui()
        self.load_sample_catalog()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(16, 12, 16, 12)
        root_layout.setSpacing(10)

        # ── 1. Enterprise Top Application Header ──
        header = QHBoxLayout()
        header.setSpacing(12)

        # Brand & Slogan
        brand_box = QVBoxLayout()
        brand_box.setSpacing(1)
        lbl_brand = QLabel("EXPLAINPHISH // ENTERPRISE SOC WORKSTATION")
        lbl_brand.setProperty("class", "app-brand")
        lbl_sub = QLabel("Autonomous Phishing Analysis, Multi-Model Consensus & Incident Response")
        lbl_sub.setProperty("class", "app-subtitle")
        brand_box.addWidget(lbl_brand)
        brand_box.addWidget(lbl_sub)
        header.addLayout(brand_box)

        header.addStretch()

        # Sample Selector
        self.cmb_samples = QComboBox()
        self.cmb_samples.setFixedWidth(280)
        self.cmb_samples.currentIndexChanged.connect(self.on_sample_selected)
        header.addWidget(self.cmb_samples)

        # Browse Document Action
        self.btn_browse = QPushButton("Browse File...")
        self.btn_browse.setProperty("class", "btn-secondary")
        self.btn_browse.clicked.connect(self.on_browse_file)
        header.addWidget(self.btn_browse)

        # Analyze Document Action
        self.btn_analyze = QPushButton("Start Analysis")
        self.btn_analyze.setProperty("class", "btn-primary")
        self.btn_analyze.clicked.connect(self.start_pipeline)
        self.btn_analyze.setEnabled(False)
        header.addWidget(self.btn_analyze)

        root_layout.addLayout(header)

        # ── 2. Master-Detail Split Workspace (QSplitter) ──
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setChildrenCollapsible(False)

        # LEFT WORKBENCH: Target Document & Vertical Pipeline Timeline
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 6, 0)
        left_layout.setSpacing(10)

        # Staged Document Card
        self.doc_card = DocumentWorkbenchCard()
        self.doc_card.file_selected_signal.connect(self.set_active_file)
        left_layout.addWidget(self.doc_card)

        # Vertical Timeline Stepper
        self.stepper = VerticalPipelineStepper()
        left_layout.addWidget(self.stepper, 1)

        self.splitter.addWidget(left_panel)

        # RIGHT WORKBENCH: Executive Verdict Banner & Evidence Tabs
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(6, 0, 0, 0)
        right_layout.setSpacing(10)

        # Executive Verdict & Action Banner
        self.verdict_banner = ExecutiveVerdictBanner()
        right_layout.addWidget(self.verdict_banner)

        # Investigation Tabs Console
        self.tabs = QTabWidget()

        self.tab_overview = OverviewTab()
        self.tab_models = ModelConsensusTab()
        self.tab_xai = ExplainableAiTab()
        self.tab_forensics = ForensicsAndIocTab()
        self.tab_mitre = MitreAndSoarTab()
        self.tab_report = IncidentReportTab()

        self.tabs.addTab(self.tab_overview, "Overview")
        self.tabs.addTab(self.tab_models, "Model Consensus")
        self.tabs.addTab(self.tab_xai, "Explainable AI")
        self.tabs.addTab(self.tab_forensics, "Forensics & IOCs")
        self.tabs.addTab(self.tab_mitre, "MITRE & SOAR")
        self.tabs.addTab(self.tab_report, "Incident Report")

        right_layout.addWidget(self.tabs, 1)

        self.splitter.addWidget(right_panel)

        # Set default split proportions (340px left workbench, remaining for evidence tabs)
        self.splitter.setSizes([340, 940])
        root_layout.addWidget(self.splitter, 1)

    # ── Sample Discovery ─────────────────────────────────────────────────────

    def load_sample_catalog(self):
        self.cmb_samples.blockSignals(True)
        self.cmb_samples.clear()
        self.cmb_samples.addItem("Select sample test document...")

        samples_dir = _HERE / "Sample"
        if samples_dir.exists():
            for folder in sorted(samples_dir.iterdir()):
                if folder.is_dir():
                    files = sorted([f for f in folder.iterdir() if f.is_file()])
                    for file_p in files[:2]:
                        self.cmb_samples.addItem(f"[{folder.name}] {file_p.name}", str(file_p))

        downloads_dir = _HERE / "downloads"
        if downloads_dir.exists():
            dl_files = sorted([f for f in downloads_dir.iterdir() if f.is_file() and not f.name.startswith(".")])
            for file_p in dl_files:
                self.cmb_samples.addItem(f"[Web/Downloaded] {file_p.name}", str(file_p))

        self.cmb_samples.blockSignals(False)

    def on_sample_selected(self, index: int):
        if index <= 0:
            return
        path = self.cmb_samples.currentData()
        if path and os.path.isfile(path):
            self.set_active_file(path)

    def on_browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Suspicious Document for Investigation",
            str(_HERE),
            "Supported Documents (*.html *.htm *.pdf *.docx *.docm *.doc *.xlsx *.xlsm *.xls *.csv);;All Files (*.*)",
        )
        if file_path:
            self.set_active_file(file_path)

    def set_active_file(self, file_path: str):
        path = Path(file_path).resolve()
        if not path.is_file():
            return

        self.current_file_path = str(path)
        self.btn_analyze.setEnabled(True)

        self.doc_card.set_file(str(path))
        self.stepper.reset_timeline()
        self.verdict_banner.set_neutral(f"Document staged: {path.name}. Click 'Start Analysis' to execute.")

    # ── LangGraph Pipeline Execution ─────────────────────────────────────────

    def start_pipeline(self):
        if not self.current_file_path:
            return

        self.btn_analyze.setEnabled(False)
        self.btn_browse.setEnabled(False)
        self.cmb_samples.setEnabled(False)

        self.stepper.reset_timeline()
        self.verdict_banner.set_analyzing()

        # Clear tab components
        self.tab_models.tbl.setRowCount(0)
        self.tab_xai.tbl.setRowCount(0)
        self.tab_forensics.tbl_iocs.setRowCount(0)
        self.tab_forensics.txt_indicators.clear()
        self.tab_mitre.tbl_mitre.setRowCount(0)
        self.tab_mitre.tbl_soar.setRowCount(0)
        self.tab_report.txt_browser.clear()

        # Spawn worker thread
        self.worker = LangGraphWorker(self.current_file_path)
        self.worker.node_completed_signal.connect(self.on_node_completed)
        self.worker.pipeline_finished_signal.connect(self.on_pipeline_finished)
        self.worker.pipeline_error_signal.connect(self.on_pipeline_error)
        self.worker.start()

    def on_node_completed(self, node_name: str, node_output: dict):
        self.stepper.set_completed(node_name, node_output)

        if node_name == "intake_safety":
            sha = node_output.get("file_hash_sha256", "N/A")
            fmt = node_output.get("format_display", "Unknown")
            sz = node_output.get("file_size_bytes", 0)
            self.doc_card.set_computed_hash(sha, fmt, sz)

        elif node_name == "ml_ensemble":
            preds = node_output.get("model_predictions", [])
            votes = node_output.get("vote_counts", {})
            self.tab_models.update_table(preds, votes)

            verdict = node_output.get("ensemble_verdict", "UNKNOWN")
            conf = node_output.get("confidence_score", 0.0)
            band = node_output.get("confidence_band", "MED")
            reasons = node_output.get("borderline_reasons", [])
            note = reasons[0] if reasons else "Unanimous multi-model consensus achieved."

            self.verdict_banner.update_findings(
                verdict,
                band,
                conf,
                "Ensemble Consensus",
                f"Preliminary classification complete: {note}",
            )

            if not node_output.get("is_borderline", False):
                self.stepper.set_skipped("deep_threat_analysis", "Bypassed (Clear Verdict)")

        elif node_name == "explainability":
            drivers = node_output.get("top_risk_drivers", [])
            self.tab_xai.update_table(drivers)

        elif node_name == "deep_threat_analysis":
            self.tab_forensics.update_forensics(node_output)

        elif node_name == "mitre_mapping":
            self.tab_mitre.update_mitre_and_soar(node_output)

        elif node_name == "soc_report":
            md = node_output.get("soc_report_markdown", "")
            path = node_output.get("report_saved_path")
            self.tab_report.set_report(md, path)

    def on_pipeline_finished(self, final_state: dict):
        self.active_state = final_state
        self.btn_analyze.setEnabled(True)
        self.btn_browse.setEnabled(True)
        self.cmb_samples.setEnabled(True)

        verdict = final_state.get("final_verdict") or final_state.get("ensemble_verdict", "UNKNOWN")
        threat = final_state.get("threat_level", "INFORMATIONAL")
        conf = final_state.get("confidence_score", 0.0)
        deep = final_state.get("deep_analysis", {})

        origin = "Forensic Override" if deep.get("verdict_adjustment", "NONE") != "NONE" else "Ensemble Consensus"

        # Determine top recommended action
        playbook = final_state.get("soc_playbook_actions", [])
        if playbook:
            action_text = f"Tier 1: {playbook[0].get('action', '')}"
        else:
            action_text = "Safe document. Release from sandbox."

        self.verdict_banner.update_findings(verdict, threat, conf, origin, action_text)
        self.tab_overview.update_overview(final_state)

    def on_pipeline_error(self, err_msg: str):
        self.btn_analyze.setEnabled(True)
        self.btn_browse.setEnabled(True)
        self.cmb_samples.setEnabled(True)
        self.verdict_banner.set_neutral("Pipeline aborted due to execution error.")
        QMessageBox.critical(self, "Pipeline Error", f"LangGraph execution halted:\n\n{err_msg}")


# ─────────────────────────────────────────────────────────────────────────────
# Application Entry Point
# ─────────────────────────────────────────────────────────────────────────────


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(SOC_ENTERPRISE_STYLESHEET)

    window = ExplainPhishDesktopApp()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
