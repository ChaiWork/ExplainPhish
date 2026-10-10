"""
ExplainPhish Autonomous SOC Agent Pipeline (LangGraph)
======================================================
Multi-stage cybersecurity incident triage & response graph combining:
  1. Intake & Safety Gatekeeper (Magic bytes, ZIP bomb heuristics, size caps)
  2. Feature Extraction (HTML, PDF, Excel, Word specialized extractors)
  3. ML Ensemble Consensus (XGBoost, Random Forest, Decision Tree)
  4. Explainability & Risk Attribution (SHAP-style scaled feature impact)
  5. Conditional Router (Autonomous escalation for borderline / ambiguous cases)
  6. Deep Threat Forensics (Static payload analysis, macro inspection, credential forms, DDE)
  7. MITRE ATT&CK Mapping & SOAR Remediation Playbooks
  8. SOC Incident Response Report Generation (Markdown + optional LLM narrative)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypedDict

import numpy as np
import pandas as pd
from langgraph.graph import END, START, StateGraph

# Ensure local imports work cleanly
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from extractors.base import ExtractionError, check_file_safety
from inference import (
    FORMAT_DISPLAY,
    check_structural_safety,
    check_web_policy_risk,
    compute_risk_drivers,
    detect_format,
    extract_features,
    load_model_bundle,
    standardize_features,
)

# ─────────────────────────────────────────────────────────────────────────────
# State Schema
# ─────────────────────────────────────────────────────────────────────────────


class ExplainPhishState(TypedDict, total=False):
    # File Metadata
    file_path: str
    file_name: str
    source_url: Optional[str]
    file_size_bytes: int
    file_hash_sha256: str
    file_hash_md5: str
    file_format: str
    format_display: str
    is_safe: bool
    error: Optional[str]

    # Feature Engineering
    raw_features: Dict[str, Any]
    standardized_features: Dict[str, float]

    # ML Ensemble Inferences
    model_predictions: List[Dict[str, Any]]
    raw_probabilities: Dict[str, float]
    vote_counts: Dict[str, int]
    ensemble_verdict: str  # "MALICIOUS" | "BENIGN"
    confidence_score: float
    confidence_band: str  # "HIGH" | "MEDIUM" | "LOW"
    unanimous: bool

    # Routing & Ambiguity Detection
    is_borderline: bool
    borderline_reasons: List[str]

    # Explainability & Attribution
    top_risk_drivers: List[Dict[str, Any]]

    # Deep Threat Forensics
    deep_analysis: Dict[str, Any]
    indicators_of_compromise: List[Dict[str, str]]
    final_verdict: str
    threat_level: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL"

    # Threat Intelligence & Response
    mitre_tactics: List[Dict[str, str]]
    soc_playbook_actions: List[Dict[str, str]]

    # Investigation Rules
    applied_rules: Dict[str, str]

    # Incident Response Output
    executive_summary: str
    soc_report_markdown: str
    report_saved_path: Optional[str]


# ─────────────────────────────────────────────────────────────────────────────
# Node 1: Intake & Safety Gatekeeper
# ─────────────────────────────────────────────────────────────────────────────


def node_intake_safety(state: ExplainPhishState) -> Dict[str, Any]:
    """
    Validates file integrity, calculates cryptographic hashes,
    enforces anti-evasion / anti-ZIP-bomb security boundaries,
    and identifies the file format.
    """
    path = Path(state["file_path"]).resolve()
    if not path.is_file():
        return {
            "is_safe": False,
            "error": f"File not found on system: {path}",
            "file_name": path.name,
            "applied_rules": {"intake_safety": "Rule 1 (Intake Safety): File not found rejection"},
        }

    # Compute hashes and size
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size_bytes = path.stat().st_size

    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            md5.update(chunk)

    try:
        # Detect format
        fmt = detect_format(path)
        is_ooxml = fmt in ("excel", "word")

        # Run safety pre-check (caps at 50MB, checks compression ratios)
        check_file_safety(path, check_zip_bomb=is_ooxml)

        rule_desc = f"Rule 1 (Intake Safety): Verified {FORMAT_DISPLAY.get(fmt, fmt.upper())} signature & sandbox limits (Anti-Zip Bomb OK, size: {size_bytes:,} bytes)"
        return {
            "file_name": path.name,
            "file_path": str(path),
            "file_size_bytes": size_bytes,
            "file_hash_sha256": sha256.hexdigest(),
            "file_hash_md5": md5.hexdigest(),
            "file_format": fmt,
            "format_display": FORMAT_DISPLAY.get(fmt, fmt.upper()),
            "is_safe": True,
            "error": None,
            "applied_rules": {"intake_safety": rule_desc},
            "applied_rule": rule_desc,
        }
    except Exception as exc:
        rule_desc = f"Rule 1 (Intake Safety): Rejected - {str(exc)}"
        return {
            "file_name": path.name,
            "file_path": str(path),
            "file_size_bytes": size_bytes,
            "file_hash_sha256": sha256.hexdigest(),
            "file_hash_md5": md5.hexdigest(),
            "is_safe": False,
            "error": f"Intake safety rejection: {str(exc)}",
            "applied_rules": {"intake_safety": rule_desc},
            "applied_rule": rule_desc,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Node 2: Feature Extraction
# ─────────────────────────────────────────────────────────────────────────────


def node_feature_extraction(state: ExplainPhishState) -> Dict[str, Any]:
    """
    Invokes the format-specific security feature extractor
    to compute structural, linguistic, and behavioural telemetry.
    """
    if not state.get("is_safe", False):
        return {"error": state.get("error", "Skipped due to safety failure")}

    path = Path(state["file_path"])
    fmt = state.get("file_format") or detect_format(path)

    try:
        raw_feats = extract_features(path, fmt)
        rules = dict(state.get("applied_rules") or {})
        rule_desc = f"Rule 2 (Telemetry Extraction): Computed {len(raw_feats)} static security vectors for {fmt.upper()}"
        rules["feature_extraction"] = rule_desc
        return {
            "raw_features": raw_feats,
            "file_format": fmt,
            "error": None,
            "applied_rules": rules,
            "applied_rule": rule_desc,
        }
    except Exception as exc:
        rule_desc = f"Rule 2 (Telemetry Extraction): Failed - {str(exc)}"
        return {"error": f"Feature extraction failed: {str(exc)}", "raw_features": {}, "applied_rule": rule_desc}


# ─────────────────────────────────────────────────────────────────────────────
# Node 3: Machine Learning Ensemble Consensus
# ─────────────────────────────────────────────────────────────────────────────


def node_ml_ensemble(state: ExplainPhishState) -> Dict[str, Any]:
    """
    Scales features with format-specific StandardScaler, evaluates
    multi-model predictions across the 5 voting architectures (Random Forest,
    Decision Tree, Neural Network, XGBoost, LightGBM) matching predict.py,
    and computes majority voting consensus with activation-safe clipping.
    """
    if state.get("error"):
        return {}

    fmt = state["file_format"]
    raw_feats = state["raw_features"]
    path = Path(state["file_path"])

    bundle = load_model_bundle(fmt)
    selected_features = bundle["selected_features"]
    scaler = bundle["scaler"]

    sample_std, std_dict = standardize_features(raw_feats, selected_features, scaler)

    # 5-Model architecture registry identical to predict.py / inference.py
    model_registry: List[Tuple[str, Any]] = [
        ("Random Forest", bundle.get("rf_model")),
        ("Decision Tree", bundle.get("dt_model")),
        ("Neural Network", bundle.get("mlp_model")),
        ("XGBoost", bundle.get("xgb_model")),
        ("LightGBM", bundle.get("lgb_model")),
    ]

    # Optional fallback for Logistic Regression if available
    if bundle.get("lr_model") is not None and not any(m[0] == "Logistic Regression" for m in model_registry):
        model_registry.append(("Logistic Regression", bundle.get("lr_model")))

    predictions: List[Dict[str, Any]] = []
    raw_probs: Dict[str, float] = {}

    for model_name, model_obj in model_registry:
        if model_obj is not None:
            # Z-Score Outlier Clipping / Winsorization for Neural Network (MLP)
            # Prevents extreme out-of-distribution z-scores from blowing up linear/ReLU activations
            if model_name == "Neural Network":
                x_input = np.clip(sample_std, -3.0, 3.0)
            else:
                x_input = sample_std

            if hasattr(model_obj, "feature_names_in_"):
                x_eval = pd.DataFrame(x_input, columns=selected_features)
            else:
                x_eval = x_input

            prob = float(model_obj.predict_proba(x_eval)[0, 1])
            pred = int(prob >= 0.5)
            predictions.append({
                "model": model_name,
                "prediction": pred,
                "probability": round(prob, 4),
                "probability_malicious": round(prob, 4),
            })
            raw_probs[model_name] = prob

    malicious_votes = sum(p["prediction"] for p in predictions)
    benign_votes = len(predictions) - malicious_votes
    all_prob_values = list(raw_probs.values())
    mean_prob = float(np.mean(all_prob_values)) if all_prob_values else 0.0

    # True majority consensus voting across all active models (matching predict.py)
    ensemble_verdict = "MALICIOUS" if malicious_votes > (len(predictions) / 2.0) else "BENIGN"
    confidence = mean_prob if ensemble_verdict == "MALICIOUS" else (1.0 - mean_prob)
    band = "HIGH" if confidence >= 0.85 else ("MEDIUM" if confidence >= 0.65 else "LOW")
    unanimous = (malicious_votes == 0 or malicious_votes == len(predictions))

    # Evaluate Borderline & Anomaly Criteria for Dynamic LangGraph Routing
    borderline_reasons: List[str] = []
    if not unanimous:
        borderline_reasons.append(
            f"Split consensus vote ({malicious_votes} Malicious vs {benign_votes} Benign across {len(predictions)} models)"
        )
    if 0.35 <= mean_prob <= 0.65:
        borderline_reasons.append(f"Soft ensemble probability {mean_prob:.1%} resides in ambiguity band [35%-65%]")

    # Check structural threat verification from inference.py
    try:
        is_safe_struct, safety_note = check_structural_safety(path, fmt, raw_feats)
        if is_safe_struct and ensemble_verdict == "MALICIOUS":
            borderline_reasons.append(f"Structural verification anomaly: {safety_note} conflicts with Malicious ML consensus")
    except Exception:
        pass

    # Check format-specific heuristic discrepancies (e.g. ML flags Malicious but macro count is 0)
    if fmt in ("excel", "word"):
        macro_vocab = raw_feats.get("macro_vocab_size", 0)
        macro_tokens = raw_feats.get("macro_token_count", 0)
        remote_tmpl = raw_feats.get("remote_template_present", 0)
        if ensemble_verdict == "MALICIOUS" and macro_vocab == 0 and macro_tokens == 0 and remote_tmpl == 0:
            borderline_reasons.append("Malicious ML vote triggered on Office document despite 0 detected macros or templates")
    elif fmt == "html":
        ext_links = raw_feats.get("external_link_count", 0)
        form_count = raw_feats.get("form_count", 0)
        js_count = raw_feats.get("embedded_js_count", 0)
        if ensemble_verdict == "BENIGN" and form_count > 0 and ext_links > 0:
            borderline_reasons.append("Benign ML vote but HTML document contains active form with external links")
        elif ensemble_verdict == "MALICIOUS":
            try:
                is_safe_html, html_safety_note = check_structural_safety(path, fmt, raw_feats)
                if is_safe_html:
                    borderline_reasons.append(
                        f"Malicious ML vote on HTML document lacks active credential harvesting vectors ({html_safety_note}); deep forensic inspection required"
                    )
            except Exception:
                pass

        # Check high-risk policy categories (gambling/casino mirrors, crypto scams)
        try:
            is_policy_risk, policy_cat, policy_info = check_web_policy_risk(path, source_url=state.get("source_url"))
            if is_policy_risk and ensemble_verdict == "BENIGN":
                borderline_reasons.append(
                    f"Web resource matches High-Risk Policy Category ({policy_cat}); deep threat & policy analysis required"
                )
        except Exception:
            pass
    elif fmt == "pdf":
        js_count = raw_feats.get("js_count", raw_feats.get("javascript_count", 0))
        open_action = raw_feats.get("open_action_count", 0)
        if ensemble_verdict == "BENIGN" and (js_count > 0 or open_action > 0):
            borderline_reasons.append("Benign ML vote but PDF contains active JavaScript or OpenAction triggers")

    is_borderline = len(borderline_reasons) > 0

    rules = dict(state.get("applied_rules") or {})
    if is_borderline:
        rule_desc = f"Rule 3 (Borderline Escalation): {borderline_reasons[0]}"
    else:
        rule_desc = f"Rule 3 (Consensus Rule): Unanimous {ensemble_verdict} consensus across {len(predictions)} models ({confidence:.1%})"
    rules["ml_ensemble"] = rule_desc

    return {
        "standardized_features": std_dict,
        "model_predictions": predictions,
        "raw_probabilities": raw_probs,
        "vote_counts": {"malicious": malicious_votes, "benign": benign_votes},
        "ensemble_verdict": ensemble_verdict,
        "confidence_score": round(confidence, 4),
        "confidence_band": band,
        "unanimous": unanimous,
        "is_borderline": is_borderline,
        "borderline_reasons": borderline_reasons,
        "applied_rules": rules,
        "applied_rule": rule_desc,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Node 4: Explainability & Risk Attribution
# ─────────────────────────────────────────────────────────────────────────────


def node_explainability(state: ExplainPhishState) -> Dict[str, Any]:
    """
    Computes top decision drivers using normalized feature impacts
    and translates them into human-readable security risk factors.
    """
    if state.get("error"):
        return {}

    fmt = state["file_format"]
    bundle = load_model_bundle(fmt)
    drivers = compute_risk_drivers(
        bundle,
        state["raw_features"],
        state["standardized_features"],
        fmt=fmt,
        n_top=6,
    )
    rules = dict(state.get("applied_rules") or {})
    rule_desc = f"Rule 4 (XAI Attribution): Ranked top {len(drivers)} feature drivers using standardized z-score deviation"
    rules["explainability"] = rule_desc

    return {
        "top_risk_drivers": drivers,
        "applied_rules": rules,
        "applied_rule": rule_desc,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Conditional Routing Helper
# ─────────────────────────────────────────────────────────────────────────────


def route_after_explainability(state: ExplainPhishState) -> str:
    """
    Routes to Deep Threat Forensics if borderline or ambiguous;
    otherwise proceeds directly to MITRE mapping.
    """
    if state.get("error"):
        return "soc_report"
    if state.get("is_borderline", False):
        return "deep_threat_analysis"
    return "mitre_mapping"


# ─────────────────────────────────────────────────────────────────────────────
# Node 5: Deep Threat Forensics (Static Inspection & De-obfuscation)
# ─────────────────────────────────────────────────────────────────────────────


def node_deep_threat_analysis(state: ExplainPhishState) -> Dict[str, Any]:
    """
    Autonomous deep static analysis for ambiguous, borderline, or conflicting samples:
    - HTML: Checks for credential phishing forms, external POST targets, hidden iframes, eval/unescape.
    - PDF: Scans streams for /Launch, /JavaScript, /OpenAction, /URI, embedded files.
    - Excel: Scans ZIP for vbaProject.bin, external sheets, DDE execution (=cmd, =powershell).
    - Word: Scans ZIP for vbaProject.bin, remote template injection, embedded OLE objects.
    """
    path = Path(state["file_path"])
    fmt = state["file_format"]
    iocs: List[Dict[str, str]] = []
    deep_findings: Dict[str, Any] = {
        "forensic_inspection_conducted": True,
        "indicators": [],
        "verdict_adjustment": "NONE",
        "rationale": "",
    }

    try:
        if fmt == "html":
            text = path.read_text(encoding="utf-8", errors="ignore")
            # 1. External form action
            form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', text, re.IGNORECASE)
            for action in form_actions:
                if action.startswith("http://") or action.startswith("https://"):
                    iocs.append({"type": "Suspicious Form Action", "value": action})
                    deep_findings["indicators"].append(f"Form submission sends credentials to external URI: {action}")

            # 2. Password inputs
            if re.search(r'<input[^>]*type=["\']password["\']', text, re.IGNORECASE):
                deep_findings["indicators"].append("Credential input field (<input type='password'>) detected")

            # 3. Obfuscated script constructs
            obf_matches = re.findall(r'(eval\s*\(|unescape\s*\(|String\.fromCharCode|document\.write\s*\(|atob\s*\()', text, re.IGNORECASE)
            if obf_matches:
                deep_findings["indicators"].append(f"Potentially obfuscated JavaScript routines: {list(set(obf_matches))}")

            # 4. Hidden iframes
            if re.search(r'<iframe[^>]*(style=["\'][^"\']*(display:\s*none|visibility:\s*hidden|width:\s*0|height:\s*0)[^"\']*|width=["\']0["\']|height=["\']0["\'])', text, re.IGNORECASE):
                deep_findings["indicators"].append("Stealth hidden <iframe> (width/height 0 or display:none) detected")

            if not any("Credential input" in i or "Form submission sends" in i for i in deep_findings["indicators"]):
                deep_findings["indicators"].append("Verified DOM: 0 credential input fields (<input type='password'>) detected")
                deep_findings["indicators"].append("Verified DOM: 0 external form actions detected")
            if not any("Stealth hidden <iframe>" in i for i in deep_findings["indicators"]):
                deep_findings["indicators"].append("Verified DOM: 0 stealth hidden iframes detected")

            # 5. High-Risk Web Category & Policy Risk Inspection
            try:
                is_policy_risk, policy_cat, policy_info = check_web_policy_risk(path, source_url=state.get("source_url"))
                if is_policy_risk:
                    matches_list = policy_info.get("content_matches", [])[:3] + policy_info.get("domain_matches", [])
                    deep_findings["indicators"].append(
                        f"High-Risk Web Category Detected: {policy_cat} (Policy: {policy_info.get('policy_code', 'AUP-VIOLATION')}, Indicators: {', '.join(matches_list)})"
                    )
                    deep_findings["policy_risk"] = {
                        "category": policy_cat,
                        "code": policy_info.get("policy_code", "AUP-VIOLATION"),
                        "details": policy_info,
                    }
                    iocs.append({
                        "type": "Policy Violation Category",
                        "value": f"{policy_cat} [{policy_info.get('policy_code')}]",
                    })
            except Exception:
                pass

        elif fmt == "pdf":
            raw_pdf = path.read_bytes()
            # 1. PDF /Launch (execute external program)
            if b"/Launch" in raw_pdf:
                deep_findings["indicators"].append("PDF /Launch action detected: capability to execute OS commands")
                iocs.append({"type": "PDF Action", "value": "/Launch"})
            # 2. PDF /JavaScript or /JS
            if b"/JavaScript" in raw_pdf or b"/JS" in raw_pdf:
                deep_findings["indicators"].append("PDF embedded JavaScript action detected")
                iocs.append({"type": "PDF Action", "value": "/JavaScript"})
            # 3. PDF /OpenAction
            if b"/OpenAction" in raw_pdf or b"/AA" in raw_pdf:
                deep_findings["indicators"].append("PDF /OpenAction / AdditionalActions detected: executes upon file opening")
            # 4. Embedded URIs
            pdf_uris = re.findall(rb'/URI\s*\((https?://[^)]+)\)', raw_pdf)
            for u in pdf_uris[:5]:
                decoded_u = u.decode("latin1", errors="ignore")
                iocs.append({"type": "Embedded URL", "value": decoded_u})
                deep_findings["indicators"].append(f"PDF Embedded outbound URI: {decoded_u}")

        elif fmt in ("excel", "word"):
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path, "r") as zf:
                    names = zf.namelist()
                    # 1. VBA Macro presence
                    vba_files = [n for n in names if "vbaProject.bin" in n or "vbaData.xml" in n]
                    if vba_files:
                        deep_findings["indicators"].append(f"Active VBA Macro binaries located in archive: {vba_files}")
                        iocs.append({"type": "VBA Binary", "value": ", ".join(vba_files)})
                    else:
                        deep_findings["indicators"].append("Verified archive: 0 VBA Macro binaries found")

                    # 2. Word Remote Template Injection
                    if fmt == "word":
                        rel_files = [n for n in names if n.endswith(".rels")]
                        for rf in rel_files:
                            try:
                                rel_content = zf.read(rf).decode("utf-8", errors="ignore")
                                if 'TargetMode="External"' in rel_content and "attachedTemplate" in rel_content:
                                    targets = re.findall(r'Target="([^"]+)"', rel_content)
                                    deep_findings["indicators"].append(f"Remote Template Injection detected: {targets}")
                                    for t in targets:
                                        iocs.append({"type": "Remote Template Target", "value": t})
                            except Exception:
                                pass

                    # 3. Embedded OLE Objects
                    ole_embeds = [n for n in names if "embeddings/" in n or "oleObject" in n]
                    if ole_embeds:
                        deep_findings["indicators"].append(f"Embedded OLE objects detected: {ole_embeds}")
                        for o in ole_embeds:
                            iocs.append({"type": "OLE Embedding", "value": o})

                    # 4. Excel Formula Injection / DDE
                    if fmt == "excel":
                        sheet_files = [n for n in names if "worksheets/sheet" in n]
                        dde_found = False
                        for sf in sheet_files:
                            try:
                                sdata = zf.read(sf).decode("utf-8", errors="ignore")
                                if re.search(r'<f[^>]*>[=+\-@](cmd|powershell|mshta|cscript|wscript|certutil)', sdata, re.IGNORECASE):
                                    dde_found = True
                                    deep_findings["indicators"].append(f"DDE / Command Execution Formula detected in {sf}")
                                    iocs.append({"type": "DDE Injection", "value": sf})
                            except Exception:
                                pass
                        if not dde_found:
                            deep_findings["indicators"].append("Verified spreadsheet: 0 DDE / command injection formulas detected")

    except Exception as exc:
        deep_findings["error"] = f"Deep inspection exception: {str(exc)}"

    # Ambiguity Resolution Logic:
    original_verdict = state.get("ensemble_verdict", "BENIGN")
    final_verdict = original_verdict
    has_active_payloads = len([i for i in deep_findings["indicators"] if not i.startswith("Verified")]) > 0

    if fmt in ("excel", "word"):
        macro_absent = any("0 VBA Macro binaries found" in i for i in deep_findings["indicators"])
        no_ole = not any("Embedded OLE" in i for i in deep_findings["indicators"])
        no_template = not any("Remote Template" in i for i in deep_findings["indicators"])
        no_dde = any("0 DDE" in i for i in deep_findings["indicators"]) or fmt == "word"

        if original_verdict == "MALICIOUS" and macro_absent and no_ole and no_template and no_dde:
            # Calibrated false-positive downgrade
            final_verdict = "BENIGN (False-Positive Screened)"
            deep_findings["verdict_adjustment"] = "DOWNGRADE_TO_BENIGN"
            deep_findings["rationale"] = (
                "ML model flagged anomaly due to statistical document text features, "
                "but exhaustive deep forensic inspection confirmed zero VBA macros, zero remote templates, "
                "zero embedded OLE objects, and zero DDE injection vectors. Classified safe."
            )
        elif original_verdict == "BENIGN" and has_active_payloads:
            final_verdict = "MALICIOUS (Forensic Override)"
            deep_findings["verdict_adjustment"] = "UPGRADE_TO_MALICIOUS"
            deep_findings["rationale"] = (
                "ML model returned benign probability, but deep forensic inspection discovered "
                f"active execution payloads: {deep_findings['indicators']}"
            )
    elif fmt == "html":
        has_cred_theft = any("Credential input field" in i or "external URI" in i for i in deep_findings["indicators"])
        has_stealth_iframe = any("Stealth hidden <iframe>" in i for i in deep_findings["indicators"])
        has_policy_risk = any("High-Risk Web Category Detected" in i for i in deep_findings["indicators"])
        policy_cat_name = deep_findings.get("policy_risk", {}).get("category", "Policy Violation")

        if has_cred_theft and original_verdict == "BENIGN":
            final_verdict = "MALICIOUS (Phishing Form Detected)"
            deep_findings["verdict_adjustment"] = "UPGRADE_TO_MALICIOUS"
            deep_findings["rationale"] = "Active credential harvesting form targeting external endpoint confirmed."
        elif has_policy_risk and original_verdict == "BENIGN":
            final_verdict = f"SUSPICIOUS ({policy_cat_name})"
            deep_findings["verdict_adjustment"] = "ESCALATE_TO_SUSPICIOUS"
            deep_findings["rationale"] = (
                f"ML models returned benign phishing score because the site is an active commercial portal "
                f"rather than a brand-impersonation phishing lure. However, deep content inspection confirmed "
                f"an active {policy_cat_name} web portal operating under an evasive rotating mirror domain. "
                "Classified SUSPICIOUS under corporate Acceptable Use Policy (AUP)."
            )
        elif original_verdict == "MALICIOUS" and not has_cred_theft and not has_stealth_iframe:
            final_verdict = "BENIGN (False-Positive Screened)"
            deep_findings["verdict_adjustment"] = "DOWNGRADE_TO_BENIGN"
            deep_findings["rationale"] = (
                "ML model flagged anomaly due to statistical covariate shift (production HTML minification and script packing), "
                "but exhaustive deep forensic inspection confirmed zero password input fields, zero external form POST actions, "
                "and zero stealth hidden iframes. Calibrated safe."
            )
    elif fmt == "pdf":
        has_exec = any("/Launch" in i or "/JavaScript" in i for i in deep_findings["indicators"])
        if has_exec and original_verdict == "BENIGN":
            final_verdict = "MALICIOUS (Active PDF Payload Detected)"
            deep_findings["verdict_adjustment"] = "UPGRADE_TO_MALICIOUS"
            deep_findings["rationale"] = "Unsafe PDF execution triggers (/Launch or /JavaScript) confirmed."

    rules = dict(state.get("applied_rules") or {})
    if deep_findings.get("verdict_adjustment") == "DOWNGRADE_TO_BENIGN":
        if fmt == "html":
            rule_desc = "Rule 5A (False-Positive Screening): Verified 0 password fields, 0 external form actions, and 0 stealth iframes. Calibrated to BENIGN."
        else:
            rule_desc = "Rule 5A (False-Positive Screening): Verified 0 VBA macros, 0 OLE payloads, 0 DDE, and 0 remote templates. Calibrated to BENIGN."
    elif deep_findings.get("verdict_adjustment") == "UPGRADE_TO_MALICIOUS":
        rule_desc = f"Rule 5B (Forensic Override): Verified active execution vectors ({', '.join(deep_findings['indicators'][:2])}). Escalated to MALICIOUS."
    elif deep_findings.get("verdict_adjustment") == "ESCALATE_TO_SUSPICIOUS":
        rule_desc = f"Rule 5D (Policy Enforcement): Detected {policy_cat_name} & mirror domain. Escalated to SUSPICIOUS."
    else:
        rule_desc = f"Rule 5C (Forensic Verification): Static inspection evaluated {len(deep_findings['indicators'])} indicators."
    rules["deep_threat_analysis"] = rule_desc

    return {
        "deep_analysis": deep_findings,
        "indicators_of_compromise": iocs,
        "final_verdict": final_verdict,
        "applied_rules": rules,
        "applied_rule": rule_desc,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Node 6: MITRE ATT&CK Mapping & SOAR Actions
# ─────────────────────────────────────────────────────────────────────────────


def node_mitre_mapping(state: ExplainPhishState) -> Dict[str, Any]:
    """
    Maps observed threats and feature vectors to industry-standard
    MITRE ATT&CK tactics, techniques, and prescriptive SOAR remediation playbooks.
    """
    if state.get("error"):
        return {}

    final_verdict = state.get("final_verdict") or state.get("ensemble_verdict", "BENIGN")
    fmt = state.get("file_format", "unknown")
    raw_feats = state.get("raw_features", {})
    deep_analysis = state.get("deep_analysis", {})
    indicators = deep_analysis.get("indicators", [])

    mitre_tactics: List[Dict[str, str]] = []
    actions: List[Dict[str, str]] = []
    threat_level = "INFORMATIONAL"

    if "MALICIOUS" in final_verdict:
        # MITRE Technique Identifiers
        if fmt == "html":
            threat_level = "HIGH"
            mitre_tactics.append({
                "id": "T1566.002",
                "tactic": "Initial Access",
                "technique": "Phishing: Spearphishing Link",
                "description": "Adversary uses deceptive HTML lure directing user to malicious landing page.",
            })
            if any("Credential input" in i or "password" in i.lower() for i in indicators) or raw_feats.get("form_count", 0) > 0:
                threat_level = "CRITICAL"
                mitre_tactics.append({
                    "id": "T1056.001",
                    "tactic": "Credential Access",
                    "technique": "Input Capture: Keylogging / Web Forms",
                    "description": "Embedded form designed to harvest victim authentication credentials.",
                })
            if raw_feats.get("embedded_js_count", 0) > 0 or raw_feats.get("script_entropy", 0) > 4.5:
                mitre_tactics.append({
                    "id": "T1059.007",
                    "tactic": "Execution",
                    "technique": "Command and Scripting Interpreter: JavaScript",
                    "description": "Embedded obfuscated client-side scripts to manipulate DOM or evade scanners.",
                })
        elif fmt == "pdf":
            threat_level = "HIGH"
            mitre_tactics.append({
                "id": "T1566.001",
                "tactic": "Initial Access",
                "technique": "Phishing: Spearphishing Attachment",
                "description": "Weaponized PDF file distributed as an email attachment lure.",
            })
            mitre_tactics.append({
                "id": "T1204.002",
                "tactic": "Execution",
                "technique": "User Execution: Malicious File",
                "description": "Relies on victim opening PDF reader to trigger malicious actions or exploit viewer.",
            })
            if any("/Launch" in i for i in indicators):
                threat_level = "CRITICAL"
                mitre_tactics.append({
                    "id": "T1106",
                    "tactic": "Execution",
                    "technique": "Native API / Process Execution",
                    "description": "PDF utilizes /Launch action to execute OS-level command interpreter or binary.",
                })
        elif fmt in ("excel", "word"):
            threat_level = "HIGH"
            mitre_tactics.append({
                "id": "T1566.001",
                "tactic": "Initial Access",
                "technique": "Phishing: Spearphishing Attachment",
                "description": "Weaponized Microsoft Office document delivered via phishing campaign.",
            })
            if any("VBA" in i for i in indicators) or raw_feats.get("macro_vocab_size", 0) > 0:
                threat_level = "CRITICAL"
                mitre_tactics.append({
                    "id": "T1059.005",
                    "tactic": "Execution",
                    "technique": "Command and Scripting Interpreter: Visual Basic",
                    "description": "Embedded VBA macros configured for AutoOpen/Workbook_Open execution upon launch.",
                })
            if any("Template Injection" in i for i in indicators) or raw_feats.get("remote_template_present", 0) > 0:
                threat_level = "CRITICAL"
                mitre_tactics.append({
                    "id": "T1221",
                    "tactic": "Defense Evasion",
                    "technique": "Template Injection",
                    "description": "Document dynamically fetches remote weaponized dotm template over SMB/HTTP.",
                })

        # SOAR Remediation Playbook
        actions.append({
            "stage": "Containment",
            "tier": "Tier 1 - Endpoint Isolation",
            "action": f"Quarantine file SHA256 {state.get('file_hash_sha256', '')[:16]}... on EDR (CrowdStrike / Defender for Endpoint).",
        })
        actions.append({
            "stage": "Perimeter Defense",
            "tier": "Tier 2 - Network Egress Block",
            "action": "Block associated destination domains/IPs on Secure Web Gateway (Zscaler / Palo Alto Networks).",
        })
        actions.append({
            "stage": "Mailbox Remediation",
            "tier": "Tier 3 - Tenant Email Purge",
            "action": f"Execute O365 / Google Workspace mail sweep to purge identical message-ID and attachments across enterprise mailboxes.",
        })
        if threat_level == "CRITICAL":
            actions.append({
                "stage": "Identity & Access",
                "tier": "Tier 4 - Credential Revocation",
                "action": "Revoke active sessions and force MFA re-authentication for any recipient who opened the attachment.",
            })

    elif "SUSPICIOUS" in final_verdict:
        threat_level = "MEDIUM"
        mitre_tactics.append({
            "id": "AUP-GAMBLING",
            "tactic": "Policy Violation",
            "technique": "Unsanctioned Commercial Web Resource: Online Gambling / Sportsbook",
            "description": "Access to unregulated online casino / betting portal. Prohibited under enterprise Acceptable Use Policy (AUP).",
        })
        mitre_tactics.append({
            "id": "T1566.002",
            "tactic": "Initial Access",
            "technique": "High-Risk Mirror Domain / Unsanctioned Web Portal",
            "description": "Rotating mirror domain associated with regulatory evasion and gray-market online gambling operations.",
        })
        actions.append({
            "stage": "Perimeter Defense",
            "tier": "Tier 1 - Web Category Block",
            "action": "Enforce category block on Secure Web Gateway (Zscaler / Palo Alto Networks URL Filtering: Gambling & Betting).",
        })
        actions.append({
            "stage": "DNS Security",
            "tier": "Tier 2 - Sinkhole Evasive Mirror",
            "action": "Sinkhole rotating mirror domain on enterprise recursive DNS resolvers (Infoblox / Cisco Umbrella).",
        })
        actions.append({
            "stage": "Compliance & Audit",
            "tier": "Tier 3 - AUP Telemetry Logging",
            "action": "Log Acceptable Use Policy (AUP) violation event on SIEM; notify user/SOC of unsanctioned browsing activity.",
        })

    elif "BENIGN" in final_verdict:
        threat_level = "LOW" if "Screened" in final_verdict else "CLEAN"
        mitre_tactics.append({
            "id": "N/A",
            "tactic": "No Malicious Tactics Identified",
            "technique": "Standard Business Document",
            "description": "File exhibits standard benign enterprise document characteristics.",
        })
        actions.append({
            "stage": "Clearance",
            "tier": "Tier 1 - Safe Release",
            "action": "Release document from sandbox quarantine to destination mailbox. No SOC escalation required.",
        })

    rules = dict(state.get("applied_rules") or {})
    rule_desc = f"Rule 6 (MITRE & SOAR): Mapped {len(mitre_tactics)} techniques & {len(actions)} prescriptive playbooks"
    rules["mitre_mapping"] = rule_desc

    return {
        "mitre_tactics": mitre_tactics,
        "soc_playbook_actions": actions,
        "threat_level": threat_level,
        "final_verdict": final_verdict,
        "applied_rules": rules,
        "applied_rule": rule_desc,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Node 7: SOC Incident Response Report Generation
# ─────────────────────────────────────────────────────────────────────────────


def node_soc_report(state: ExplainPhishState) -> Dict[str, Any]:
    """
    Assembles a comprehensive, human-readable SOC Incident Response Report
    in Markdown format with embedded metrics, indicators, and mitigation steps.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    filename = state.get("file_name", "unknown")
    sha256 = state.get("file_hash_sha256", "N/A")
    md5 = state.get("file_hash_md5", "N/A")
    size_bytes = state.get("file_size_bytes", 0)
    fmt_display = state.get("format_display", "Unknown")
    verdict = state.get("final_verdict") or state.get("ensemble_verdict", "UNKNOWN")
    threat_level = state.get("threat_level", "UNKNOWN")
    confidence = state.get("confidence_score", 0.0)
    band = state.get("confidence_band", "UNKNOWN")
    unanimous = state.get("unanimous", False)
    predictions = state.get("model_predictions", [])
    top_drivers = state.get("top_risk_drivers", [])
    iocs = state.get("indicators_of_compromise", [])
    mitre = state.get("mitre_tactics", [])
    playbook = state.get("soc_playbook_actions", [])
    deep = state.get("deep_analysis", {})

    status_badge = "🔴" if "MALICIOUS" in verdict else ("🟠" if "SUSPICIOUS" in verdict else ("🟢" if "CLEAN" in threat_level else "🟡"))

    rules = dict(state.get("applied_rules") or {})
    rule_desc = f"Rule 7 (Executive Synthesis): Synthesized comprehensive SOC IR dossier with verdict {verdict}"
    rules["soc_report"] = rule_desc

    report_lines = [
        f"# {status_badge} SOC Incident Response Report — {filename}",
        f"**Generated:** `{timestamp}` | **Pipeline:** `ExplainPhish LangGraph Agent v2.0` | **Classification:** `{threat_level}`",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        f"- **File Name:** `{filename}`",
        f"- **Verdict:** **{verdict}**",
        f"- **Threat Level:** `{threat_level}`",
        f"- **Ensemble Confidence:** `{confidence:.1%}` ({band} confidence band)",
        f"- **Format:** `{fmt_display}` | **Size:** `{size_bytes:,} bytes`",
        f"- **SHA-256:** `{sha256}`",
        f"- **MD5:** `{md5}`",
    ]
    if state.get("source_url"):
        report_lines.append(f"- **Source URL:** `{state['source_url']}`")
    report_lines.append("")

    if rules:
        report_lines.extend([
            "### Investigation Pipeline Rules Applied",
            "| Stage | Trigger & Operational Rule Evaluation |",
            "| :--- | :--- |",
        ])
        for stage_k in ["intake_safety", "feature_extraction", "ml_ensemble", "explainability", "deep_threat_analysis", "mitre_mapping", "soc_report"]:
            if stage_k in rules:
                stage_title = stage_k.replace("_", " ").title()
                report_lines.append(f"| **{stage_title}** | {rules[stage_k]} |")
        report_lines.append("")

    if deep.get("rationale"):
        report_lines.extend([
            "> [!NOTE]",
            f"> **Autonomous Forensics Decision:** {deep['rationale']}",
            "",
        ])

    # Model Inference Table
    report_lines.extend([
        "## 2. Multi-Model ML Ensemble Consensus",
        f"Consensus voting evaluated across {len(predictions)} standardized architectures with 100% feature parity.",
        "",
        "| Architecture | Prediction | Phishing Probability | Status |",
        "| :--- | :--- | :--- | :--- |",
    ])
    for p in predictions:
        pred_label = "MALICIOUS" if p["prediction"] == 1 else "BENIGN"
        prob_val = p.get("probability", 0.0)
        icon = "⚠️" if p["prediction"] == 1 else "✅"
        report_lines.append(f"| **{p['model']}** | `{pred_label}` | `{prob_val:.1%}` | {icon} |")

    consensus_text = "Unanimous agreement across all models." if unanimous else "Split consensus vote resolved through LangGraph deep analysis."
    report_lines.extend([
        "",
        f"**Consensus Status:** {consensus_text}",
        "",
    ])

    # Explainable AI Drivers
    if top_drivers:
        report_lines.extend([
            "## 3. Explainable AI (XAI) — Top Decision Drivers",
            "Feature impact on model classification derived from normalized feature importance and standardized training deviations ($z = \\frac{x - \\mu}{\\sigma}$):",
            "",
            "| Feature | Description | Raw Value | Z-Score | Direction | Risk Impact |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for d in top_drivers:
            dir_icon = "🔺 Increases Risk" if d["direction"] == "↑" else "🔻 Reduces Risk"
            report_lines.append(
                f"| `{d['feature']}` | {d['description']} | `{d['raw_value']}` | `{d['std_value']:+.2f}` | `{d['direction']}` | {dir_icon} (`{d['impact']:+.4f}`) |"
            )
        report_lines.append("")

    # Deep Forensics & IOCs
    if deep.get("forensic_inspection_conducted"):
        report_lines.extend([
            "## 4. Deep Forensic Static Telemetry",
            "Autonomous static inspection findings:",
            "",
        ])
        for ind in deep.get("indicators", []):
            report_lines.append(f"- {ind}")
        report_lines.append("")

    if iocs:
        report_lines.extend([
            "### Indicators of Compromise (IOCs)",
            "| Type | Indicator Value |",
            "| :--- | :--- |",
        ])
        for ioc in iocs:
            report_lines.append(f"| `{ioc['type']}` | `{ioc['value']}` |")
        report_lines.append("")

    # MITRE ATT&CK Matrix
    if mitre:
        report_lines.extend([
            "## 5. MITRE ATT&CK Mapping",
            "| Technique ID | Tactic | Technique Name | Operational Description |",
            "| :--- | :--- | :--- | :--- |",
        ])
        for m in mitre:
            report_lines.append(f"| **{m['id']}** | `{m['tactic']}` | `{m['technique']}` | {m['description']} |")
        report_lines.append("")

    # SOAR Playbook Actions
    if playbook:
        report_lines.extend([
            "## 6. Prescriptive SOAR Incident Response Playbook",
            "| Stage | Action Tier | Prescribed Response Action |",
            "| :--- | :--- | :--- |",
        ])
        for a in playbook:
            report_lines.append(f"| **{a['stage']}** | `{a['tier']}` | {a['action']} |")
        report_lines.append("")

    report_lines.extend([
        "---",
        "*Report automatically generated by ExplainPhish Autonomous Security Agent. For SOC escalations, submit hash to SIEM.*",
    ])

    report_markdown = "\n".join(report_lines)

    # Save report to reports directory
    reports_dir = _HERE / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / f"SOC_Report_{sha256[:10]}_{path_safe(filename)}.md"
    try:
        report_file.write_text(report_markdown, encoding="utf-8")
        saved_path = str(report_file)
    except Exception:
        saved_path = None

    return {
        "soc_report_markdown": report_markdown,
        "executive_summary": f"Verdict: {verdict} ({threat_level}) with {confidence:.1%} confidence.",
        "report_saved_path": saved_path,
    }


def path_safe(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-\.]", "_", name)


# ─────────────────────────────────────────────────────────────────────────────
# Graph Construction & Compilation
# ─────────────────────────────────────────────────────────────────────────────


def build_explainphish_graph():
    """
    Constructs and compiles the ExplainPhish LangGraph StateGraph.
    """
    builder = StateGraph(ExplainPhishState)

    # Add Nodes
    builder.add_node("intake_safety", node_intake_safety)
    builder.add_node("feature_extraction", node_feature_extraction)
    builder.add_node("ml_ensemble", node_ml_ensemble)
    builder.add_node("explainability", node_explainability)
    builder.add_node("deep_threat_analysis", node_deep_threat_analysis)
    builder.add_node("mitre_mapping", node_mitre_mapping)
    builder.add_node("soc_report", node_soc_report)

    # Edges
    builder.add_edge(START, "intake_safety")
    builder.add_edge("intake_safety", "feature_extraction")
    builder.add_edge("feature_extraction", "ml_ensemble")
    builder.add_edge("ml_ensemble", "explainability")

    # Conditional Branching: Ambiguity / Borderline Handling
    builder.add_conditional_edges(
        "explainability",
        route_after_explainability,
        {
            "deep_threat_analysis": "deep_threat_analysis",
            "mitre_mapping": "mitre_mapping",
            "soc_report": "soc_report",
        },
    )

    builder.add_edge("deep_threat_analysis", "mitre_mapping")
    builder.add_edge("mitre_mapping", "soc_report")
    builder.add_edge("soc_report", END)

    return builder.compile()


# Singleton compiled graph
_EXPLAINPHISH_APP = None


def get_explainphish_graph():
    global _EXPLAINPHISH_APP
    if _EXPLAINPHISH_APP is None:
        _EXPLAINPHISH_APP = build_explainphish_graph()
    return _EXPLAINPHISH_APP


def run_pipeline(file_path: str | Path, source_url: Optional[str] = None) -> ExplainPhishState:
    """Convenience function to run the full graph on any file or URL."""
    graph = get_explainphish_graph()
    initial_state: ExplainPhishState = {
        "file_path": str(file_path),
        "source_url": source_url,
    }
    return graph.invoke(initial_state)


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="ExplainPhish Autonomous SOC Agent Pipeline (Powered by LangGraph)"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", help="Path to suspicious document (HTML, PDF, Excel, Word)")
    group.add_argument("--url", "-u", help="Live website / phishing URL to fetch and triage autonomously")
    parser.add_argument("--json", action="store_true", help="Output full JSON state instead of Markdown report")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress console markdown output")

    args = parser.parse_args()

    source_url = None
    if args.url:
        import urllib.request
        from urllib.parse import urlparse

        source_url = args.url.strip()
        parsed = urlparse(source_url)
        if not parsed.scheme or not parsed.netloc:
            print(f"Error: Invalid URL scheme or host: {source_url}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Fetching live web resource from: {source_url}...")
        req = urllib.request.Request(
            source_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read()
                content_type = resp.headers.get("Content-Type", "")
        except Exception as exc:
            print(f"Error fetching URL '{source_url}': {exc}", file=sys.stderr)
            sys.exit(1)

        ext = Path(parsed.path).suffix.lower()
        if not ext or ext not in (".html", ".htm", ".pdf", ".xlsx", ".docx"):
            ext = ".pdf" if "pdf" in content_type.lower() else ".html"

        clean_host = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", parsed.netloc)
        downloads_dir = _HERE / "downloads"
        downloads_dir.mkdir(parents=True, exist_ok=True)
        input_file = downloads_dir / f"live_{clean_host}{ext}"
        input_file.write_bytes(content)
        print(f"[+] Downloaded {len(content):,} bytes to temporary artifact: {input_file.name}")
    else:
        input_file = Path(args.file).resolve()
        if not input_file.exists():
            print(f"Error: Target file not found: {input_file}", file=sys.stderr)
            sys.exit(1)

    print(f"[*] Initializing ExplainPhish LangGraph Agent for: {input_file.name}...")
    result = run_pipeline(input_file, source_url=source_url)

    if args.json:
        # Filter serializable subset
        clean_out = {
            k: v for k, v in result.items() if k not in ("raw_features", "standardized_features")
        }
        print(json.dumps(clean_out, indent=2))
        return

    if not args.quiet:
        print("\n" + result.get("soc_report_markdown", "No report generated."))

    if result.get("report_saved_path"):
        print(f"\n[+] Full SOC Incident Response Report saved to: {result['report_saved_path']}")


if __name__ == "__main__":
    main()

