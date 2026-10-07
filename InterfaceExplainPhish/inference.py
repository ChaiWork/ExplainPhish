"""
InterfaceExplainPhish Core Inference Engine
============================================
Implements the standardized inference & multi-model consensus voting pipeline:
  1. Raw Feature Extraction (using format-specific extractors)
  2. StandardScaler Transformation (z = (x - mu_train) / sigma_train)
  3. Multi-Model Inferences across the 5 voting architectures:
       - Random Forest
       - Decision Tree
       - Neural Network (Multi-Layer Perceptron / MLP)
       - XGBoost (Extreme Gradient Boosting)
       - LightGBM (Light Gradient Boosting Machine)
  4. Consensus Voting (Majority Vote across all 5 models + Soft Probability Averaging + Risk Drivers)
     or Target Single-Model Prediction when requested.
"""
from __future__ import annotations

import json
import math
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TypedDict

import joblib
import numpy as np
import pandas as pd

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

FORMAT_EXTENSIONS: Dict[str, Tuple[str, ...]] = {
    "pdf": (".pdf",),
    "excel": (".xlsx", ".xlsm", ".xls", ".xlsb"),
    "html": (".html", ".htm"),
    "word": (".docx", ".docm", ".dotx", ".dotm", ".doc", ".dot"),
}

FORMAT_DISPLAY: Dict[str, str] = {
    "html": "HTML Document",
    "pdf": "PDF Document",
    "excel": "Excel Spreadsheet",
    "word": "Word Document",
}

MODEL_ALIASES: Dict[str, str] = {
    "rf": "Random Forest",
    "random forest": "Random Forest",
    "random_forest": "Random Forest",
    "dt": "Decision Tree",
    "decision tree": "Decision Tree",
    "decision_tree": "Decision Tree",
    "nn": "Neural Network",
    "mlp": "Neural Network",
    "neural network": "Neural Network",
    "neural_network": "Neural Network",
    "xgb": "XGBoost",
    "xgboost": "XGBoost",
    "lgb": "LightGBM",
    "lightgbm": "LightGBM",
}

# In-memory cache for loaded model bundles
_MODEL_CACHE: Dict[str, Dict[str, Any]] = {}


class ModelPrediction(TypedDict):
    model: str
    prediction: int  # 1 for malicious, 0 for benign
    probability_malicious: float


class VoteResult(TypedDict):
    verdict: str  # "MALICIOUS" | "BENIGN"
    confidence: float
    confidence_band: str  # "HIGH" | "MEDIUM" | "LOW"
    vote_counts: Dict[str, int]
    mean_probability: float
    uncertain: bool
    target_model: Optional[str]


class FeatureDriver(TypedDict):
    feature: str
    impact: float
    direction: str
    raw_value: Any
    std_value: float


class InferenceResult(TypedDict):
    file_name: str
    file_path: str
    format: str
    format_display: str
    features: Dict[str, Any]
    standardized_features: Dict[str, float]
    model_predictions: List[ModelPrediction]
    vote: VoteResult
    top_risk_drivers: List[FeatureDriver]
    error: Optional[str]


def detect_format(file_path: Path) -> str:
    """
    Detect file format based on suffix and magic byte sniffing.
    Supports PDF, Word (OOXML & legacy), Excel (OOXML & legacy), and HTML.
    """
    suffix = file_path.suffix.lower()
    for fmt, exts in FORMAT_EXTENSIONS.items():
        if suffix in exts:
            return fmt

    # Fallback: Magic byte & structure inspection
    if file_path.is_file():
        try:
            with open(file_path, "rb") as f:
                header = f.read(4096)

            # 1. PDF signature
            if header.startswith(b"%PDF") or b"%PDF-" in header[:1024]:
                return "pdf"

            # 2. OOXML ZIP package (Word .docx or Excel .xlsx)
            if header.startswith(b"PK\x03\x04"):
                import zipfile
                try:
                    with zipfile.ZipFile(file_path, "r") as zf:
                        names = zf.namelist()
                        if any(n.startswith("word/") for n in names):
                            return "word"
                        if any(n.startswith("xl/") for n in names):
                            return "excel"
                except Exception:
                    pass

            # 3. HTML signatures
            header_lower = header.lower()
            html_markers = [b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<iframe"]
            if any(m in header_lower for m in html_markers):
                return "html"

            # 4. Legacy OLE Compound Document (Excel 97-2003 or Word 97-2003)
            if header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                try:
                    import olefile
                    if olefile.isOleFile(file_path):
                        with olefile.OleFileIO(file_path) as ole:
                            if ole.exists("Workbook") or ole.exists("Book"):
                                return "excel"
                            if ole.exists("WordDocument"):
                                return "word"
                except Exception:
                    pass
        except Exception:
            pass

    raise ValueError(
        f"Unsupported file extension '{suffix}' and cannot determine format via magic byte sniffing. "
        f"Supported formats: HTML (.html, .htm), PDF (.pdf), Excel (.xlsx, .xlsm, .xls), Word (.docx, .docm, .doc)"
    )


def load_model_bundle(fmt: str) -> Dict[str, Any]:
    """
    Load models, scaler, feature list, and metadata for a format.
    Checks InterfaceExplainPhish/models/<fmt> first, then ../models/<fmt>.
    Dynamically loads all 5 trained models:
      - Random Forest (rf_model.joblib)
      - Decision Tree (dt_model.joblib)
      - Neural Network / MLP (mlp_model.joblib)
      - XGBoost (xgb_model.joblib)
      - LightGBM (lgb_model.joblib)
    """
    if fmt in _MODEL_CACHE:
        return _MODEL_CACHE[fmt]

    candidates = [
        _HERE / "models" / fmt,
        _HERE.parent / "models" / fmt,
        _HERE.parent / "googleCollab" / "models" / fmt,
    ]

    model_dir = None
    for c in candidates:
        if (c / "rf_model.joblib").exists() and (c / "scaler.joblib").exists():
            model_dir = c
            break

    if model_dir is None:
        raise FileNotFoundError(
            f"Could not locate trained models for format '{fmt}'. "
            f"Checked: {[str(c) for c in candidates]}"
        )

    # Load core artifacts
    rf_model = joblib.load(model_dir / "rf_model.joblib")
    dt_model = joblib.load(model_dir / "dt_model.joblib")
    scaler = joblib.load(model_dir / "scaler.joblib")

    # Load advanced / format-specific models if available
    mlp_model = None
    if (model_dir / "mlp_model.joblib").exists():
        mlp_model = joblib.load(model_dir / "mlp_model.joblib")

    xgb_model = None
    if (model_dir / "xgb_model.joblib").exists():
        xgb_model = joblib.load(model_dir / "xgb_model.joblib")

    lgb_model = None
    if (model_dir / "lgb_model.joblib").exists():
        lgb_model = joblib.load(model_dir / "lgb_model.joblib")

    with open(model_dir / "selected_features.json", "r", encoding="utf-8") as f:
        selected_features = json.load(f)

    meta = {}
    if (model_dir / "metadata.json").exists():
        with open(model_dir / "metadata.json", "r", encoding="utf-8") as f:
            meta = json.load(f)

    bundle = {
        "fmt": fmt,
        "model_dir": model_dir,
        "rf_model": rf_model,
        "dt_model": dt_model,
        "mlp_model": mlp_model,
        "xgb_model": xgb_model,
        "lgb_model": lgb_model,
        "scaler": scaler,
        "selected_features": selected_features,
        "metadata": meta,
    }
    _MODEL_CACHE[fmt] = bundle
    return bundle


def extract_features(file_path: Path, fmt: str) -> Dict[str, Any]:
    """Extract raw features using the format extractor."""
    if fmt == "html":
        from extractors.html_extractor import extract
    elif fmt == "pdf":
        from extractors.pdf_extractor import extract
    elif fmt == "excel":
        from extractors.excel_extractor import extract
    elif fmt == "word":
        from extractors.word_extractor import extract
    else:
        raise ValueError(f"Unknown format: {fmt}")

    return extract(file_path)


def standardize_features(
    raw_features: Dict[str, Any],
    selected_features: List[str],
    scaler: Any,
) -> Tuple[np.ndarray, Dict[str, float]]:
    """
    Standardize raw features using the pre-fitted StandardScaler.
    Applies defensive zero imputation and preserves exact feature ordering.
    """
    df_sample = pd.DataFrame([raw_features])
    
    # Ensure all selected features exist, fill missing with 0
    for col in selected_features:
        if col not in df_sample.columns:
            df_sample[col] = 0.0

    df_sample = df_sample[selected_features].fillna(0.0)

    # Standardize values: z = (x - mu) / sigma
    sample_std_arr = scaler.transform(df_sample.values)
    
    std_dict = {
        col: float(sample_std_arr[0, idx])
        for idx, col in enumerate(selected_features)
    }
    return sample_std_arr, std_dict


def compute_risk_drivers(
    bundle: Dict[str, Any],
    raw_features: Dict[str, Any],
    std_dict: Dict[str, float],
    sample_std: Optional[np.ndarray] = None,
    n_top: Optional[int] = None,
) -> List[FeatureDriver]:
    """
    Compute decision drivers using TreeExplainer SHAP values on Random Forest
    (the primary ensemble detector) or feature importance weighted z-scores as fallback.
    Positive impact increases phishing risk, negative impact reduces it.
    If n_top is None or <= 0, returns all active model features sorted by absolute impact.
    """
    rf = bundle.get("rf_model")
    selected_features = bundle["selected_features"]

    if rf is None:
        return []

    if sample_std is None:
        sample_std = np.array([[std_dict.get(feat, 0.0) for feat in selected_features]])

    shap_impacts: Optional[List[float]] = None

    # 1. Primary: Use SHAP TreeExplainer on Random Forest for non-linear feature attribution
    try:
        import shap
        explainer = bundle.get("_rf_shap_explainer")
        if explainer is None:
            explainer = shap.TreeExplainer(rf)
            bundle["_rf_shap_explainer"] = explainer

        shap_vals = explainer.shap_values(sample_std)
        # Binary classification SHAP values: extract class 1 (malicious)
        if isinstance(shap_vals, list) and len(shap_vals) > 1:
            shap_impacts = [float(v) for v in shap_vals[1][0]]
        elif hasattr(shap_vals, "ndim") and shap_vals.ndim == 3 and shap_vals.shape[2] > 1:
            shap_impacts = [float(v) for v in shap_vals[0, :, 1]]
        elif hasattr(shap_vals, "ndim") and shap_vals.ndim == 2:
            shap_impacts = [float(v) for v in shap_vals[0]]
    except Exception:
        shap_impacts = None

    drivers: List[FeatureDriver] = []
    for idx, feat in enumerate(selected_features):
        z_val = std_dict.get(feat, 0.0)
        raw_val = raw_features.get(feat, 0)

        if shap_impacts is not None and idx < len(shap_impacts):
            impact = shap_impacts[idx]
        elif hasattr(rf, "feature_importances_"):
            rf_imp = float(rf.feature_importances_[idx])
            impact = float(rf_imp * z_val)
        else:
            impact = 0.0

        direction = "↑" if impact > 0 else "↓"
        drivers.append({
            "feature": feat,
            "impact": round(impact, 4),
            "direction": direction,
            "raw_value": raw_val,
            "std_value": round(z_val, 4),
        })

    # Sort by absolute impact descending
    drivers.sort(key=lambda d: abs(d["impact"]), reverse=True)
    if n_top is not None and n_top > 0:
        return drivers[:n_top]
    return drivers


def run_inference(
    file_path: str | Path,
    fmt: str | None = None,
    n_top: Optional[int] = None,
    target_model: Optional[str] = None,
) -> InferenceResult:
    """
    Main inference entrypoint: extracts features, standardizes them,
    queries all 5 voting models (Random Forest, Decision Tree, Neural Network,
    XGBoost, LightGBM), and evaluates voting consensus or
    specific single-model prediction.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    if fmt is None:
        fmt = detect_format(path)
    fmt = fmt.lower()

    # 1. Load model bundle
    bundle = load_model_bundle(fmt)
    selected_features = bundle["selected_features"]
    scaler = bundle["scaler"]

    # 2. Extract raw features
    raw_features = extract_features(path, fmt)

    # 3. Standardize features
    sample_std, std_dict = standardize_features(raw_features, selected_features, scaler)

    # 4. Multi-model predictions across the 5 voting architectures
    model_registry: List[Tuple[str, Any]] = [
        ("Random Forest", bundle.get("rf_model")),
        ("Decision Tree", bundle.get("dt_model")),
        ("Neural Network", bundle.get("mlp_model")),
        ("XGBoost", bundle.get("xgb_model")),
        ("LightGBM", bundle.get("lgb_model")),
    ]

    predictions: List[ModelPrediction] = []
    for model_name, model_obj in model_registry:
        if model_obj is not None:
            prob = float(model_obj.predict_proba(sample_std)[0, 1])
            pred = int(prob >= 0.5)
            predictions.append({
                "model": model_name,
                "prediction": pred,
                "probability_malicious": round(prob, 4),
            })

    # Resolve target model filter if specified
    normalized_target: Optional[str] = None
    if target_model and target_model.strip().lower() not in ("all", "ensemble", "consensus"):
        key = target_model.strip().lower()
        normalized_target = MODEL_ALIASES.get(key, target_model.strip())
        matched = [p for p in predictions if p["model"].lower() == normalized_target.lower()]
        if not matched:
            available_names = [p["model"] for p in predictions]
            raise ValueError(
                f"Model '{target_model}' not available for format '{fmt}'. "
                f"Available models: {available_names}"
            )
        # Match exact casing from predictions
        normalized_target = matched[0]["model"]

    # 5. Consensus or Target Model Decision
    if normalized_target:
        target_pred = next(p for p in predictions if p["model"] == normalized_target)
        prob_target = target_pred["probability_malicious"]
        verdict = "MALICIOUS" if target_pred["prediction"] == 1 else "BENIGN"
        confidence = prob_target if verdict == "MALICIOUS" else (1.0 - prob_target)
        band = "HIGH" if confidence >= 0.85 else ("MEDIUM" if confidence >= 0.65 else "LOW")

        vote: VoteResult = {
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "confidence_band": band,
            "vote_counts": {"malicious": target_pred["prediction"], "benign": 1 - target_pred["prediction"]},
            "mean_probability": round(prob_target, 4),
            "uncertain": False,
            "target_model": normalized_target,
        }
    else:
        # Multimodal consensus voting across all 5 models
        voting_candidates = predictions

        malicious_votes = sum([p["prediction"] for p in voting_candidates])
        benign_votes = len(voting_candidates) - malicious_votes
        mean_prob = float(np.mean([p["probability_malicious"] for p in voting_candidates]))

        verdict = "MALICIOUS" if malicious_votes > (len(voting_candidates) / 2.0) else "BENIGN"
        confidence = mean_prob if verdict == "MALICIOUS" else (1.0 - mean_prob)
        band = "HIGH" if confidence >= 0.85 else ("MEDIUM" if confidence >= 0.65 else "LOW")
        uncertain = (malicious_votes != len(voting_candidates) and malicious_votes != 0)

        vote: VoteResult = {
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "confidence_band": band,
            "vote_counts": {"malicious": malicious_votes, "benign": benign_votes},
            "mean_probability": round(mean_prob, 4),
            "uncertain": uncertain,
            "target_model": "Ensemble (Consensus)",
        }

    # 6. Explainability drivers
    top_drivers = compute_risk_drivers(
        bundle, raw_features, std_dict, sample_std=sample_std, n_top=n_top
    )

    return {
        "file_name": path.name,
        "file_path": str(path),
        "format": fmt,
        "format_display": FORMAT_DISPLAY.get(fmt, fmt.upper()),
        "features": raw_features,
        "standardized_features": std_dict,
        "model_predictions": predictions,
        "vote": vote,
        "top_risk_drivers": top_drivers,
        "error": None,
    }
