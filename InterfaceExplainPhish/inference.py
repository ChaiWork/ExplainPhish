"""
InterfaceExplainPhish Core Inference Engine
============================================
Implements the 3-step standardized inference & multimodal consensus voting pipeline:
  1. Raw Feature Extraction (using format-specific extractors)
  2. StandardScaler Transformation (z = (x - mu_train) / sigma_train)
  3. Multi-Model Inferences (Random Forest, Decision Tree, Logistic Regression)
  4. Consensus Voting (Hard Majority Vote + Soft Probability Averaging + Risk Drivers)
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

    # Load artifacts
    rf_model = joblib.load(model_dir / "rf_model.joblib")
    dt_model = joblib.load(model_dir / "dt_model.joblib")
    lr_model = joblib.load(model_dir / "lr_model.joblib")
    scaler = joblib.load(model_dir / "scaler.joblib")

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
        "lr_model": lr_model,
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
    n_top: int = 5,
) -> List[FeatureDriver]:
    """
    Compute top decision drivers using Logistic Regression coefficients (w_j * z_j).
    Positive impact increases phishing probability, negative impact reduces it.
    """
    lr = bundle.get("lr_model")
    selected_features = bundle["selected_features"]
    
    if lr is None or not hasattr(lr, "coef_"):
        return []

    coefs = lr.coef_[0]
    drivers = []

    for idx, feat in enumerate(selected_features):
        z_val = std_dict.get(feat, 0.0)
        impact = float(coefs[idx] * z_val)
        direction = "↑" if impact > 0 else "↓"
        raw_val = raw_features.get(feat, 0)
        drivers.append({
            "feature": feat,
            "impact": round(impact, 4),
            "direction": direction,
            "raw_value": raw_val,
            "std_value": round(z_val, 4),
        })

    # Sort by absolute impact descending
    drivers.sort(key=lambda d: abs(d["impact"]), reverse=True)
    return drivers[:n_top]


def run_inference(file_path: str | Path, fmt: str | None = None) -> InferenceResult:
    """
    Main inference entrypoint: extracts features, standardizes them,
    queries all three models, and evaluates voting consensus.
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
    rf = bundle["rf_model"]
    dt = bundle["dt_model"]
    lr = bundle["lr_model"]

    # 2. Extract raw features
    raw_features = extract_features(path, fmt)

    # 3. Standardize features
    sample_std, std_dict = standardize_features(raw_features, selected_features, scaler)

    # 4. Multi-model predictions
    prob_rf = float(rf.predict_proba(sample_std)[0, 1])
    prob_dt = float(dt.predict_proba(sample_std)[0, 1])
    prob_lr = float(lr.predict_proba(sample_std)[0, 1])

    predictions: List[ModelPrediction] = [
        {"model": "Random Forest", "prediction": int(prob_rf >= 0.5), "probability_malicious": round(prob_rf, 4)},
        {"model": "Decision Tree", "prediction": int(prob_dt >= 0.5), "probability_malicious": round(prob_dt, 4)},
        {"model": "Logistic Regression", "prediction": int(prob_lr >= 0.5), "probability_malicious": round(prob_lr, 4)},
    ]

    # 5. Consensus voting
    malicious_votes = sum([p["prediction"] for p in predictions])
    benign_votes = len(predictions) - malicious_votes
    mean_prob = (prob_rf + prob_dt + prob_lr) / 3.0

    verdict = "MALICIOUS" if malicious_votes >= 2 else "BENIGN"
    confidence = mean_prob if verdict == "MALICIOUS" else (1.0 - mean_prob)
    band = "HIGH" if confidence >= 0.85 else ("MEDIUM" if confidence >= 0.65 else "LOW")
    uncertain = (malicious_votes in (1, 2))

    vote: VoteResult = {
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "confidence_band": band,
        "vote_counts": {"malicious": malicious_votes, "benign": benign_votes},
        "mean_probability": round(mean_prob, 4),
        "uncertain": uncertain,
    }

    # 6. Explainability drivers
    top_drivers = compute_risk_drivers(bundle, raw_features, std_dict, n_top=5)

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
