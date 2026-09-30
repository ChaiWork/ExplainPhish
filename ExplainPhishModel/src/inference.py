"""
ExplainPhish inference core.

Public API
----------
    result = run_inference(file_path)

    result is an InferenceResult dict:
    {
      "format":              "excel",
      "format_display":      "Excel",
      "features":            {"entropy_of_text": 4.87, ...},  # raw extracted features
      "model_predictions":   [{"model": ..., "prediction": ..., "probability_malicious": ...}, ...],
      "vote":                VoteResult,            # see src/voting.py
      "shap_top_features":   [{"feature": "macro_chr_count", "shap_value": 0.43}, ...],
      "error":               None | str,            # set only if something fails gracefully
    }

Lower-level helpers are also importable:
    load_format_models(fmt)          – load models + preprocessing bundle for one format
    predict_all_models(loaded, df)   – run all three models on a pre-built features DataFrame
    get_shap_top_features(...)       – extract top SHAP contributors for the LLM explainer
"""
from __future__ import annotations

import traceback
from pathlib import Path
from typing import Optional, TypedDict

import joblib
import numpy as np
import pandas as pd

from config import config as cfg
from src.models import MODEL_KEYS, load_model, predict_with_model
from src.preprocessing import transform_with_bundle
from src.router import detect_format
from src.voting import VoteResult, majority_vote

# Feature extractors are imported lazily (inside run_inference) so that
# optional heavy dependencies (openpyxl, fitz, bs4, …) only fail at runtime
# if the matching format is actually requested.


# ─── types ────────────────────────────────────────────────────────────────────

class InferenceResult(TypedDict):
    format: str
    format_display: str
    features: dict
    model_predictions: list[dict]
    vote: VoteResult
    shap_top_features: list[dict]
    error: Optional[str]


# ─── model loading ────────────────────────────────────────────────────────────

def load_format_models(fmt: str) -> dict:
    """
    Load the three trained models and the preprocessing bundle for *fmt*.
    Returns a dict suitable for passing to predict_all_models().
    """
    folder = cfg.MODELS_DIR / fmt
    if not folder.is_dir():
        raise FileNotFoundError(
            f"No model folder found for format '{fmt}'. "
            f"Expected: {folder}  — run train.py first."
        )
    return {
        "fmt":            fmt,
        "models":         {key: load_model(key, folder) for key in MODEL_KEYS},
        "preprocessing":  joblib.load(folder / "preprocessing.joblib"),
    }


# ─── prediction ───────────────────────────────────────────────────────────────

def predict_all_models(loaded: dict, features_df: pd.DataFrame) -> list[dict]:
    """
    Run all three models on a one-row DataFrame of raw extracted features.

    Parameters
    ----------
    loaded       : dict returned by load_format_models()
    features_df  : pd.DataFrame with ONE row and the same column names
                   as the training data (before preprocessing).

    Returns
    -------
    list of {"model": str, "prediction": int, "probability_malicious": float}
    """
    X = transform_with_bundle(features_df, loaded["preprocessing"])
    return [
        predict_with_model(key, model, X)[0]
        for key, model in loaded["models"].items()
    ]


# ─── SHAP top-feature extraction ──────────────────────────────────────────────

def get_shap_top_features(
    loaded: dict,
    features_df: pd.DataFrame,
    model_key: str = "xgb",
    n_top: int = 5,
) -> list[dict]:
    """
    Compute SHAP values for a single file and return the top *n_top* drivers.

    Uses XGBoost by default (fastest and most reliable SHAP support).
    Falls back to an empty list if shap is not installed or the call fails.

    Returns
    -------
    list of {"feature": str, "shap_value": float, "direction": "↑"|"↓"}
      sorted by |shap_value| descending.
    """
    try:
        import shap  # optional dependency

        model = loaded["models"][model_key]
        X = transform_with_bundle(features_df, loaded["preprocessing"])

        explainer = shap.TreeExplainer(model)
        shap_vals = explainer.shap_values(X)

        # shap_vals shape: (1, n_features)  — single row
        vals = np.array(shap_vals[0]) if isinstance(shap_vals, list) else np.array(shap_vals).flatten()
        feature_names = list(X.columns)

        paired = sorted(
            zip(feature_names, vals.tolist()),
            key=lambda x: abs(x[1]),
            reverse=True,
        )
        return [
            {
                "feature":    feat,
                "shap_value": round(float(val), 4),
                "direction":  "↑" if val > 0 else "↓",
            }
            for feat, val in paired[:n_top]
        ]
    except Exception:
        return []


# ─── feature extraction dispatch ──────────────────────────────────────────────

def _extract_features(fmt: str, file_path: Path) -> dict:
    """
    Dispatch to the correct static feature extractor for *fmt*.
    Returns a dict of {feature_name: value} matching the training columns.

    Each extractor lives in src/extractors/<fmt>_extractor.py and exposes:
        extract(file_path: Path) -> dict
    """
    # Dynamic import so missing optional deps only fail for the relevant format.
    import importlib
    module_name = f"src.extractors.{fmt}_extractor"
    try:
        mod = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        raise NotImplementedError(
            f"No extractor implemented for format '{fmt}'. "
            f"Expected module: {module_name}  ({exc})"
        ) from exc
    return mod.extract(file_path)


# ─── main entry point ─────────────────────────────────────────────────────────

def run_inference(
    file_path: str | Path,
    fmt: Optional[str] = None,
    loaded: Optional[dict] = None,
) -> InferenceResult:
    """
    Full end-to-end inference for a single file.

    Parameters
    ----------
    file_path : path to the uploaded file.
    fmt       : override format detection (e.g. "pdf"). If None, auto-detected.
    loaded    : pre-loaded model bundle (from load_format_models).
                Pass this when serving multiple requests for the same format
                to avoid reloading models on every call.

    Returns
    -------
    InferenceResult — always returns a dict; sets 'error' key on partial failure.
    """
    path = Path(file_path)
    result: InferenceResult = {
        "format":            "",
        "format_display":    "",
        "features":          {},
        "model_predictions": [],
        "vote":              {},            # type: ignore[assignment]
        "shap_top_features": [],
        "error":             None,
    }

    # ── 1. Format detection ────────────────────────────────────────────────────
    try:
        detected = fmt or detect_format(path)
        if detected is None:
            result["error"] = (
                f"Cannot determine file format for '{path.name}'. "
                "Supported: PDF, Word (.docx/.doc), Excel (.xlsx/.xlsb), HTML."
            )
            return result
        if detected not in cfg.FORMATS:
            result["error"] = f"Detected format '{detected}' is not supported."
            return result
        result["format"]         = detected
        result["format_display"] = cfg.FORMAT_DISPLAY[detected]
    except Exception as exc:
        result["error"] = f"Format detection failed: {exc}"
        return result

    fmt = result["format"]

    # ── 2. Feature extraction ──────────────────────────────────────────────────
    try:
        features = _extract_features(fmt, path)
        result["features"] = features
    except NotImplementedError as exc:
        result["error"] = str(exc)
        return result
    except Exception as exc:
        result["error"] = f"Feature extraction failed: {exc}\n{traceback.format_exc()}"
        return result

    # ── 3. Load models (if not pre-loaded) ────────────────────────────────────
    try:
        if loaded is None:
            loaded = load_format_models(fmt)
    except Exception as exc:
        result["error"] = f"Model loading failed: {exc}"
        return result

    # ── 4. Predict ────────────────────────────────────────────────────────────
    try:
        features_df = pd.DataFrame([features])
        preds = predict_all_models(loaded, features_df)
        result["model_predictions"] = preds
    except Exception as exc:
        result["error"] = f"Prediction failed: {exc}\n{traceback.format_exc()}"
        return result

    # ── 5. Vote ───────────────────────────────────────────────────────────────
    try:
        result["vote"] = majority_vote(preds)
    except Exception as exc:
        result["error"] = f"Voting failed: {exc}"
        return result

    # ── 6. SHAP top features (best-effort — does not abort on failure) ─────────
    try:
        result["shap_top_features"] = get_shap_top_features(loaded, features_df)
    except Exception:
        result["shap_top_features"] = []   # LLM explainer handles missing SHAP gracefully

    return result
