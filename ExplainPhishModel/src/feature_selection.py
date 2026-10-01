"""
FEATURE SELECTION - uses the TRAINING set only ("less variables, better result").
Mode A: use the feature list supplied in config.PROVIDED_FEATURES.
Mode B: rank features by XGBoost importance + Random Forest importance + mean |SHAP|
        (all computed on training data) and keep the top N.
"""
import numpy as np
import pandas as pd

from config import config as cfg
from src.explainability import malicious_shap
from src.models import build_model


def _normalise(values):
    values = np.asarray(values, dtype=float)
    total = values.sum()
    return values / total if total > 0 else values


def select_features(X_train, y_train, fmt, logger):
    """Return (selected_feature_list, info_dict, ranking_table_or_None)."""
    mode = cfg.FEATURE_SELECTION_MODE
    provided = cfg.PROVIDED_FEATURES.get(fmt) or []

    # ---- Mode All: use all features from original dataset
    if mode == "all":
        cols = list(X_train.columns)
        logger.info(f"Feature selection mode 'all': using all {len(cols)} features from original dataset.")
        return cols, {"mode": "all", "n_features": len(cols)}, None

    # ---- Mode A
    if mode == "provided" or (mode == "auto" and provided):
        if not provided:
            raise ValueError(f"FEATURE_SELECTION_MODE='provided' but PROVIDED_FEATURES['{fmt}'] is empty.")
        missing = [f for f in provided if f not in X_train.columns]
        if missing:
            raise ValueError(f"Provided features not found in the cleaned data: {missing}\n"
                             f"Available columns: {list(X_train.columns)}")
        logger.info(f"Feature selection mode A: using {len(provided)} provided features.")
        return list(provided), {"mode": "provided", "n_features": len(provided)}, None

    # ---- Mode B
    top_n_cfg = cfg.TOP_N_FEATURES.get(fmt)
    if top_n_cfg in (None, "all", -1):
        top_n = X_train.shape[1]
    else:
        top_n = min(int(top_n_cfg), X_train.shape[1])
    logger.info(f"Feature selection mode B: ranking {X_train.shape[1]} features on TRAINING data, keeping top {top_n}.")
    xgb = build_model("xgb").fit(X_train, y_train)
    rf = build_model("rf").fit(X_train, y_train)
    ranking = pd.DataFrame({"feature": X_train.columns,
                            "xgb_importance": _normalise(xgb.feature_importances_),
                            "rf_importance": _normalise(rf.feature_importances_)})
    score_columns = ["xgb_importance", "rf_importance"]
    try:
        sample = X_train.sample(n=min(cfg.SHAP_SELECTION_SAMPLES, len(X_train)), random_state=cfg.RANDOM_STATE)
        values, _ = malicious_shap(xgb, sample)
        ranking["xgb_mean_abs_shap"] = _normalise(np.abs(values).mean(axis=0))
        score_columns.append("xgb_mean_abs_shap")
    except Exception as error:
        logger.warning(f"SHAP ranking skipped ({error}); using model importances only.")
    ranking["combined_score"] = ranking[score_columns].mean(axis=1)
    ranking = ranking.sort_values("combined_score", ascending=False).reset_index(drop=True)
    selected = ranking["feature"].head(top_n).tolist()
    logger.info(f"Selected features: {selected}")
    return selected, {"mode": "own (train-only importance + SHAP)", "n_features": len(selected),
                      "score_columns": score_columns}, ranking
