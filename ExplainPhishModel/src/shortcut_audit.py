"""
STAGE 1.5 - SHORTCUT & STATISTICAL LEAKAGE AUDIT (TRAIN SPLIT ONLY)
===================================================================
Runs strictly on X_train, y_train AFTER the train/test split.
Never sees the test set.

Evaluates:
  1. Per-feature single-feature AUC (direction-invariant: max(auc, 1-auc))
  2. Depth-1 decision-stump 5-fold CV F1 score per feature
  3. Fitted Decision Tree depth, leaf count, and top feature importance share
  4. Missingness audit: AUC of is_missing indicator and path/structure missing shares by class
  5. Near-perfectly correlated feature pairs (|r| >= 0.98)
  6. likely_shortcut flag (depth-1 tree CV F1 >= 0.99 or top feature importance >= 0.90)
  7. Optional high-AUC feature removal (with < 3 features guard)
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold
from sklearn.tree import DecisionTreeClassifier

from config import config as cfg
from src.utils import ensure_dir, save_json


def audit_train_shortcuts(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    fmt: str,
    out_dir: Path,
    logger: logging.Logger,
    remove_high_auc: bool = False,
    auc_threshold: float = 0.985,
) -> tuple[dict, list[str]]:
    """
    Run shortcut and leakage audit strictly on training data.

    Returns
    -------
    audit_summary : dict
        Full audit dictionary saved to shortcut_audit.json.
    features_to_keep : list[str]
        List of surviving feature column names.
    """
    logger.info("=" * 60)
    logger.info(f"[{fmt.upper()}] Running Shortcut & Leakage Audit on TRAIN only ({len(X_train)} rows)")
    logger.info("=" * 60)

    # 1. Impute numeric features for modeling tests (strictly train statistics)
    numeric_cols = [c for c in X_train.columns if pd.api.types.is_numeric_dtype(X_train[c])]
    non_numeric_cols = [c for c in X_train.columns if c not in numeric_cols]
    if non_numeric_cols:
        logger.warning(f"  Non-numeric columns in training set: {non_numeric_cols}")

    imputer = SimpleImputer(strategy="median", keep_empty_features=True)
    X_imp = pd.DataFrame(imputer.fit_transform(X_train[numeric_cols]), columns=numeric_cols, index=X_train.index)

    # 2. Per-feature single-feature AUC & Depth-1 Decision Stump 5-fold CV F1
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=cfg.RANDOM_STATE)
    feature_rows = []
    high_auc_features = []

    for col in numeric_cols:
        vals = X_imp[col]
        # Single-feature AUC
        try:
            raw_auc = roc_auc_score(y_train, vals)
            auc_strength = max(raw_auc, 1.0 - raw_auc)
        except ValueError:
            auc_strength = 0.5

        # Depth-1 Decision Stump 5-fold CV F1
        stump_f1_scores = []
        for tr_idx, val_idx in skf.split(X_imp, y_train):
            X_tr_f, X_val_f = X_imp.iloc[tr_idx][[col]], X_imp.iloc[val_idx][[col]]
            y_tr_f, y_val_f = y_train.iloc[tr_idx], y_train.iloc[val_idx]
            stump = DecisionTreeClassifier(max_depth=1, random_state=cfg.RANDOM_STATE)
            stump.fit(X_tr_f, y_tr_f)
            preds = stump.predict(X_val_f)
            stump_f1_scores.append(f1_score(y_val_f, preds, zero_division=0))
        mean_stump_f1 = float(np.mean(stump_f1_scores))

        is_high_auc = bool(auc_strength >= auc_threshold)
        if is_high_auc:
            high_auc_features.append(col)

        feature_rows.append({
            "feature": col,
            "single_feature_auc": round(auc_strength, 5),
            "stump_cv_f1_mean": round(mean_stump_f1, 5),
            "high_auc_flag": is_high_auc,
        })

    feature_audit_df = pd.DataFrame(feature_rows).sort_values("single_feature_auc", ascending=False).reset_index(drop=True)

    # 3. Decision Tree structural complexity & top feature dominance
    dt_full = DecisionTreeClassifier(random_state=cfg.RANDOM_STATE)
    dt_full.fit(X_imp, y_train)
    dt_depth = int(dt_full.get_depth())
    dt_leaves = int(dt_full.get_n_leaves())
    importances = dt_full.feature_importances_
    max_imp_idx = int(np.argmax(importances)) if len(importances) > 0 else 0
    top_feature_name = numeric_cols[max_imp_idx] if numeric_cols else "None"
    top_feature_share = float(importances[max_imp_idx]) if len(importances) > 0 else 0.0

    # 4. Missingness Audit
    missing_audit = {}
    missing_counts = X_train.isna().sum()
    cols_with_na = missing_counts[missing_counts > 0].index.tolist()
    
    missing_col_stats = []
    for col in cols_with_na:
        is_missing = X_train[col].isna().astype(int)
        if is_missing.nunique() > 1:
            try:
                raw_na_auc = roc_auc_score(y_train, is_missing)
                na_auc = max(raw_na_auc, 1.0 - raw_na_auc)
            except ValueError:
                na_auc = 0.5
        else:
            na_auc = 0.5
        missing_col_stats.append({
            "column": col,
            "missing_count": int(missing_counts[col]),
            "missing_pct": round(float(missing_counts[col] / len(X_train) * 100), 2),
            "is_missing_auc": round(float(na_auc), 5),
        })
    missing_audit["columns_with_missing"] = missing_col_stats

    # Specific audit for path_* and struct_* missingness
    path_cols = [c for c in X_train.columns if c.startswith("path_")]
    struct_cols = [c for c in X_train.columns if c.startswith("struct_")]
    
    if path_cols:
        b_any_na_path = float((X_train.loc[y_train == 0, path_cols].isna().any(axis=1)).mean())
        m_any_na_path = float((X_train.loc[y_train == 1, path_cols].isna().any(axis=1)).mean())
        b_all_na_path = float((X_train.loc[y_train == 0, path_cols].isna().all(axis=1)).mean())
        m_all_na_path = float((X_train.loc[y_train == 1, path_cols].isna().all(axis=1)).mean())
        missing_audit["path_missingness_by_class"] = {
            "path_column_count": len(path_cols),
            "benign_share_with_any_missing_path": round(b_any_na_path, 4),
            "malicious_share_with_any_missing_path": round(m_any_na_path, 4),
            "benign_share_with_all_missing_path": round(b_all_na_path, 4),
            "malicious_share_with_all_missing_path": round(m_all_na_path, 4),
        }
        # Explicit missingness indicator for path block (Task 4)
        path_block_missing = X_train[path_cols].isna().any(axis=1).astype(int)
        if path_block_missing.nunique() > 1:
            try:
                raw_path_na_auc = roc_auc_score(y_train, path_block_missing)
                path_na_auc = max(raw_path_na_auc, 1.0 - raw_path_na_auc)
            except ValueError:
                path_na_auc = 0.5
        else:
            path_na_auc = 0.5
        missing_audit["path_block_any_missing_indicator_auc"] = round(float(path_na_auc), 5)

    if struct_cols:
        b_any_na_struct = float((X_train.loc[y_train == 0, struct_cols].isna().any(axis=1)).mean())
        m_any_na_struct = float((X_train.loc[y_train == 1, struct_cols].isna().any(axis=1)).mean())
        missing_audit["struct_missingness_by_class"] = {
            "struct_column_count": len(struct_cols),
            "benign_share_with_any_missing_struct": round(b_any_na_struct, 4),
            "malicious_share_with_any_missing_struct": round(m_any_na_struct, 4),
        }

    # 5. Near-perfectly correlated feature pairs (|r| >= 0.98)
    corr_matrix = X_imp.corr().abs()
    high_corr_pairs = []
    cols_corr = list(X_imp.columns)
    for i in range(len(cols_corr)):
        for j in range(i + 1, len(cols_corr)):
            c1, c2 = cols_corr[i], cols_corr[j]
            val = corr_matrix.loc[c1, c2]
            if not np.isnan(val) and val >= 0.98:
                high_corr_pairs.append({
                    "feature_1": c1,
                    "feature_2": c2,
                    "correlation": round(float(val), 5),
                })
    high_corr_pairs = sorted(high_corr_pairs, key=lambda x: x["correlation"], reverse=True)

    # 6. Shortcut detection rule:
    # True when any depth-1 tree reaches CV F1 >= 0.99 OR one feature holds >= 0.90 of tree importance
    any_stump_ge_99 = any(r["stump_cv_f1_mean"] >= 0.99 for r in feature_rows)
    single_feature_dominates = (top_feature_share >= 0.90)
    likely_shortcut = bool(any_stump_ge_99 or single_feature_dominates)

    if likely_shortcut:
        logger.warning(
            f"  [SHORTCUT WARNING] {fmt.upper()} data exhibits likely shortcut learning! "
            f"Any stump CV F1 >= 0.99: {any_stump_ge_99} | "
            f"Top feature '{top_feature_name}' holds {top_feature_share:.1%} of tree importance."
        )

    # 7. High-AUC feature removal logic (if configured)
    features_to_keep = list(X_train.columns)
    removed_high_auc = []
    if remove_high_auc:
        candidate_keep = [c for c in features_to_keep if c not in high_auc_features]
        if len(candidate_keep) < 3:
            msg = (
                f"[{fmt.upper()}] High-AUC feature removal would drop {len(high_auc_features)} features, "
                f"leaving only {len(candidate_keep)} features (minimum 3 required). "
                f"High-AUC features: {high_auc_features}. Pipeline stopped."
            )
            logger.error(msg)
            raise ValueError(msg)
        removed_high_auc = high_auc_features
        features_to_keep = candidate_keep
        logger.info(
            f"  [LEAKAGE REMOVAL] Removed {len(removed_high_auc)} features with train AUC >= {auc_threshold}: "
            f"{removed_high_auc}. Remaining features: {len(features_to_keep)}"
        )

    audit_summary = {
        "format": fmt,
        "n_train_samples": len(X_train),
        "n_features_evaluated": len(numeric_cols),
        "likely_shortcut": likely_shortcut,
        "shortcut_criteria": {
            "any_depth1_stump_cv_f1_ge_0_99": any_stump_ge_99,
            "top_feature_importance_ge_0_90": single_feature_dominates,
        },
        "decision_tree_diagnostics": {
            "fitted_depth": dt_depth,
            "fitted_leaves": dt_leaves,
            "top_feature": top_feature_name,
            "top_feature_importance_share": round(top_feature_share, 5),
        },
        "high_auc_features_found": high_auc_features,
        "high_auc_features_removed": removed_high_auc,
        "n_features_surviving": len(features_to_keep),
        "missingness_audit": missing_audit,
        "near_perfect_correlations_count": len(high_corr_pairs),
        "near_perfect_correlations": high_corr_pairs[:20],
        "top_10_features_by_auc": feature_rows[:10],
    }

    # Save outputs
    out_dir = ensure_dir(out_dir)
    save_json(audit_summary, out_dir / "shortcut_audit.json")
    feature_audit_df.to_csv(out_dir / "shortcut_audit.csv", index=False)
    logger.info(f"  Shortcut audit saved to {out_dir / 'shortcut_audit.json'} and .csv")

    return audit_summary, features_to_keep
