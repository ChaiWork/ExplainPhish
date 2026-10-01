"""
Ablation Experiment Suite for ExplainPhish
==========================================
Usage:  python ablation.py --format <pdf|word|excel|html|all>

Evaluates model performance under 5 feature sets:
  a. baseline (all cleaned features)
  b. without_macro_ole_dde (ole_object_count, ole_object_type_count, macro_present, vba_keywords_count, dde_present)
  c. without_format_proxies (entropy, file_size, struct_pos, struct_ContentType, struct_PartName)
  d. without_macro_and_proxies (without both b and c; only if >= 3 features remain)
  e. without_audit_high_risk (without all features flagged high-risk by the train-only audit; only if >= 3 remain)

Metrics:
  - 5-Fold Stratified CV on TRAIN only: mean +/- std for Acc, Prec, Rec, F1, ROC-AUC, FPR
  - Test set metrics (for reporting only, labelled 'not used for selection')
Output:
  results/<format>/ablation.csv
"""
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score,
    recall_score, roc_auc_score
)
from sklearn.model_selection import StratifiedKFold, train_test_split

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import config as cfg
from src.balancing import check_and_balance
from src.data_stabilization import load_dataset, stabilize
from src.models import MODEL_DISPLAY, MODEL_KEYS, build_model
from src.shortcut_audit import audit_train_shortcuts
from src.utils import ensure_dir, get_logger


def match_cols_case_insensitive(columns: List[str], targets: List[str]) -> List[str]:
    """Find columns matching any target name case-insensitively."""
    target_set = {t.lower().strip() for t in targets}
    return [c for c in columns if c.lower().strip() in target_set]


def evaluate_feature_subset(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    feature_cols: List[str],
    variant_name: str,
    fmt: str,
    logger,
) -> List[dict]:
    """Evaluate all 3 models using 5-fold CV on train, then evaluate on test set for reporting."""
    X_tr = X_train[feature_cols].copy()
    X_te = X_test[feature_cols].copy()

    # Learn median imputation strictly on train
    imputer = SimpleImputer(strategy="median", keep_empty_features=True)
    X_tr_imp = pd.DataFrame(imputer.fit_transform(X_tr), columns=feature_cols, index=X_tr.index)
    X_te_imp = pd.DataFrame(imputer.transform(X_te), columns=feature_cols, index=X_te.index)

    skf = StratifiedKFold(n_splits=cfg.CV_FOLDS, shuffle=True, random_state=cfg.RANDOM_STATE)
    rows = []

    for key in MODEL_KEYS:
        model_name = MODEL_DISPLAY[key]
        cv_acc, cv_prec, cv_rec, cv_f1, cv_auc, cv_fpr = [], [], [], [], [], []

        # 5-fold Stratified CV on train only
        for train_idx, val_idx in skf.split(X_tr_imp, y_train):
            X_fold_tr, X_fold_val = X_tr_imp.iloc[train_idx], X_tr_imp.iloc[val_idx]
            y_fold_tr, y_fold_val = y_train.iloc[train_idx], y_train.iloc[val_idx]

            fold_model = build_model(key)
            fold_model.fit(X_fold_tr, y_fold_tr)

            proba = fold_model.predict_proba(X_fold_val)[:, 1]
            pred = (proba >= 0.5).astype(int)

            tn, fp, fn, tp = confusion_matrix(y_fold_val, pred, labels=[0, 1]).ravel()
            cv_acc.append(accuracy_score(y_fold_val, pred))
            cv_prec.append(precision_score(y_fold_val, pred, zero_division=0))
            cv_rec.append(recall_score(y_fold_val, pred, zero_division=0))
            cv_f1.append(f1_score(y_fold_val, pred, zero_division=0))
            try:
                cv_auc.append(roc_auc_score(y_fold_val, proba))
            except ValueError:
                cv_auc.append(0.5)
            cv_fpr.append(fp / (fp + tn) if (fp + tn) > 0 else 0.0)

        # Final fit on train and evaluate on untouched test set for reporting only
        final_model = build_model(key)
        final_model.fit(X_tr_imp, y_train)
        test_proba = final_model.predict_proba(X_te_imp)[:, 1]
        test_pred = (test_proba >= 0.5).astype(int)
        tn_te, fp_te, fn_te, tp_te = confusion_matrix(y_test, test_pred, labels=[0, 1]).ravel()

        try:
            test_auc = roc_auc_score(y_test, test_proba)
        except ValueError:
            test_auc = 0.5
        test_fpr = fp_te / (fp_te + tn_te) if (fp_te + tn_te) > 0 else 0.0

        rows.append({
            "Format": cfg.FORMAT_DISPLAY[fmt],
            "Variant": variant_name,
            "Model": model_name,
            "N_Features": len(feature_cols),
            "CV_F1_Mean": round(float(np.mean(cv_f1)), 4),
            "CV_F1_Std": round(float(np.std(cv_f1)), 4),
            "CV_AUC_Mean": round(float(np.mean(cv_auc)), 4),
            "CV_AUC_Std": round(float(np.std(cv_auc)), 4),
            "CV_Accuracy_Mean": round(float(np.mean(cv_acc)), 4),
            "CV_Precision_Mean": round(float(np.mean(cv_prec)), 4),
            "CV_Recall_Mean": round(float(np.mean(cv_rec)), 4),
            "CV_FPR_Mean": round(float(np.mean(cv_fpr)), 4),
            "Test_F1 (not used for selection)": round(f1_score(y_test, test_pred, zero_division=0), 4),
            "Test_AUC (not used for selection)": round(float(test_auc), 4),
            "Test_Accuracy (not used for selection)": round(accuracy_score(y_test, test_pred), 4),
            "Test_FPR (not used for selection)": round(float(test_fpr), 4),
        })

    return rows


def run_ablation_for_format(fmt: str):
    logger = get_logger(f"ablation.{fmt}", cfg.LOGS_DIR / f"{fmt}_ablation.log")
    logger.info("=" * 70)
    logger.info(f"Running Ablation Experiments for {cfg.FORMAT_DISPLAY[fmt]}")
    logger.info("=" * 70)

    results_dir = ensure_dir(cfg.RESULTS_DIR / fmt)

    # 1. Stabilization & Balancing
    raw = load_dataset(fmt, logger)
    X, y, _ = stabilize(raw, fmt, ensure_dir(results_dir / "stabilization"), logger)
    X, y, _ = check_and_balance(X, y, logger)

    # 2. Stratified 60/40 Split
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X, y, test_size=cfg.TEST_SIZE, stratify=y, random_state=cfg.RANDOM_STATE
    )

    # 3. Train-only Shortcut Audit (identifies high-risk features)
    audit_summary, _ = audit_train_shortcuts(
        X_train_raw, y_train, fmt, results_dir, logger,
        remove_high_auc=False, auc_threshold=cfg.LEAKAGE_AUC_REMOVE
    )
    audit_flagged_features = audit_summary.get("high_auc_features_found", [])

    all_cols = list(X_train_raw.columns)
    logger.info(f"Total cleaned features available: {len(all_cols)}")

    # Target sets for variants b and c
    macro_targets = ["ole_object_count", "ole_object_type_count", "macro_present", "vba_keywords_count", "dde_present"]
    proxy_targets = ["entropy", "file_size", "struct_pos", "struct_ContentType", "struct_PartName"]

    matched_macro = match_cols_case_insensitive(all_cols, macro_targets)
    matched_proxy = match_cols_case_insensitive(all_cols, proxy_targets)

    logger.info(f"Matched macro/OLE/DDE features ({len(matched_macro)}): {matched_macro}")
    logger.info(f"Matched format proxy features ({len(matched_proxy)}): {matched_proxy}")
    logger.info(f"Audit-flagged high-risk features ({len(audit_flagged_features)}): {audit_flagged_features}")

    # Build variants
    variants = {}

    # Variant a: baseline (all cleaned features)
    variants["a_baseline"] = all_cols

    # Variant b: without macro/OLE/DDE
    b_cols = [c for c in all_cols if c not in matched_macro]
    if len(b_cols) >= 3 and len(matched_macro) > 0:
        variants["b_without_macro_ole_dde"] = b_cols
    else:
        logger.info("Variant b skipped: no macro/OLE features found or < 3 features remaining.")

    # Variant c: without format proxies
    c_cols = [c for c in all_cols if c not in matched_proxy]
    if len(c_cols) >= 3 and len(matched_proxy) > 0:
        variants["c_without_format_proxies"] = c_cols
    else:
        logger.info("Variant c skipped: no format proxies found or < 3 features remaining.")

    # Variant d: without both b and c
    d_cols = [c for c in all_cols if c not in matched_macro and c not in matched_proxy]
    if len(d_cols) >= 3 and (len(matched_macro) > 0 or len(matched_proxy) > 0):
        variants["d_without_macro_and_proxies"] = d_cols
    else:
        logger.info(f"Variant d skipped: < 3 features remain ({len(d_cols)} left) or no target features.")

    # Variant e: without audit-flagged high-risk features
    e_cols = [c for c in all_cols if c not in audit_flagged_features]
    if len(e_cols) >= 3 and len(audit_flagged_features) > 0:
        variants["e_without_audit_flagged"] = e_cols
    else:
        logger.info(f"Variant e skipped: < 3 features remain ({len(e_cols)} left) or no features flagged by audit.")

    ablation_rows = []
    for var_name, cols in variants.items():
        logger.info(f"--- Evaluating Variant: {var_name} ({len(cols)} features) ---")
        rows = evaluate_feature_subset(
            X_train_raw, y_train, X_test_raw, y_test,
            feature_cols=cols, variant_name=var_name, fmt=fmt, logger=logger
        )
        ablation_rows.extend(rows)

    out_csv = results_dir / "ablation.csv"
    df_res = pd.DataFrame(ablation_rows)
    df_res.to_csv(out_csv, index=False)
    logger.info(f"Saved ablation results to: {out_csv}")
    print(f"\n[{cfg.FORMAT_DISPLAY[fmt]}] Ablation Summary:")
    print(df_res[["Variant", "Model", "N_Features", "CV_F1_Mean", "CV_AUC_Mean", "Test_F1 (not used for selection)", "Test_AUC (not used for selection)"]].to_string(index=False))
    return df_res


def main():
    parser = argparse.ArgumentParser(description="ExplainPhish Ablation Suite")
    parser.add_argument("--format", required=True, choices=cfg.FORMATS + ["all"])
    args = parser.parse_args()

    formats = cfg.FORMATS if args.format == "all" else [args.format]
    for fmt in formats:
        run_ablation_for_format(fmt)


if __name__ == "__main__":
    main()
