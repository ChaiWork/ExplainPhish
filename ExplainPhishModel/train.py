"""
ExplainPhish training pipeline.
Usage:  python train.py --format pdf | word | excel | html | all
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # so 'config' and 'src' can be imported

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from config import config as cfg
from src.balancing import check_and_balance
from src.data_stabilization import load_dataset, stabilize
from src.evaluation import (aggregate_all_formats, compute_metrics,
                            save_confusion_matrix, save_feature_importance)
from src.explainability import run_shap
from src.feature_selection import select_features
from src.models import MODEL_DISPLAY, MODEL_KEYS, build_model, save_model
from src.preprocessing import fit_preprocessor, transform_with_bundle
from src.shortcut_audit import audit_train_shortcuts
from src.training import cross_validate_model, train_final, tune_model
from src.utils import Timer, ensure_dir, get_logger, save_json


def run_pipeline(fmt, results_root=None, models_root=None, custom_df=None):
    results_base = Path(results_root) if results_root else cfg.RESULTS_DIR
    models_base = Path(models_root) if models_root else cfg.MODELS_DIR

    logger = get_logger(f"explainphish.{fmt}", cfg.LOGS_DIR / f"{fmt}_training.log")
    logger.info("=" * 70)
    logger.info(f"ExplainPhish pipeline - format: {cfg.FORMAT_DISPLAY[fmt]}")
    logger.info("=" * 70)
    results_dir = ensure_dir(results_base / fmt)
    models_dir = ensure_dir(models_base / fmt)
    summary = {"format": fmt, "random_state": cfg.RANDOM_STATE}

    with Timer() as total_timer:
        # 1. Data stabilization ------------------------------------------------
        if custom_df is not None:
            raw = custom_df.copy()
            if "__source_file__" not in raw.columns:
                raw["__source_file__"] = f"{fmt}_custom.csv"
            logger.info(f"Using custom DataFrame: {raw.shape[0]} rows x {raw.shape[1] - 1} columns")
        else:
            raw = load_dataset(fmt, logger)
        X, y, stab_report = stabilize(raw, fmt, ensure_dir(results_dir / "stabilization"), logger)
        summary["stabilization"] = {k: stab_report.get(k, 0) for k in (
            "rows_before_cleaning", "rows_after_cleaning", "columns_before_cleaning", "columns_after_cleaning",
            "exact_duplicates_removed", "feature_duplicates_removed", "conflicting_label_rows",
            "total_missing_cells", "columns_with_missing", "label_column")}

        # 2. Class balancing ---------------------------------------------------
        X, y, balance_info = check_and_balance(X, y, logger)
        summary["class_balance"] = balance_info

        # 3. Stratified 60/40 split ---------------------------------------------
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            X, y, test_size=cfg.TEST_SIZE, stratify=y, random_state=cfg.RANDOM_STATE)
        summary["split"] = {"train_size": len(y_train), "test_size": len(y_test),
                            "train_malicious": int(y_train.sum()), "test_malicious": int(y_test.sum())}
        logger.info(f"Split: train={len(y_train)}, test={len(y_test)} (test set is untouched until final evaluation)")

        # 3.5. Shortcut Audit on TRAIN only -------------------------------------
        audit_summary, features_to_keep = audit_train_shortcuts(
            X_train_raw, y_train, fmt, results_dir, logger,
            remove_high_auc=cfg.REMOVE_HIGH_AUC_FEATURES,
            auc_threshold=cfg.LEAKAGE_AUC_REMOVE
        )
        summary["shortcut_audit"] = audit_summary
        if cfg.REMOVE_HIGH_AUC_FEATURES:
            X_train_raw = X_train_raw[features_to_keep]
            X_test_raw = X_test_raw[features_to_keep]
            logger.info(f"Features after train-only leakage removal: {len(features_to_keep)}")

        # 4. Preprocessing fitted on TRAIN only --------------------------------
        bundle = fit_preprocessor(X_train_raw)
        X_train_all = transform_with_bundle(X_train_raw, bundle, select=False)
        X_test_all = transform_with_bundle(X_test_raw, bundle, select=False)

        # 5. Feature selection on TRAIN only -------------------------------------
        selected, selection_info, ranking = select_features(X_train_all, y_train, fmt, logger)
        bundle["selected_features"] = selected
        X_train, X_test = X_train_all[selected], X_test_all[selected]
        if ranking is not None:
            ranking.to_csv(results_dir / "feature_ranking_train_only.csv", index=False)
        selection_info["selected_features"] = selected
        save_json(selection_info, models_dir / "selected_features.json")
        save_json(selection_info, results_dir / "selected_features.json")
        joblib.dump(bundle, models_dir / "preprocessing.joblib")
        summary["feature_selection"] = selection_info

        # 6-8. CV, final training, evaluation, importance, SHAP ---------------
        logger.info("--- MODEL PARAMETERS ---")
        logger.info("")
        logger.info("XGBoost:")
        for k in ("n_estimators", "max_depth", "learning_rate", "subsample", "colsample_bytree", "min_child_weight", "reg_alpha", "reg_lambda"):
            logger.info(f"{k}={cfg.XGB_PARAMS.get(k)}")
        logger.info("")
        logger.info("Random Forest:")
        for k in ("n_estimators", "max_depth", "min_samples_leaf", "min_samples_split", "max_features"):
            logger.info(f"{k}={cfg.RF_PARAMS.get(k)}")
        logger.info("")
        logger.info("Decision Tree:")
        for k in ("max_depth", "min_samples_leaf", "min_samples_split"):
            logger.info(f"{k}={cfg.DT_PARAMS.get(k)}")
        logger.info("")

        metric_rows, model_details = [], {}
        predictions = pd.DataFrame({"y_true": y_test.to_numpy()}, index=range(len(y_test)))
        for key in MODEL_KEYS:
            name = MODEL_DISPLAY[key]
            logger.info(f"--- {name} ---")
            model = build_model(key)
            details = {}
            if cfg.TUNE_HYPERPARAMETERS:
                model, details["best_params_from_cv"] = tune_model(key, model, X_train, y_train, logger)
            details.update(cross_validate_model(model, X_train, y_train))
            logger.info(f"  {cfg.CV_FOLDS}-fold CV F1 = {details['cv_f1_mean']} +/- {details['cv_f1_std']}")
            model, details["train_seconds"] = train_final(model, X_train, y_train)
            details["parameters"] = model.get_params()

            # The untouched test set is used ONCE here.
            proba = model.predict_proba(X_test)[:, 1]
            pred = (proba >= 0.5).astype(int)
            metrics = compute_metrics(y_test.to_numpy(), pred, proba)
            logger.info(f"  TEST: acc={metrics['Accuracy']:.4f} recall={metrics['Recall']:.4f} "
                        f"FPR={metrics['FPR']:.4f} AUC={metrics['ROC-AUC']:.4f}")
            metric_rows.append({"Format": cfg.FORMAT_DISPLAY[fmt], "Model": name,
                                **{k: (round(v, 4) if isinstance(v, float) else v) for k, v in metrics.items()}})
            predictions[f"{key}_prediction"] = pred
            predictions[f"{key}_probability_malicious"] = proba.round(4)

            # Per-model subfolder: results/<fmt>/<key>/
            model_dir = ensure_dir(results_dir / key)

            save_model(key, model, models_dir)
            save_confusion_matrix(metrics, model_dir / f"{key}_confusion_matrix.png",
                                  f"{cfg.FORMAT_DISPLAY[fmt]} - {name}")
            save_feature_importance(model, selected, model_dir / f"{key}_feature_importance.csv",
                                    model_dir / f"{key}_feature_importance.png",
                                    f"{cfg.FORMAT_DISPLAY[fmt]} - {name} feature importance")
            try:
                run_shap(key, model, X_test, y_test, model_dir, logger)
            except Exception as error:   # keep going even if SHAP fails for one model
                logger.warning(f"  SHAP failed for {name}: {error}")
                details["shap_error"] = str(error)
            model_details[key] = details

        # 9. Ensemble Diversity Diagnostics (Task 6) -------------------------
        y_test_arr = y_test.to_numpy()
        pred_xgb = predictions["xgb_prediction"].to_numpy()
        pred_rf = predictions["rf_prediction"].to_numpy()
        pred_dt = predictions["dt_prediction"].to_numpy()

        disagree_xgb_rf = float(np.mean(pred_xgb != pred_rf))
        disagree_xgb_dt = float(np.mean(pred_xgb != pred_dt))
        disagree_rf_dt = float(np.mean(pred_rf != pred_dt))
        mean_pairwise_disagreement = float(np.mean([disagree_xgb_rf, disagree_xgb_dt, disagree_rf_dt]))

        # Error vectors (1 if error, 0 if correct)
        err_xgb = (pred_xgb != y_test_arr).astype(int)
        err_rf = (pred_rf != y_test_arr).astype(int)
        err_dt = (pred_dt != y_test_arr).astype(int)

        def safe_corr(a, b):
            if np.std(a) == 0 or np.std(b) == 0:
                return 1.0 if np.array_equal(a, b) else 0.0
            val = np.corrcoef(a, b)[0, 1]
            return float(np.nan_to_num(val, nan=0.0))

        error_corr_xgb_rf = round(safe_corr(err_xgb, err_rf), 4)
        error_corr_xgb_dt = round(safe_corr(err_xgb, err_dt), 4)
        error_corr_rf_dt = round(safe_corr(err_rf, err_dt), 4)

        all_wrong_mask = (pred_xgb != y_test_arr) & (pred_rf != y_test_arr) & (pred_dt != y_test_arr)
        all_models_wrong_count = int(all_wrong_mask.sum())
        all_models_wrong_pct = round(float(all_models_wrong_count / max(len(y_test_arr), 1) * 100), 2)

        identical_predictions = bool((pred_xgb == pred_rf).all() and (pred_rf == pred_dt).all())
        if identical_predictions:
            logger.warning("  [ENSEMBLE WARNING] All three models produced 100% IDENTICAL predictions on test rows! Pairwise disagreement = 0.0.")

        ensemble_diagnostics = {
            "mean_pairwise_disagreement": round(mean_pairwise_disagreement, 4),
            "pairwise_disagreement": {
                "xgb_vs_rf": round(disagree_xgb_rf, 4),
                "xgb_vs_dt": round(disagree_xgb_dt, 4),
                "rf_vs_dt": round(disagree_rf_dt, 4),
            },
            "error_correlations": {
                "xgb_vs_rf": error_corr_xgb_rf,
                "xgb_vs_dt": error_corr_xgb_dt,
                "rf_vs_dt": error_corr_rf_dt,
            },
            "all_models_wrong_count": all_models_wrong_count,
            "all_models_wrong_pct": all_models_wrong_pct,
            "predictions_100pct_identical": identical_predictions,
        }
        summary["ensemble_diversity"] = ensemble_diagnostics
        logger.info(f"Ensemble Diversity: mean disagreement = {mean_pairwise_disagreement:.2%}, all models wrong = {all_models_wrong_count}")

        # 10. Save results -----------------------------------------------------
        table = pd.DataFrame(metric_rows)
        table.to_csv(results_dir / "metrics.csv", index=False)
        predictions.to_csv(results_dir / "test_predictions.csv", index=False)
        summary["models"] = model_details
        summary["test_metrics"] = metric_rows
    summary["total_training_seconds"] = total_timer.seconds
    save_json(summary, results_dir / "training_summary.json")
    aggregate_all_formats(results_base)
    logger.info(f"Finished {cfg.FORMAT_DISPLAY[fmt]} in {total_timer.seconds}s. Results: {results_dir}")
    return table


def main():
    parser = argparse.ArgumentParser(description="ExplainPhish training pipeline")
    parser.add_argument("--format", required=True, choices=cfg.FORMATS + ["all"])
    parser.add_argument("--tune", action="store_true", help="grid-search hyperparameters with 5-fold CV on train")
    parser.add_argument("--feature-mode", choices=["auto", "provided", "own", "all"], help="override FEATURE_SELECTION_MODE")
    parser.add_argument("--missing-strategy", choices=["median", "remove"], default=None,
                        help="Strategy for missing values: 'median' (impute with train median) or 'remove' (drop rows with missing)")
    parser.add_argument("--drop-duplicates", action="store_true", default=False,
                        help="Drop duplicate rows/features (default: False, keep original dataset)")
    parser.add_argument("--remove-high-auc", action="store_true", default=False,
                        help="Remove high-AUC shortcut features on train split (AUC >= LEAKAGE_AUC_REMOVE)")
    parser.add_argument("--results-dir", type=str, default=None, help="Custom results output directory root")
    parser.add_argument("--models-dir", type=str, default=None, help="Custom models output directory root")
    args = parser.parse_args()
    if args.tune:
        cfg.TUNE_HYPERPARAMETERS = True
    if args.feature_mode:
        cfg.FEATURE_SELECTION_MODE = args.feature_mode
    if args.missing_strategy:
        cfg.MISSING_STRATEGY = args.missing_strategy
    if args.drop_duplicates:
        cfg.DROP_EXACT_DUPLICATES = True
        cfg.DROP_FEATURE_DUPLICATES = True
    if args.remove_high_auc:
        cfg.REMOVE_HIGH_AUC_FEATURES = True

    results_root = Path(args.results_dir) if args.results_dir else cfg.RESULTS_DIR
    models_root = Path(args.models_dir) if args.models_dir else cfg.MODELS_DIR

    formats = cfg.FORMATS if args.format == "all" else [args.format]
    failed = []
    for fmt in formats:
        try:
            run_pipeline(fmt, results_root=results_root, models_root=models_root)
        except Exception as error:
            print(f"\n[ERROR] {fmt} failed: {error}")
            failed.append(fmt)
            if len(formats) == 1:
                raise
    if failed:
        print(f"\nFormats that failed: {failed}")
        sys.exit(1)


if __name__ == "__main__":
    main()
