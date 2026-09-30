"""
ExplainPhish training pipeline.
Usage:  python train.py --format pdf | word | excel | html | all
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # so 'config' and 'src' can be imported

import joblib
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
from src.training import cross_validate_model, train_final, tune_model
from src.utils import Timer, ensure_dir, get_logger, save_json


def run_pipeline(fmt):
    logger = get_logger(f"explainphish.{fmt}", cfg.LOGS_DIR / f"{fmt}_training.log")
    logger.info("=" * 70)
    logger.info(f"ExplainPhish pipeline - format: {cfg.FORMAT_DISPLAY[fmt]}")
    logger.info("=" * 70)
    results_dir = ensure_dir(cfg.RESULTS_DIR / fmt)
    models_dir = ensure_dir(cfg.MODELS_DIR / fmt)
    summary = {"format": fmt, "random_state": cfg.RANDOM_STATE}

    with Timer() as total_timer:
        # 1. Data stabilization ------------------------------------------------
        raw = load_dataset(fmt, logger)
        X, y, stab_report = stabilize(raw, fmt, ensure_dir(results_dir / "stabilization"), logger)
        summary["stabilization"] = {k: stab_report[k] for k in (
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

        # 9. Save results ------------------------------------------------------
        table = pd.DataFrame(metric_rows)
        table.to_csv(results_dir / "metrics.csv", index=False)
        predictions.to_csv(results_dir / "test_predictions.csv", index=False)
        summary["models"] = model_details
        summary["test_metrics"] = metric_rows
    summary["total_training_seconds"] = total_timer.seconds
    save_json(summary, results_dir / "training_summary.json")
    aggregate_all_formats()
    logger.info(f"Finished {cfg.FORMAT_DISPLAY[fmt]} in {total_timer.seconds}s. Results: {results_dir}")
    return table


def main():
    parser = argparse.ArgumentParser(description="ExplainPhish training pipeline")
    parser.add_argument("--format", required=True, choices=cfg.FORMATS + ["all"])
    parser.add_argument("--tune", action="store_true", help="grid-search hyperparameters with 5-fold CV on train")
    parser.add_argument("--feature-mode", choices=["auto", "provided", "own"], help="override FEATURE_SELECTION_MODE")
    args = parser.parse_args()
    if args.tune:
        cfg.TUNE_HYPERPARAMETERS = True
    if args.feature_mode:
        cfg.FEATURE_SELECTION_MODE = args.feature_mode

    formats = cfg.FORMATS if args.format == "all" else [args.format]
    failed = []
    for fmt in formats:
        try:
            run_pipeline(fmt)
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
