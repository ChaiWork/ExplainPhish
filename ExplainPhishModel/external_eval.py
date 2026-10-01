"""
External Evaluation Harness for ExplainPhish
============================================
Usage:  python external_eval.py --format <fmt> --csv <path_to_csv> [--models-dir <dir>]

Evaluates saved models and preprocessing pipeline on external, unseen feature CSVs.
Validates required columns against selected_features.json.
Reports standard metrics (Accuracy, Precision, Recall, F1, ROC-AUC, FPR) and
warns if either class has fewer than 50 samples.
"""
import argparse
import sys
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score,
    recall_score, roc_auc_score
)

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import config as cfg
from src.data_stabilization import find_label_column, normalize_labels
from src.models import MODEL_DISPLAY, MODEL_KEYS, load_model
from src.preprocessing import transform_with_bundle
from src.utils import get_logger, load_json

logger = get_logger("external_eval", None)


def evaluate_external_csv(fmt: str, csv_path: Path, models_dir: Path):
    if not csv_path.exists():
        raise FileNotFoundError(f"External CSV file not found: {csv_path}")

    fmt_models_dir = models_dir / fmt
    if not fmt_models_dir.exists():
        raise FileNotFoundError(f"Models directory not found for format {fmt}: {fmt_models_dir}")

    # Load selected features & preprocessing bundle
    feat_json_path = fmt_models_dir / "selected_features.json"
    bundle_path = fmt_models_dir / "preprocessing.joblib"

    if not feat_json_path.exists():
        raise FileNotFoundError(f"Missing selected_features.json at: {feat_json_path}")
    if not bundle_path.exists():
        raise FileNotFoundError(f"Missing preprocessing.joblib at: {bundle_path}")

    feat_info = load_json(feat_json_path)
    selected_features = feat_info.get("selected_features", [])
    bundle = joblib.load(bundle_path)

    logger.info("=" * 70)
    logger.info(f"External Evaluation for [{cfg.FORMAT_DISPLAY[fmt]}]")
    logger.info(f"  CSV:    {csv_path}")
    logger.info(f"  Models: {fmt_models_dir}")
    logger.info(f"  Expected Features ({len(selected_features)}): {selected_features}")
    logger.info("=" * 70)

    # Read external CSV
    df = pd.read_csv(csv_path, low_memory=False)
    logger.info(f"Loaded external data: {len(df)} rows x {df.shape[1]} columns")

    # Locate and normalize labels
    label_col = find_label_column(df)
    if label_col is None:
        raise ValueError(
            f"No label column found in {csv_path.name}. "
            f"Expected one of: {cfg.LABEL_COLUMN_CANDIDATES}"
        )

    y, label_rep = normalize_labels(df[label_col])
    valid_mask = y.notna()
    df = df.loc[valid_mask].copy()
    y = y[valid_mask].astype(int)

    # Validate class counts
    counts = y.value_counts().to_dict()
    benign_count = counts.get(0, 0)
    malicious_count = counts.get(1, 0)
    logger.info(f"Label distribution: Benign (0) = {benign_count}, Malicious (1) = {malicious_count}")

    if benign_count < 50 or malicious_count < 50:
        logger.warning(
            f"  [SAMPLE SIZE WARNING] External dataset has fewer than 50 samples in a class "
            f"(Benign={benign_count}, Malicious={malicious_count}). "
            f"Metrics will exhibit high statistical uncertainty."
        )

    # Drop target column
    X_raw = df.drop(columns=[label_col], errors="ignore")

    # Verify required feature columns are present
    missing_features = [f for f in selected_features if f not in X_raw.columns]
    if missing_features:
        raise ValueError(
            f"External CSV is missing {len(missing_features)} required feature(s):\n"
            f"  Missing: {missing_features}\n"
            f"  Available: {list(X_raw.columns)}"
        )

    # Transform features with preprocessor bundle
    X_proc = transform_with_bundle(X_raw, bundle, select=True)

    results = []
    y_arr = y.to_numpy()

    for key in MODEL_KEYS:
        name = MODEL_DISPLAY[key]
        try:
            model = load_model(key, fmt_models_dir)
        except Exception as error:
            logger.warning(f"Could not load {name} from {fmt_models_dir}: {error}")
            continue

        proba = model.predict_proba(X_proc)[:, 1]
        pred = (proba >= 0.5).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_arr, pred, labels=[0, 1]).ravel()
        try:
            auc = roc_auc_score(y_arr, proba)
        except ValueError:
            auc = 0.5
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        res_row = {
            "Format": cfg.FORMAT_DISPLAY[fmt],
            "Model": name,
            "Samples": len(y_arr),
            "Benign": benign_count,
            "Malicious": malicious_count,
            "Accuracy": round(accuracy_score(y_arr, pred), 4),
            "Precision": round(precision_score(y_arr, pred, zero_division=0), 4),
            "Recall": round(recall_score(y_arr, pred, zero_division=0), 4),
            "F1": round(f1_score(y_arr, pred, zero_division=0), 4),
            "ROC-AUC": round(float(auc), 4),
            "FPR": round(float(fpr), 4),
            "TN": int(tn),
            "FP": int(fp),
            "FN": int(fn),
            "TP": int(tp),
        }
        results.append(res_row)

    res_df = pd.DataFrame(results)
    print("\n" + res_df.to_string(index=False))
    return res_df


def main():
    parser = argparse.ArgumentParser(description="ExplainPhish External Evaluation Harness")
    parser.add_argument("--format", required=True, choices=cfg.FORMATS)
    parser.add_argument("--csv", required=True, type=str, help="Path to external CSV file")
    parser.add_argument("--models-dir", type=str, default=None, help="Custom models directory root")
    args = parser.parse_args()

    models_dir = Path(args.models_dir) if args.models_dir else cfg.MODELS_DIR
    evaluate_external_csv(args.format, Path(args.csv), models_dir)


if __name__ == "__main__":
    main()
