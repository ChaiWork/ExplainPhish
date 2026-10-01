"""Metrics, confusion matrices, feature-importance files and the comparison table."""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)

from config import config as cfg
from src.utils import save_json


def compute_metrics(y_true, y_pred, y_proba):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"Accuracy": accuracy_score(y_true, y_pred),
            "Precision": precision_score(y_true, y_pred, zero_division=0),
            "Recall": recall_score(y_true, y_pred, zero_division=0),   # malicious recall
            "F1": f1_score(y_true, y_pred, zero_division=0),
            "ROC-AUC": roc_auc_score(y_true, y_proba),
            "FPR": fp / (fp + tn) if (fp + tn) else 0.0,               # benign flagged as malicious
            "TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)}


def save_confusion_matrix(metrics, path, title):
    matrix = [[metrics["TN"], metrics["FP"]], [metrics["FN"], metrics["TP"]]]
    plt.figure(figsize=(4.5, 4))
    sns.heatmap(matrix, annot=True, fmt="d", cmap="Blues", cbar=False,
                xticklabels=["Benign", "Malicious"], yticklabels=["Benign", "Malicious"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title(title)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close("all")


def save_feature_importance(model, feature_names, csv_path, png_path, title):
    table = pd.DataFrame({"feature": feature_names, "importance": model.feature_importances_}) \
        .sort_values("importance", ascending=False)
    table.to_csv(csv_path, index=False)
    top = table.head(cfg.SHAP_MAX_DISPLAY + 3).iloc[::-1]
    plt.figure(figsize=(7, 4.5))
    plt.barh(top["feature"], top["importance"], color="#3b7dd8")
    plt.xlabel("Importance")
    plt.title(title)
    plt.tight_layout()
    plt.savefig(png_path, dpi=150)
    plt.close("all")
    return table


def aggregate_all_formats(results_dir=None):
    """Combine results/<format>/metrics.csv of every trained format into model_comparison.*"""
    if results_dir is None:
        results_dir = cfg.RESULTS_DIR
    results_dir = Path(results_dir)
    frames = []
    for fmt in cfg.FORMATS:
        path = results_dir / fmt / "metrics.csv"
        if path.exists():
            frames.append(pd.read_csv(path))
    if not frames:
        return None
    table = pd.concat(frames, ignore_index=True)
    table.to_csv(results_dir / "model_comparison.csv", index=False)
    save_json(table.to_dict(orient="records"), results_dir / "model_comparison.json")
    return table
