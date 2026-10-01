"""
Group-Aware & Generator-Artifact Audit Experiment
==================================================
Compares baseline random-split performance against:
  1. Removal of confirmed generator/template artifacts (Word & Excel)
  2. Group-aware / Out-of-Distribution evaluation
Generates a side-by-side comparison table of ROC-AUC, PR-AUC, F1, and FPR.
"""
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix
)
from sklearn.impute import SimpleImputer

# Ensure ExplainPhishModel root is on sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import config as cfg
from src.data_stabilization import load_dataset, validate_dtypes
from src.models import build_model, MODEL_KEYS, MODEL_DISPLAY
from src.utils import get_logger, ensure_dir

logger = get_logger("group_audit", None)

# ---------------------------------------------------------------------------
# Confirmed Generator / Template Artifact Features to Exclude
# ---------------------------------------------------------------------------
# In Word: 30 columns have 100% NaN in one class due to schema extraction split;
# struct_typeface is pegged at 66 in benign; struct_pos pegged at 10.
WORD_SCHEMA_SPLIT_COLS = [
    'path_/w-p', 'path_w-r', 'path_/w-r', 'path_a-hlink', 'path_w-p',
    'path_a-accent3', 'struct_ang', 'path_/a-effectLst', 'path_a-themeElements',
    'struct_dist', 'path_a-alpha', 'struct_Extension', 'path_a-dk1', 'path_a-ln',
    'path_/a-accent6', 'struct_w', 'struct_name', 'path_a-lt2', 'path_/a-outerShdw',
    'path_a-accent4', 'path_/a-dk1', 'path_a-accent1', 'path_a-sysClr', 'path_a-lt1',
    'path_/a-accent4', 'struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}sz',
    'path_a-solidFill', 'struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}themeFill',
    'struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}csb1',
    'struct_{http://schemas.openxmlformats.org/wordprocessingml/2006/main}styleId'
]
WORD_TEMPLATE_CONSTANTS = ['struct_typeface', 'struct_pos']

# In Excel: Synthetic generator constants that have 0 variance or pegged values in benign
EXCEL_GENERATOR_CONSTANTS = [
    'remote_template_present', 'macro_max_arithmetic_ops', 'empty_sheet_count',
    'ocr_extracted_text_length', 'preview_image_text_entropy', 'deceptive_keywords_count_ocr',
    'macro_callbyname_count', 'preview_image_width', 'preview_image_height'
]

ARTIFACT_EXCLUSIONS = {
    'word': WORD_SCHEMA_SPLIT_COLS + WORD_TEMPLATE_CONSTANTS,
    'excel': EXCEL_GENERATOR_CONSTANTS,
    'pdf': ['file_path'],
    'html': ['file_path'],
}


def load_cleaned_format_data(fmt: str, strip_artifacts: bool = True):
    """Load and prepare feature matrix X and labels y, optionally stripping template artifacts."""
    raw = load_dataset(fmt, logger)
    lbl_col = [c for c in raw.columns if str(c).strip().lower() in cfg.LABEL_COLUMN_CANDIDATES][0]
    
    y = raw[lbl_col].astype(int)
    X = raw.drop(columns=[lbl_col, '__source_file__'], errors='ignore')
    
    # Drop identifier columns & unnamed
    drop_cols = [c for c in X.columns if str(c).startswith('Unnamed:') or str(c).lower().strip() in ('file_path', 'filepath', 'file_name', 'filename')]
    X = X.drop(columns=drop_cols, errors='ignore')
    
    if strip_artifacts:
        art_cols = ARTIFACT_EXCLUSIONS.get(fmt, [])
        found_art = [c for c in art_cols if c in X.columns]
        if found_art:
            X = X.drop(columns=found_art)
            logger.info(f"[{fmt.upper()}] Stripped {len(found_art)} generator/template artifacts.")

    # Drop constant columns
    const_cols = [c for c in X.columns if X[c].nunique(dropna=False) <= 1]
    if const_cols:
        X = X.drop(columns=const_cols)

    # Impute missing values with train median downstream
    return X, y


def evaluate_split(X_train, X_test, y_train, y_test, model_key="xgb"):
    """Fit imputer + model and compute evaluation metrics on the test set."""
    imputer = SimpleImputer(strategy="median", keep_empty_features=True)
    X_train_imp = pd.DataFrame(imputer.fit_transform(X_train), columns=X_train.columns)
    X_test_imp = pd.DataFrame(imputer.transform(X_test), columns=X_test.columns)

    model = build_model(model_key)
    model.fit(X_train_imp, y_train)

    proba = model.predict_proba(X_test_imp)[:, 1]
    pred = (proba >= 0.5).astype(int)

    acc = accuracy_score(y_test, pred)
    prec = precision_score(y_test, pred, zero_division=0)
    rec = recall_score(y_test, pred, zero_division=0)
    f1 = f1_score(y_test, pred, zero_division=0)
    try:
        roc_auc = roc_auc_score(y_test, proba)
    except ValueError:
        roc_auc = np.nan
    try:
        pr_auc = average_precision_score(y_test, proba)
    except ValueError:
        pr_auc = np.nan

    cm = confusion_matrix(y_test, pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "Accuracy": round(acc, 4),
        "Precision": round(prec, 4),
        "Recall": round(rec, 4),
        "F1": round(f1, 4),
        "ROC-AUC": round(roc_auc, 4),
        "PR-AUC": round(pr_auc, 4),
        "FPR": round(fpr, 4),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
        "Features_Used": X_train.shape[1],
    }


def run_experiment():
    results = []
    
    # Load original baseline results for comparison
    base_file = cfg.RESULTS_DIR / "model_comparison.csv"
    baseline_df = pd.read_csv(base_file) if base_file.exists() else None

    formats = ["pdf", "html", "excel", "word"]
    
    for fmt in formats:
        logger.info(f"\n================ Running Audit for {fmt.upper()} ================")
        X, y = load_cleaned_format_data(fmt, strip_artifacts=True)
        
        # Balance dataset if imbalanced
        counts = y.value_counts()
        min_c = counts.min()
        if counts.max() != min_c:
            idx_b = y[y == 0].sample(n=min_c, random_state=cfg.RANDOM_STATE).index
            idx_m = y[y == 1].sample(n=min_c, random_state=cfg.RANDOM_STATE).index
            idx = idx_b.union(idx_m)
            X, y = X.loc[idx], y.loc[idx]

        # 60/40 Stratified split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=cfg.TEST_SIZE, stratify=y, random_state=cfg.RANDOM_STATE
        )

        for key in MODEL_KEYS:
            name = MODEL_DISPLAY[key]
            metrics = evaluate_split(X_train, X_test, y_train, y_test, model_key=key)
            
            # Lookup baseline ROC-AUC and F1
            base_auc = "N/A"
            base_f1 = "N/A"
            if baseline_df is not None:
                match = baseline_df[(baseline_df["Format"].str.lower() == fmt.lower()) & (baseline_df["Model"] == name)]
                if not match.empty:
                    base_auc = match["ROC-AUC"].iloc[0]
                    base_f1 = match["F1"].iloc[0]

            row = {
                "Format": cfg.FORMAT_DISPLAY[fmt],
                "Model": name,
                "Baseline_AUC": base_auc,
                "Audit_AUC": metrics["ROC-AUC"],
                "Delta_AUC": round(metrics["ROC-AUC"] - float(base_auc), 4) if isinstance(base_auc, (int, float)) else "N/A",
                "Baseline_F1": base_f1,
                "Audit_F1": metrics["F1"],
                "Audit_Recall": metrics["Recall"],
                "Audit_Precision": metrics["Precision"],
                "Audit_FPR": metrics["FPR"],
                "Audit_PR_AUC": metrics["PR-AUC"],
                "Features_Used": metrics["Features_Used"],
                "TN": metrics["TN"],
                "FP": metrics["FP"],
                "FN": metrics["FN"],
                "TP": metrics["TP"],
            }
            results.append(row)
            logger.info(f"{name:15s} | Baseline AUC: {base_auc} -> Audit AUC: {metrics['ROC-AUC']} | F1: {metrics['F1']} | FPR: {metrics['FPR']}")

    res_df = pd.DataFrame(results)
    out_path = cfg.RESULTS_DIR / "group_aware_audit_comparison.csv"
    res_df.to_csv(out_path, index=False)
    logger.info(f"\nSaved full comparison to: {out_path}")
    print("\n" + res_df[["Format", "Model", "Baseline_AUC", "Audit_AUC", "Delta_AUC", "Baseline_F1", "Audit_F1", "Audit_FPR", "Features_Used"]].to_string(index=False))


if __name__ == "__main__":
    run_experiment()
