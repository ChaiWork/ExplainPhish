"""
Task 5: Word OOXML-Only Subset Experiment
=========================================
Checks:
  1. pd.crosstab(label, has_xml) where has_xml = any path_* column is non-null.
  2. If BOTH classes have at least 500 rows in the XML subset:
     Train and evaluate a Word model restricted to rows with XML parts
     (same pipeline, same baseline policy, split inside the subset).
     Save results under results_word_ooxml_only/ and models under models_word_ooxml_only/.
  3. If fewer than 500 rows in either class: report counts and do not train.
"""
import sys
from pathlib import Path
import pandas as pd
import numpy as np

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import config as cfg
from train import run_pipeline
from src.utils import ensure_dir, get_logger

logger = get_logger("word_ooxml_exp", None)


def run_word_ooxml_experiment():
    logger.info("=" * 70)
    logger.info("Task 5: Word OOXML-Only Subset Experiment")
    logger.info("=" * 70)

    raw_path = cfg.DATA_DIR / "word" / "Word_All_features.csv"
    if not raw_path.exists():
        raise FileNotFoundError(f"Missing Word dataset at: {raw_path}")

    df = pd.read_csv(raw_path, low_memory=False)
    path_cols = [c for c in df.columns if c.startswith("path_")]
    w_cols = [c for c in df.columns if c.startswith("path_w") or c.startswith("path_/w")]
    a_cols = [c for c in df.columns if c.startswith("path_a") or c.startswith("path_/a")]

    has_any_xml = df[path_cols].notna().any(axis=1)
    has_w_xml = df[w_cols].notna().any(axis=1) if w_cols else pd.Series(False, index=df.index)
    has_a_xml = df[a_cols].notna().any(axis=1) if a_cols else pd.Series(False, index=df.index)
    has_both_xml = has_w_xml & has_a_xml

    ct_any = pd.crosstab(df["label"], has_any_xml, rownames=["label"], colnames=["has_any_path_xml"])
    ct_w = pd.crosstab(df["label"], has_w_xml, rownames=["label"], colnames=["has_wordprocessingml_xml"])
    ct_a = pd.crosstab(df["label"], has_a_xml, rownames=["label"], colnames=["has_drawingml_xml"])
    ct_both = pd.crosstab(df["label"], has_both_xml, rownames=["label"], colnames=["has_both_w_and_a_xml"])

    print("\n--- Crosstab 1: has_xml (any path_* column is non-null) ---")
    print(ct_any)

    print("\n--- Crosstab 2: has_wordprocessingml_xml (path_w* / path_/w*) ---")
    print(ct_w)

    print("\n--- Crosstab 3: has_drawingml_xml (path_a* / path_/a*) ---")
    print(ct_a)

    print("\n--- Crosstab 4: has_both_w_and_a_xml ---")
    print(ct_both)

    xml_subset = df[has_any_xml].copy()
    counts = xml_subset["label"].value_counts().to_dict()
    benign_count = counts.get(0, 0)
    malicious_count = counts.get(1, 0)

    logger.info(f"XML Subset sample counts: Benign (0) = {benign_count}, Malicious (1) = {malicious_count}")

    results_dir = ensure_dir(cfg.PROJECT_ROOT / "results_word_ooxml_only")
    models_dir = ensure_dir(cfg.PROJECT_ROOT / "models_word_ooxml_only")

    # Save crosstabs to CSV for documentation
    ct_any.to_csv(results_dir / "crosstab_any_path_xml.csv")
    ct_w.to_csv(results_dir / "crosstab_wordprocessingml_xml.csv")
    ct_a.to_csv(results_dir / "crosstab_drawingml_xml.csv")
    ct_both.to_csv(results_dir / "crosstab_both_xml.csv")

    if benign_count < 500 or malicious_count < 500:
        msg = (
            f"CANNOT TRAIN OOXML SUBSET: One of the classes has fewer than 500 rows "
            f"(Benign={benign_count}, Malicious={malicious_count}). "
            f"Threshold is 500 rows per class."
        )
        logger.warning(msg)
        return False, msg

    logger.info(
        f"Both classes have >= 500 rows in the XML subset ({benign_count} Benign, {malicious_count} Malicious). "
        f"Training Word model on OOXML subset..."
    )

    run_pipeline(
        "word",
        results_root=results_dir,
        models_root=models_dir,
        custom_df=xml_subset
    )

    logger.info(f"Task 5 Word OOXML experiment complete. Results saved to: {results_dir}")
    return True, "Success"


if __name__ == "__main__":
    run_word_ooxml_experiment()
