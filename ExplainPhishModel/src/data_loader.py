"""
TRAP4Phish 2025 - Dataset Cleaning and Loading Utility
=======================================================
Handles the known structural quirks of each CSV file delivered by the dataset:

  * Excel  - clean, only drops the 'file_name' identifier column
  * PDF    - has 9 trailing 'Unnamed' ghost columns from CSV export artifacts;
             also 704 rows short of the advertised 20 000 (accepted as-is)
  * HTML   - has 12 trailing 'Unnamed' ghost columns + 3 missing rows
             + a 'file_name' identifier column
  * Word   - contains all 43 raw features (no pre-selection by the authors);
             the pipeline's feature-selection stage picks the top 10 via
             SHAP / RF importance (see config.py -> FEATURE_SELECTION_MODE)

Public API
----------
    load_and_clean(fmt, logger=None)  ->  (X, y, report)

        fmt     one of  "pdf" | "word" | "excel" | "html"
        X       pd.DataFrame  - feature matrix (no label, no ID columns)
        y       pd.Series     - int labels {0=Benign, 1=Malicious}
        report  dict          - loading statistics for the training summary

The function is deliberately lightweight: it does NOT impute, scale, or
select features.  Those steps are handled later by data_stabilization.py
(stabilize) and preprocessing.py inside the training pipeline.

Standalone health-check (prints a summary table for all four formats):
    python -m src.data_loader
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Allow "python -m src.data_loader" from the ExplainPhishModel/ root
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent.parent   # ExplainPhishModel/
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from config import config as cfg  # noqa: E402  (import after sys.path fix)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Exact CSV file names or patterns as downloaded from the TRAP4Phish 2025 dataset page.
_CSV_FILES: dict[str, list[str]] = {
    "excel": ["Excel_All_Features.csv", "Excel_Top10_Features.csv"],
    "pdf":   ["PDF_All_features.csv", "PDF_Top10_features.csv"],
    "html":  ["HTML_All_Features.csv", "HTML_Top13_Features.csv"],
    "word":  ["Word_All_features.csv"],
}

# Columns that are file identifiers and must NOT be used as features.
_IDENTIFIER_COLS: set[str] = {"file_name", "filename", "file name", "file_path", "filepath", "file path"}

# The label column name shared by all four CSVs.
_LABEL_COL = "label"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_logger(name: str = "data_loader") -> logging.Logger:
    """Return a basic console logger (used when the caller passes None)."""
    log = logging.getLogger(name)
    if not log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
    return log


def _drop_unnamed_cols(
    df: pd.DataFrame,
    logger: logging.Logger,
) -> tuple[pd.DataFrame, list[str]]:
    """
    Remove columns whose name starts with 'Unnamed:'.

    These appear in CSV files that were saved with extra trailing commas
    (a common pandas / Excel export artefact).
    """
    ghost = [c for c in df.columns if str(c).startswith("Unnamed:")]
    if ghost:
        preview = ghost[:5]
        suffix  = "..." if len(ghost) > 5 else ""
        logger.warning(
            "  Dropping %d ghost 'Unnamed' column(s) caused by trailing "
            "commas in the CSV export: %s%s",
            len(ghost), preview, suffix,
        )
        df = df.drop(columns=ghost)
    return df, ghost


def _drop_identifier_cols(
    df: pd.DataFrame,
    logger: logging.Logger,
) -> tuple[pd.DataFrame, list[str]]:
    """Remove known identifier / file-name columns that must not be features."""
    to_drop = [c for c in df.columns if c.strip().lower() in _IDENTIFIER_COLS]
    if to_drop:
        logger.info("  Dropping identifier column(s): %s", to_drop)
        df = df.drop(columns=to_drop)
    return df, to_drop


def _extract_label(
    df: pd.DataFrame,
    logger: logging.Logger,
) -> tuple[pd.DataFrame, pd.Series]:
    """
    Locate the label column, convert values to int {0, 1}, and drop it from X.

    Accepts numeric 0/1, float 0.0/1.0, or text strings mapped through
    config.BENIGN_LABELS / config.MALICIOUS_LABELS.

    Raises ValueError if the column is absent.
    """
    col_map = {str(c).strip().lower(): c for c in df.columns}
    label_key = col_map.get(_LABEL_COL)
    if label_key is None:
        raise ValueError(
            f"Label column '{_LABEL_COL}' not found.  "
            f"Available columns: {list(df.columns)}"
        )

    raw = df[label_key]

    # Fast path: column is already numeric
    try:
        y = pd.to_numeric(raw, errors="raise").astype(int)
    except (ValueError, TypeError):
        # Slow path: map text strings
        def _map(v):
            s = str(v).strip().lower()
            if s in cfg.BENIGN_LABELS:
                return 0
            if s in cfg.MALICIOUS_LABELS:
                return 1
            return np.nan

        y = raw.map(_map)
        bad = int(y.isna().sum())
        if bad:
            logger.warning("  %d rows have unrecognised label values - dropped.", bad)
        y = y.dropna().astype(int)
        df = df.loc[y.index]

    df = df.drop(columns=[label_key])
    return df, y


def _validate_balance(
    y: pd.Series,
    fmt: str,
    logger: logging.Logger,
) -> dict:
    """Check label distribution and return a short report dict."""
    counts  = y.value_counts().sort_index().to_dict()
    total   = len(y)
    ratio   = counts.get(1, 0) / max(total, 1)
    balanced = abs(ratio - 0.5) <= cfg.BALANCE_TOLERANCE
    status   = "balanced" if balanced else "IMBALANCED"

    logger.info(
        "  Labels - Benign: %d  Malicious: %d  Total: %d  [%s]",
        counts.get(0, 0), counts.get(1, 0), total, status,
    )

    # Warn if the total is notably below the published 20 000
    if total < 18_000:
        logger.warning(
            "  [%s] Only %d rows (expected ~20 000). "
            "Some files may have been skipped during feature extraction.",
            fmt.upper(), total,
        )

    return {
        "benign":           counts.get(0, 0),
        "malicious":        counts.get(1, 0),
        "total":            total,
        "malicious_ratio":  round(ratio, 4),
        "balanced":         balanced,
    }


# ---------------------------------------------------------------------------
# Per-format loaders
# ---------------------------------------------------------------------------

def _load_excel(
    path: Path,
    logger: logging.Logger,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Excel - cleanest file; only drops the file_name identifier."""
    logger.info("  Reading: %s", path.name)
    df = pd.read_csv(path, low_memory=False)
    logger.info("  Raw shape: %s", df.shape)

    df, _ghost   = _drop_unnamed_cols(df, logger)   # none expected
    df, _id_cols = _drop_identifier_cols(df, logger)
    df, y        = _extract_label(df, logger)

    missing = int(df.isnull().sum().sum())
    logger.info("  Missing cells in feature matrix: %d", missing)

    balance = _validate_balance(y, "excel", logger)
    report  = {
        "format":        "excel",
        "rows":          len(df),
        "features":      list(df.columns),
        "n_features":    df.shape[1],
        "missing_cells": missing,
        "balance":       balance,
        "actions":       ["dropped identifier column 'file_name'"],
    }
    return df, y, report


def _load_pdf(
    path: Path,
    logger: logging.Logger,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """
    PDF - drops 9 trailing 'Unnamed' ghost columns.
    Real feature count: 10. Row count: ~19 296 (704 short of 20 000).
    """
    logger.info("  Reading: %s", path.name)
    df = pd.read_csv(path, low_memory=False)
    logger.info("  Raw shape: %s", df.shape)

    df, ghost    = _drop_unnamed_cols(df, logger)
    df, _id_cols = _drop_identifier_cols(df, logger)
    df, y        = _extract_label(df, logger)

    missing = int(df.isnull().sum().sum())
    logger.info("  Missing cells in feature matrix: %d", missing)

    balance = _validate_balance(y, "pdf", logger)
    report  = {
        "format":        "pdf",
        "rows":          len(df),
        "features":      list(df.columns),
        "n_features":    df.shape[1],
        "missing_cells": missing,
        "balance":       balance,
        "actions":       [f"dropped {len(ghost)} ghost 'Unnamed' columns"],
        "note":          (
            "19 296 rows (not 20 000): 704 samples omitted during feature "
            "extraction - accepted as-is."
        ),
    }
    return df, y, report


def _load_html(
    path: Path,
    logger: logging.Logger,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """
    HTML - drops 12 trailing 'Unnamed' ghost columns + the 'file_name' column.
    Real feature count: 13.  Row count: ~19 997 (3 short of 20 000).
    """
    logger.info("  Reading: %s", path.name)
    df = pd.read_csv(path, low_memory=False)
    logger.info("  Raw shape: %s", df.shape)

    df, ghost   = _drop_unnamed_cols(df, logger)
    df, id_cols = _drop_identifier_cols(df, logger)
    df, y       = _extract_label(df, logger)

    missing = int(df.isnull().sum().sum())
    logger.info("  Missing cells in feature matrix: %d", missing)

    balance = _validate_balance(y, "html", logger)
    report  = {
        "format":        "html",
        "rows":          len(df),
        "features":      list(df.columns),
        "n_features":    df.shape[1],
        "missing_cells": missing,
        "balance":       balance,
        "actions":       [
            f"dropped {len(ghost)} ghost 'Unnamed' columns",
            f"dropped identifier column(s): {id_cols}",
        ],
        "note": (
            "19 997 rows (not 20 000): 3 samples omitted during feature "
            "extraction - accepted as-is."
        ),
    }
    return df, y, report


def _load_word(
    path: Path,
    logger: logging.Logger,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """
    Word - retains all 43 raw features for downstream pipeline selection.

    The dataset authors selected 10 features; this pipeline replicates that
    selection on the TRAINING SET ONLY via SHAP (see feature_selection.py).
    Many columns are sparse (NaN) because certain XML paths are absent in
    simple .docx documents - these will be median-imputed by preprocessing.py.
    """
    logger.info("  Reading: %s", path.name)
    df = pd.read_csv(path, low_memory=False)
    logger.info("  Raw shape: %s", df.shape)

    df, ghost   = _drop_unnamed_cols(df, logger)   # none expected
    df, id_cols = _drop_identifier_cols(df, logger) # 'file_name' not present in this CSV
    df, y       = _extract_label(df, logger)

    # Report sparse columns (XML-path count features are absent in simple docs)
    missing_per_col = df.isnull().sum()
    sparse = missing_per_col[missing_per_col > 0]
    if not sparse.empty:
        logger.info(
            "  %d column(s) have missing values "
            "(XML paths absent in simple .docx files - will be imputed downstream):",
            len(sparse),
        )
        for col, cnt in sparse.items():
            pct = 100.0 * cnt / max(len(df), 1)
            logger.info("    %-55s %6d missing (%5.1f%%)", col, cnt, pct)

    total_missing = int(missing_per_col.sum())
    balance = _validate_balance(y, "word", logger)

    actions = (
        ([f"dropped {len(ghost)} ghost columns"] if ghost else []) +
        ([f"dropped identifier columns: {id_cols}"] if id_cols else []) +
        ["all 43 features retained - top-10 selection performed by pipeline (SHAP)"]
    )
    report = {
        "format":        "word",
        "rows":          len(df),
        "features":      list(df.columns),
        "n_features":    df.shape[1],
        "missing_cells": total_missing,
        "balance":       balance,
        "actions":       actions,
        "note": (
            "Word_All_features.csv contains all 43 extracted features. "
            "The dataset paper selected 10 via feature importance; "
            "this pipeline replicates that selection using SHAP on the "
            "training set only (data_stabilization -> feature_selection)."
        ),
    }
    return df, y, report


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------
_LOADERS = {
    "excel": _load_excel,
    "pdf":   _load_pdf,
    "html":  _load_html,
    "word":  _load_word,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_and_clean(
    fmt: str,
    logger: Optional[logging.Logger] = None,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """
    Load and clean the TRAP4Phish 2025 CSV for the given document format.

    Parameters
    ----------
    fmt : str
        One of "pdf" | "word" | "excel" | "html".
    logger : logging.Logger, optional
        Pipeline logger.  If None, a default console logger is created.

    Returns
    -------
    X : pd.DataFrame
        Feature matrix - no label column, no identifier columns.
    y : pd.Series (int, index aligned with X)
        Labels: 0 = Benign, 1 = Malicious.
    report : dict
        Dataset statistics (rows, feature names, missing counts, balance).

    Raises
    ------
    ValueError
        If fmt is not recognised.
    FileNotFoundError
        If the expected CSV file is not present on disk.
    """
    if fmt not in _LOADERS:
        raise ValueError(
            f"Unknown format {fmt!r}. Choose from: {list(_LOADERS)}"
        )

    log = logger or _get_logger()
    log.info("=" * 60)
    log.info("Loading [%s] dataset", fmt.upper())
    log.info("=" * 60)

    candidates = _CSV_FILES[fmt]
    path = None
    for cand in candidates:
        p = cfg.DATA_DIR / fmt / cand
        if p.exists():
            path = p
            break
    if path is None:
        csvs = list((cfg.DATA_DIR / fmt).glob("*.csv"))
        if csvs:
            path = csvs[0]

    if path is None or not path.exists():
        raise FileNotFoundError(
            f"Dataset file not found in {cfg.DATA_DIR / fmt}.\n"
            f"Download from https://www.unb.ca/cic/datasets/trap4phish2025.html "
            f"and place it in  ExplainPhishModel/data/{fmt}/"
        )

    X, y, report = _LOADERS[fmt](path, log)

    log.info(
        "  [%s] ready - %d rows x %d features  |  "
        "benign %d / malicious %d",
        fmt.upper(), len(X), X.shape[1],
        report["balance"]["benign"], report["balance"]["malicious"],
    )
    return X, y, report


# ---------------------------------------------------------------------------
# Standalone health-check
# ---------------------------------------------------------------------------

def _health_check() -> None:
    """Print a summary table for all four formats."""
    print("\n" + "=" * 72)
    print("  TRAP4Phish 2025 - Dataset Health Check")
    print("=" * 72)

    rows_data: list[dict] = []
    all_ok = True

    for fmt in cfg.FORMATS:
        try:
            X, y, report = load_and_clean(fmt)
            b = report["balance"]
            rows_data.append({
                "Format":    fmt.upper(),
                "Rows":      f"{report['rows']:,}",
                "Features":  str(report["n_features"]),
                "Missing":   str(report["missing_cells"]),
                "Benign":    f"{b['benign']:,}",
                "Malicious": f"{b['malicious']:,}",
                "Balanced":  "Yes" if b["balanced"] else "NO",
                "Status":    "OK",
            })
        except Exception as exc:
            rows_data.append({
                "Format": fmt.upper(), "Rows": "-", "Features": "-",
                "Missing": "-", "Benign": "-", "Malicious": "-",
                "Balanced": "-", "Status": f"ERROR: {exc}",
            })
            all_ok = False

    headers = ["Format", "Rows", "Features", "Missing",
               "Benign", "Malicious", "Balanced", "Status"]
    widths   = [8, 9, 10, 9, 9, 10, 9, 35]

    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(header_line)
    print("-" * len(header_line))
    for r in rows_data:
        print("  ".join(str(r[h]).ljust(w) for h, w in zip(headers, widths)))

    print()
    if all_ok:
        print("  All datasets loaded successfully.")
    else:
        print("  WARNING: one or more datasets failed - check errors above.")
    print("=" * 72 + "\n")


if __name__ == "__main__":
    _health_check()
