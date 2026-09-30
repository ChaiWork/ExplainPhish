"""
STAGE 1 - DATA STABILIZATION
Loads the raw CSV files of one format and makes them safe for machine learning.
Nothing here executes any document: we only read numeric/text feature tables.

Order of checks:
  labels -> exact duplicates -> irrelevant/ID columns -> data types ->
  feature-level duplicates & conflicts -> missing values -> constant columns ->
  leakage -> descriptive statistics & outlier report
Everything that is removed is written to removed_columns.csv with a reason.
Missing values are NOT filled here: columns that are mostly empty are dropped and
the rest are imputed later using statistics from the TRAINING set only.
"""
import re

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from config import config as cfg
from src.utils import save_json

SOURCE_COL = "__source_file__"


# ------------------------------------------------------------------ loading
def load_dataset(fmt, logger):
    """Read every CSV in data/<fmt>/ and stack them into one DataFrame."""
    folder = cfg.DATA_DIR / fmt
    files = sorted(folder.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No .csv files found in {folder}. Put the {fmt} dataset there.")
    frames = []
    for path in files:
        try:
            frame = pd.read_csv(path, low_memory=False)
        except Exception as error:
            raise RuntimeError(f"Could not read {path.name}: {error}")
        frame[SOURCE_COL] = path.name
        logger.info(f"Loaded {path.name}: {frame.shape[0]} rows x {frame.shape[1] - 1} columns")
        frames.append(frame)
    return pd.concat(frames, ignore_index=True)


# ------------------------------------------------------------------- labels
def find_label_column(df):
    lowered = {str(c).lower().strip(): c for c in df.columns}
    for candidate in cfg.LABEL_COLUMN_CANDIDATES:
        if candidate in lowered:
            return lowered[candidate]
    return None


def _label_from_filename(name):
    name = name.lower()
    if any(w in name for w in ("benign", "legit", "clean")):
        return "0"
    if any(w in name for w in ("malicious", "phish", "malware")):
        return "1"
    return None


def normalize_labels(raw):
    """Map raw label values to 0 (Benign) / 1 (Malicious); return (series, report)."""
    def to_text(value):
        if pd.isna(value):
            return None
        text = str(value).strip().lower()
        try:                       # 1.0 -> "1"
            number = float(text)
            if number == int(number):
                text = str(int(number))
        except ValueError:
            pass
        return text

    text = raw.map(to_text)
    mapped = text.map(lambda t: 0 if t in cfg.BENIGN_LABELS else (1 if t in cfg.MALICIOUS_LABELS else np.nan))
    unexpected = text[mapped.isna()].fillna("<missing>").value_counts()
    report = {
        "raw_label_values": text.fillna("<missing>").value_counts().to_dict(),
        "unexpected_labels": unexpected.to_dict(),
        "rows_with_unexpected_labels": int(mapped.isna().sum()),
    }
    return mapped, report


# --------------------------------------------------------------- data types
def validate_dtypes(df, logger):
    """Classify every column and convert text/bool columns where possible."""
    kinds, rows, unexpected = {}, [], []
    for col in df.columns:
        series = df[col]
        original = str(series.dtype)
        note = ""
        if pd.api.types.is_bool_dtype(series):
            df[col] = series.astype(int)
            kind, note = "boolean", "bool -> 0/1"
        elif pd.api.types.is_numeric_dtype(series):
            kind = "numeric"
        elif (series.dtype == object or pd.api.types.is_string_dtype(series)
              or isinstance(series.dtype, pd.CategoricalDtype)):
            lowered = series.astype(str).str.strip().str.lower().where(series.notna())
            values = set(lowered.dropna().unique())
            if values and values <= {"true", "false"}:
                df[col] = lowered.map({"true": 1, "false": 0})
                kind, note = "boolean", "text true/false -> 0/1"
            else:
                converted = pd.to_numeric(series, errors="coerce")
                ratio = converted.notna().sum() / max(series.notna().sum(), 1)
                if ratio >= 0.95:
                    lost = int(series.notna().sum() - converted.notna().sum())
                    df[col] = converted
                    kind, note = "numeric", f"text -> number ({lost} unparseable values became missing)"
                else:
                    kind = "categorical"
        else:
            kind, note = "unexpected", "unsupported dtype - dropped"
            unexpected.append(col)
        kinds[col] = kind
        rows.append({"column": col, "original_dtype": original, "kind": kind, "note": note})
    if unexpected:
        logger.warning(f"Unexpected data types, dropping: {unexpected}")
    return kinds, pd.DataFrame(rows), unexpected


# ------------------------------------------------------------- outlier check
def outlier_report(df):
    """IQR-based outlier counts per numeric column. Values are NOT removed."""
    rows = []
    for col in df.select_dtypes(include=[np.number]).columns:
        s = df[col].dropna()
        if s.empty:
            continue
        q1, q3 = s.quantile(0.25), s.quantile(0.75)
        iqr = q3 - q1
        low, high = q1 - cfg.OUTLIER_IQR_MULTIPLIER * iqr, q3 + cfg.OUTLIER_IQR_MULTIPLIER * iqr
        count = int(((s < low) | (s > high)).sum())
        if count > 0 and iqr > 0:
            rows.append({"column": col, "lower_fence": low, "upper_fence": high,
                         "n_outliers": count, "pct_outliers": round(100 * count / len(s), 3),
                         "min": s.min(), "max": s.max()})
    columns = ["column", "lower_fence", "upper_fence", "n_outliers", "pct_outliers", "min", "max"]
    table = pd.DataFrame(rows, columns=columns)
    return table.sort_values("pct_outliers", ascending=False) if len(table) else table


def get_outlier_rows(df, column):
    """Helper for manual inspection: rows whose value lies outside the IQR fences."""
    s = df[column]
    q1, q3 = s.quantile(0.25), s.quantile(0.75)
    iqr = q3 - q1
    mask = (s < q1 - cfg.OUTLIER_IQR_MULTIPLIER * iqr) | (s > q3 + cfg.OUTLIER_IQR_MULTIPLIER * iqr)
    return df[mask]


def numeric_statistics(df):
    numeric = df.select_dtypes(include=[np.number])
    if numeric.shape[1] == 0:
        return pd.DataFrame()
    stats = numeric.agg(["mean", "median", "min", "max", "std"]).T
    stats["q1"] = numeric.quantile(0.25)
    stats["q3"] = numeric.quantile(0.75)
    return stats


# --------------------------------------------------------------- leakage
def detect_statistical_leakage(df, y, kinds, remove_threshold=None):
    """Flag features that (almost) perfectly reveal the label on their own.

    Parameters
    ----------
    remove_threshold : float, optional
        AUC above which a feature is marked for removal.  Defaults to
        cfg.LEAKAGE_AUC_REMOVE.  Pass a per-format override (e.g. 1.001)
        to keep features when no better dataset is available.
    """
    if remove_threshold is None:
        remove_threshold = cfg.LEAKAGE_AUC_REMOVE
    findings = []
    for col in df.columns:
        s = df[col]
        if kinds.get(col) in ("numeric", "boolean"):
            values = s.fillna(s.median()) if s.notna().any() else s.fillna(0)
            try:
                auc = roc_auc_score(y.loc[df.index], values)
            except ValueError:
                continue
            strength = max(auc, 1 - auc)
            if strength >= cfg.LEAKAGE_AUC_WARN:
                findings.append({"column": col, "check": "single-feature AUC", "value": round(strength, 5),
                                 "remove": strength >= remove_threshold})
        elif kinds.get(col) == "categorical":
            if s.nunique() <= 20:
                purity = pd.DataFrame({"v": s.fillna("__missing__"), "y": y.loc[df.index]}).groupby("v")["y"].nunique()
                if (purity == 1).all():
                    findings.append({"column": col, "check": "every category has a single label",
                                     "value": 1.0, "remove": True})
    return findings


# ------------------------------------------------------------------ main
def stabilize(df, fmt, out_dir, logger):
    """Run the full stabilization stage. Returns (X, y, report)."""
    df = df.copy()
    report = {"format": fmt, "rows_before_cleaning": int(len(df)),
              "columns_before_cleaning": int(df.shape[1] - 1)}
    removed = []   # (column, reason)

    def drop_columns(columns, reason):
        columns = [c for c in columns if c in df.columns]
        for c in columns:
            removed.append({"column": c, "reason": reason})
        if columns:
            df.drop(columns=columns, inplace=True)

    # 1. Labels ---------------------------------------------------------------
    label_col = find_label_column(df)
    if label_col is not None:
        raw_labels = df[label_col]
        logger.info(f"Label column detected: '{label_col}'")
    else:
        raw_labels = df[SOURCE_COL].map(_label_from_filename)
        if raw_labels.isna().all():
            raise ValueError("No label column found and file names do not say benign/malicious. "
                             "Add the column name to LABEL_COLUMN_CANDIDATES in config.py.")
        label_col = "<from file name>"
        logger.warning("No label column found - labels inferred from file names.")
    y, label_report = normalize_labels(raw_labels)
    report["label_column"] = str(label_col)
    report["label_check"] = label_report
    if label_report["rows_with_unexpected_labels"]:
        logger.warning(f"Unexpected labels found (rows will be dropped): {label_report['unexpected_labels']}")
    keep = y.notna()
    df, y = df.loc[keep].copy(), y[keep].astype(int)
    if label_col in df.columns:
        drop_columns([label_col], "target column")
    drop_columns([SOURCE_COL], "source file name (would leak the label if files are split by class)")
    logger.info(f"Label distribution after normalisation: {y.value_counts().sort_index().to_dict()} (0=Benign, 1=Malicious)")

    # 2. Exact duplicate rows -------------------------------------------------
    combined = df.copy()
    combined["__y__"] = y
    dup_mask = combined.duplicated(keep="first")
    report["exact_duplicates_removed"] = int(dup_mask.sum())
    df, y = df.loc[~dup_mask], y.loc[~dup_mask]
    logger.info(f"Exact duplicate rows removed: {int(dup_mask.sum())}")

    # 3. Irrelevant / identifier columns --------------------------------------
    user_excluded = cfg.EXCLUDE_COLUMNS.get(fmt, [])
    drop_columns(user_excluded, "excluded in config.EXCLUDE_COLUMNS")
    review_columns = []
    for col in list(df.columns):
        tokens = set(re.split(r"[^a-z0-9]+", str(col).lower()))
        if str(col).lower().startswith("unnamed:"):
            drop_columns([col], "pandas index column ('Unnamed')")
        elif tokens & cfg.ID_NAME_TOKENS:
            is_numeric = pd.api.types.is_numeric_dtype(df[col])
            if (not is_numeric) or df[col].nunique() > 0.99 * len(df):
                drop_columns([col], "identifier-like column name")
            else:
                review_columns.append(col)
    if review_columns:
        logger.warning(f"Columns with ID-like names kept (numeric, not unique) - please review: {review_columns}")
    report["id_like_columns_to_review"] = review_columns
    for col in df.columns:
        if str(col).lower().strip() in cfg.LEAKAGE_EXACT_NAMES:
            drop_columns([col], "leakage: column name reveals the target")

    # 4. Data types -----------------------------------------------------------
    kinds, dtype_table, unexpected = validate_dtypes(df, logger)
    drop_columns(unexpected, "unexpected data type")
    for col in [c for c in df.columns if kinds[c] == "categorical"]:
        n_unique = df[col].nunique()
        if n_unique > cfg.MAX_CATEGORICAL_LEVELS or n_unique > cfg.MAX_CATEGORICAL_UNIQUE_RATIO * len(df):
            drop_columns([col], f"text column with {n_unique} distinct values (identifier-like)")
    kinds = {c: kinds[c] for c in df.columns}
    df = df.replace([np.inf, -np.inf], np.nan)
    report["dtype_counts"] = pd.Series(kinds).value_counts().to_dict()

    # 5. Feature-level duplicates and conflicting labels ---------------------
    hashes = pd.util.hash_pandas_object(df, index=False)
    feature_dups = pd.DataFrame({"h": hashes, "y": y}).duplicated(keep="first")
    report["feature_duplicates_removed"] = int(feature_dups.sum())
    df, y = df.loc[~feature_dups], y.loc[~feature_dups]
    hashes = hashes.loc[df.index]
    label_count = pd.DataFrame({"h": hashes, "y": y}).groupby("h")["y"].transform("nunique")
    conflicts = label_count > 1
    report["conflicting_label_rows"] = int(conflicts.sum())
    if conflicts.any():
        logger.warning(f"{int(conflicts.sum())} rows share identical features but have different labels.")
        if cfg.DROP_CONFLICTING_LABEL_ROWS:
            df, y = df.loc[~conflicts], y.loc[~conflicts]
    logger.info(f"Duplicate feature rows removed: {int(feature_dups.sum())}")

    # 6. Missing values -------------------------------------------------------
    missing = df.isna().sum()
    pct = missing / max(len(df), 1)
    rows = []
    for col in df.columns:
        if pct[col] > cfg.MAX_MISSING_COLUMN_FRACTION:
            action = f"dropped (>{int(cfg.MAX_MISSING_COLUMN_FRACTION * 100)}% missing)"
        elif missing[col] == 0:
            action = "none needed"
        elif kinds[col] == "categorical":
            action = "most-frequent/'__missing__' category (fitted on train only)"
        else:
            action = "median imputation (fitted on train only)"
        rows.append({"column": col, "kind": kinds[col], "missing_count": int(missing[col]),
                     "missing_pct": round(100 * pct[col], 3), "action": action})
    missing_table = pd.DataFrame(rows)
    drop_columns([c for c in df.columns if pct[c] > cfg.MAX_MISSING_COLUMN_FRACTION], "too many missing values")
    report["total_missing_cells"] = int(missing.sum())
    report["columns_with_missing"] = int((missing > 0).sum())
    logger.info(f"Missing cells: {int(missing.sum())} in {int((missing > 0).sum())} columns")

    # 7. Constant columns -----------------------------------------------------
    constant = [c for c in df.columns if df[c].nunique(dropna=False) <= 1]
    drop_columns(constant, "constant column (single value)")
    logger.info(f"Constant columns removed: {constant}")

    # 8. Leakage ---------------------------------------------------------------
    kinds = {c: kinds[c] for c in df.columns}
    remove_threshold = getattr(cfg, "LEAKAGE_AUC_REMOVE_OVERRIDE", {}).get(fmt, cfg.LEAKAGE_AUC_REMOVE)
    if remove_threshold != cfg.LEAKAGE_AUC_REMOVE:
        logger.info(f"Leakage remove threshold overridden for '{fmt}': {remove_threshold} "
                    f"(global={cfg.LEAKAGE_AUC_REMOVE})")
    findings = detect_statistical_leakage(df, y, kinds, remove_threshold=remove_threshold)
    report["leakage_findings"] = findings
    for item in findings:
        level = logger.warning
        level(f"Possible leakage: {item['column']} ({item['check']} = {item['value']})"
              f"{' -> REMOVED' if item['remove'] and cfg.REMOVE_STATISTICAL_LEAKAGE else ''}")
    if cfg.REMOVE_STATISTICAL_LEAKAGE:
        drop_columns([f["column"] for f in findings if f["remove"]], "leakage: feature alone separates the classes")


    # 9. Statistics & outliers (reported only) --------------------------------
    stats = numeric_statistics(df)
    outliers = outlier_report(df)
    report["columns_with_outliers"] = int(len(outliers))
    logger.info(f"Columns containing IQR outliers (kept, see suspicious_outliers.csv): {len(outliers)}")

    # Save everything ----------------------------------------------------------
    report["rows_after_cleaning"] = int(len(df))
    report["columns_after_cleaning"] = int(df.shape[1])
    report["removed_columns"] = removed
    report["feature_columns"] = list(df.columns)
    missing_table.to_csv(out_dir / "missing_values.csv", index=False)
    dtype_table.to_csv(out_dir / "dtype_report.csv", index=False)
    pd.DataFrame(removed, columns=["column", "reason"]).to_csv(out_dir / "removed_columns.csv", index=False)
    stats.to_csv(out_dir / "numeric_statistics.csv")
    outliers.to_csv(out_dir / "suspicious_outliers.csv", index=False)
    if cfg.SAVE_CLEANED_DATASET:
        cleaned = df.copy()
        cleaned["label"] = y
        cleaned.to_csv(out_dir / "cleaned_dataset.csv", index=False)
    save_json(report, out_dir / "stabilization_report.json")
    logger.info(f"Stabilization finished: {report['rows_before_cleaning']} -> {len(df)} rows, "
                f"{report['columns_before_cleaning']} -> {df.shape[1]} feature columns")
    return df, y, report
