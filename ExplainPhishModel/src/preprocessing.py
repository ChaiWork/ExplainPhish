"""
Preprocessing fitted on the TRAINING set only, then reused for test data and
for future unseen documents. Everything needed is stored in one dictionary
("bundle") so it can be saved with joblib and loaded without our own classes.
"""
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OrdinalEncoder


def fit_preprocessor(X_train):
    """Learn imputation values (median) and category encodings from training data."""
    numeric_cols = [c for c in X_train.columns if pd.api.types.is_numeric_dtype(X_train[c])]
    categorical_cols = [c for c in X_train.columns if c not in numeric_cols]
    bundle = {"input_columns": list(X_train.columns), "numeric_cols": numeric_cols,
              "categorical_cols": categorical_cols,
              "feature_order": numeric_cols + categorical_cols,
              "imputer": None, "encoder": None, "selected_features": None}
    clean = X_train.replace([np.inf, -np.inf], np.nan)
    if numeric_cols:
        bundle["imputer"] = SimpleImputer(strategy="median", keep_empty_features=True).fit(
            clean[numeric_cols].astype(float))
    if categorical_cols:
        text = clean[categorical_cols].astype(object).fillna("__missing__").astype(str)
        bundle["encoder"] = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1).fit(text)
    return bundle


def transform_with_bundle(X, bundle, select=True):
    """Apply the saved preprocessing. Output columns follow the exact training order."""
    X = X.reindex(columns=bundle["input_columns"]).replace([np.inf, -np.inf], np.nan)
    parts = []
    if bundle["numeric_cols"]:
        values = bundle["imputer"].transform(X[bundle["numeric_cols"]].astype(float))
        parts.append(pd.DataFrame(values, columns=bundle["numeric_cols"], index=X.index))
    if bundle["categorical_cols"]:
        text = X[bundle["categorical_cols"]].astype(object).fillna("__missing__").astype(str)
        values = bundle["encoder"].transform(text)
        parts.append(pd.DataFrame(values, columns=bundle["categorical_cols"], index=X.index))
    out = pd.concat(parts, axis=1)[bundle["feature_order"]].astype(float)
    if select and bundle.get("selected_features"):
        out = out[bundle["selected_features"]]
    return out
