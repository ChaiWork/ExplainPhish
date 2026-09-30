"""SHAP explanations: global summary plots and local explanations for single documents."""
import matplotlib
matplotlib.use("Agg")   # save images without opening windows
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap

from config import config as cfg


def malicious_shap(model, X):
    """SHAP values for the MALICIOUS class as a 2-D array, plus the base value.
    Handles the different output shapes of different shap/sklearn versions."""
    explainer = shap.TreeExplainer(model)
    values = explainer.shap_values(X)
    expected = np.ravel(explainer.expected_value)
    if isinstance(values, list):
        values = values[1]
        base = expected[1] if len(expected) > 1 else expected[0]
    else:
        values = np.asarray(values)
        if values.ndim == 3:
            values = values[:, :, 1]
            base = expected[1] if len(expected) > 1 else expected[0]
        else:
            base = expected[0]
    return np.asarray(values), float(base)


def _pick_local_cases(y_true, pred, proba):
    """Choose one representative test row for TP, TN, FP and FN."""
    cases = {"true_positive": (y_true == 1) & (pred == 1), "true_negative": (y_true == 0) & (pred == 0),
             "false_positive": (y_true == 0) & (pred == 1), "false_negative": (y_true == 1) & (pred == 0)}
    chosen = {}
    for name, mask in cases.items():
        idx = np.where(mask)[0]
        if len(idx) == 0:
            continue
        # most confident example of each kind
        chosen[name] = idx[np.argmax(proba[idx])] if name in ("true_positive", "false_positive") \
            else idx[np.argmin(proba[idx])]
    return chosen


def run_shap(key, model, X_test, y_test, out_dir, logger):
    """Create global (summary, bar, csv) and local (waterfall, csv) SHAP outputs."""
    y_true = np.asarray(y_test)
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)

    # ---- Global explanation
    sample = X_test.sample(n=min(cfg.SHAP_MAX_SAMPLES, len(X_test)), random_state=cfg.RANDOM_STATE)
    values, _ = malicious_shap(model, sample)
    for plot_type, suffix in (("dot", "shap_summary"), ("bar", "shap_bar")):
        plt.figure()
        shap.summary_plot(values, sample, plot_type=plot_type, max_display=cfg.SHAP_MAX_DISPLAY, show=False)
        plt.tight_layout()
        plt.savefig(out_dir / f"{key}_{suffix}.png", dpi=150, bbox_inches="tight")
        plt.close("all")
    pd.DataFrame({"feature": X_test.columns, "mean_abs_shap": np.abs(values).mean(axis=0)}) \
        .sort_values("mean_abs_shap", ascending=False) \
        .to_csv(out_dir / f"{key}_shap_importance.csv", index=False)

    # ---- Local explanations
    for case, position in _pick_local_cases(y_true, pred, proba).items():
        row = X_test.iloc[[position]]
        row_values, base = malicious_shap(model, row)
        explanation = shap.Explanation(values=row_values[0], base_values=base,
                                       data=row.iloc[0].to_numpy(), feature_names=list(X_test.columns))
        plt.figure()
        shap.plots.waterfall(explanation, max_display=cfg.SHAP_MAX_DISPLAY, show=False)
        plt.title(f"{key.upper()} - {case.replace('_', ' ')} (P(malicious)={proba[position]:.3f})", fontsize=10)
        plt.savefig(out_dir / f"{key}_shap_local_{case}.png", dpi=150, bbox_inches="tight")
        plt.close("all")
        table = pd.DataFrame({"feature": X_test.columns, "feature_value": row.iloc[0].to_numpy(),
                              "shap_value": row_values[0]})
        table["abs"] = table["shap_value"].abs()
        table = table.sort_values("abs", ascending=False).drop(columns="abs")
        table.insert(0, "actual", int(y_true[position]))
        table.insert(1, "predicted", int(pred[position]))
        table.insert(2, "probability_malicious", round(float(proba[position]), 4))
        table.to_csv(out_dir / f"{key}_shap_local_{case}.csv", index=False)
    logger.info(f"  SHAP outputs saved for {key}")
