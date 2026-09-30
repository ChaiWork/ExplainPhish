"""
Visualise the three trained tree models for a given format.

Usage:
    python src/visualize_trees.py --format excel
    python src/visualize_trees.py --format all      # runs all four formats

Outputs (per format, into results/<fmt>/):
    dt_tree.png         – Decision Tree (full model, depth capped at 3 for readability)
    rf_tree0.png        – First estimator of the Random Forest (depth 3)
    xgb_tree0.png       – First boosted tree of XGBoost (requires Graphviz)

Notes on XGBoost / Graphviz
    XGBoost's plot_tree() needs the Graphviz *program* (not just the Python package).
    Install: winget install graphviz   (Windows)  or  brew install graphviz  (macOS)
    Then:   pip install graphviz
    If Graphviz is absent the script will fall back to dumping the tree as a CSV table
    at results/<fmt>/xgb_tree0.csv instead of an image.
"""
import argparse
import os
import sys
import traceback
from pathlib import Path

# Make sure 'config' and 'src' are importable from the project root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ── Inject Graphviz into PATH so XGBoost's plot_tree can find 'dot' even
#    when the shell session hasn't picked up the updated system/user PATH yet.
_GRAPHVIZ_CANDIDATES = [
    r"C:\Program Files\Graphviz\bin",          # winget default (Windows)
    r"C:\Program Files (x86)\Graphviz\bin",
    "/usr/bin",                                 # apt (Ubuntu/Debian)
    "/usr/local/bin",                           # brew (macOS)
    "/opt/homebrew/bin",                        # brew Apple Silicon
]
for _gv in _GRAPHVIZ_CANDIDATES:
    if Path(_gv, "dot").exists() or Path(_gv, "dot.exe").exists():
        if _gv not in os.environ.get("PATH", ""):
            os.environ["PATH"] = _gv + os.pathsep + os.environ.get("PATH", "")
        break

import matplotlib
matplotlib.use("Agg")          # headless – no display required
import matplotlib.pyplot as plt
from sklearn.tree import plot_tree

from config import config as cfg
from src.models import load_model
from src.utils import ensure_dir, get_logger, load_json

# ─── constants ────────────────────────────────────────────────────────────────
MAX_DEPTH_DISPLAY = 3          # deeper trees are unreadable as images
FIG_WIDTH, FIG_HEIGHT = 24, 10
DPI = 200
CLASS_NAMES = ["Benign", "Malicious"]


# ─── helpers ──────────────────────────────────────────────────────────────────
def _save_fig(path: Path, title: str):
    plt.suptitle(title, fontsize=11, y=1.01)
    plt.tight_layout()
    plt.savefig(path, dpi=DPI, bbox_inches="tight")
    plt.close("all")
    return path


def visualise_dt(model, features, out_path: Path, title: str, logger):
    """Plot a sklearn DecisionTreeClassifier."""
    fig, ax = plt.subplots(figsize=(FIG_WIDTH, FIG_HEIGHT))
    plot_tree(
        model,
        feature_names=features,
        class_names=CLASS_NAMES,
        filled=True,
        max_depth=MAX_DEPTH_DISPLAY,
        fontsize=9,
        ax=ax,
    )
    _save_fig(out_path, title)
    logger.info(f"  Saved: {out_path.relative_to(PROJECT_ROOT)}")


def visualise_rf(model, features, out_path: Path, title: str, logger):
    """Plot the first tree in a RandomForestClassifier."""
    estimator = model.estimators_[0]
    fig, ax = plt.subplots(figsize=(FIG_WIDTH, FIG_HEIGHT))
    plot_tree(
        estimator,
        feature_names=features,
        class_names=CLASS_NAMES,
        filled=True,
        max_depth=MAX_DEPTH_DISPLAY,
        fontsize=9,
        ax=ax,
    )
    n_trees = len(model.estimators_)
    _save_fig(out_path, f"{title}  (tree 0 of {n_trees}; SHAP plots show full ensemble behaviour)")
    logger.info(f"  Saved: {out_path.relative_to(PROJECT_ROOT)}")


def visualise_xgb(model, features, out_path_png: Path, out_path_csv: Path, title: str, logger):
    """
    Try to render XGBoost tree 0 as a PNG (needs Graphviz program installed).
    Falls back to saving the tree as a CSV table if Graphviz is not found.
    """
    # ── attempt graphviz image ──
    try:
        from xgboost import plot_tree as xgb_plot_tree
        fig, ax = plt.subplots(figsize=(FIG_WIDTH, FIG_HEIGHT))
        xgb_plot_tree(model, tree_idx=0, ax=ax)
        _save_fig(out_path_png, title)
        logger.info(f"  Saved: {out_path_png.relative_to(PROJECT_ROOT)}")
        return
    except Exception as exc:
        logger.warning(f"  XGBoost plot_tree failed ({type(exc).__name__}: {exc}). "
                       f"Falling back to CSV table.")
        plt.close("all")

    # ── CSV fallback ──
    df = model.get_booster().trees_to_dataframe()
    tree0 = df[df["Tree"] == 0].copy()
    tree0.to_csv(out_path_csv, index=False)
    logger.info(f"  Saved XGBoost tree-0 as table: {out_path_csv.relative_to(PROJECT_ROOT)}")
    logger.info("  Install Graphviz to get the image version: winget install graphviz  &&  pip install graphviz")


# ─── per-format runner ────────────────────────────────────────────────────────
def run_format(fmt: str, logger):
    logger.info(f"{'='*60}")
    logger.info(f"Visualising trees for format: {cfg.FORMAT_DISPLAY[fmt]}")
    logger.info(f"{'='*60}")

    folder = cfg.MODELS_DIR / fmt
    results_dir = ensure_dir(cfg.RESULTS_DIR / fmt)

    # ── load features ──
    features_path = folder / "selected_features.json"
    if not features_path.exists():
        logger.error(f"  selected_features.json not found in {folder}. Run train.py first.")
        return

    features = load_json(features_path)["selected_features"]
    logger.info(f"  Features ({len(features)}): {features}")

    # ── Decision Tree ──
    logger.info("  [1/3] Decision Tree")
    try:
        dt = load_model("dt", folder)
        visualise_dt(
            dt, features,
            results_dir / "dt_tree.png",
            f"{cfg.FORMAT_DISPLAY[fmt]} — Decision Tree (max depth {MAX_DEPTH_DISPLAY} shown)",
            logger,
        )
    except Exception:
        logger.error(f"  Decision Tree failed:\n{traceback.format_exc()}")

    # ── Random Forest ──
    logger.info("  [2/3] Random Forest (tree 0)")
    try:
        rf = load_model("rf", folder)
        visualise_rf(
            rf, features,
            results_dir / "rf_tree0.png",
            f"{cfg.FORMAT_DISPLAY[fmt]} — Random Forest estimator 0 (max depth {MAX_DEPTH_DISPLAY} shown)",
            logger,
        )
    except Exception:
        logger.error(f"  Random Forest failed:\n{traceback.format_exc()}")

    # ── XGBoost ──
    logger.info("  [3/3] XGBoost (tree 0)")
    try:
        xgb = load_model("xgb", folder)
        visualise_xgb(
            xgb, features,
            results_dir / "xgb_tree0.png",
            results_dir / "xgb_tree0.csv",
            f"{cfg.FORMAT_DISPLAY[fmt]} — XGBoost boosted tree 0",
            logger,
        )
    except Exception:
        logger.error(f"  XGBoost failed:\n{traceback.format_exc()}")

    logger.info(f"  Done. Output folder: {results_dir}")


# ─── entry point ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Visualise trained tree models for ExplainPhish.")
    parser.add_argument(
        "--format", "-f",
        choices=cfg.FORMATS + ["all"],
        default="all",
        help="File format to visualise, or 'all' for every format (default: all).",
    )
    args = parser.parse_args()

    logger = get_logger("explainphish.visualize")
    formats = cfg.FORMATS if args.format == "all" else [args.format]

    failed = []
    for fmt in formats:
        try:
            run_format(fmt, logger)
        except Exception:
            logger.error(f"{fmt} visualisation crashed:\n{traceback.format_exc()}")
            failed.append(fmt)

    if failed:
        logger.error(f"Failed formats: {failed}")
        sys.exit(1)
    else:
        logger.info("All visualisations complete.")


if __name__ == "__main__":
    main()
