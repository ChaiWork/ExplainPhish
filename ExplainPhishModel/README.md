# ExplainPhish - Training Pipeline

Explainable phishing-attachment detection (Scam Defence track). This repo contains the
machine-learning training pipeline (models: XGBoost, Random Forest, Decision Tree). Files are analysed as static feature
tables; no macro, script, or document payload is ever executed.

> [!WARNING]
> For detailed scientific findings regarding dataset artefacts, shortcut learning, and generalization limits across Word, Excel, PDF, and HTML, read [LIMITATIONS.md](file:///d:/codingProject/ExplainPhish/ExplainPhishModel/LIMITATIONS.md).

---

## 1. Objective
For each format (PDF, Word, Excel, HTML) train XGBoost, Random Forest, and Decision Tree on
CIC-Trap4Phish2025 features -> 12 models, with 5-fold CV, evaluation, feature importance, and SHAP explanations.

## 2. Pipeline Architecture & Integrity Rules
* **Data Stabilization**: Label-agnostic checks (duplicates, dtypes, constants, ID/name columns, target-name leakage).
* **Stratified 60/40 Split**: Seed 42. The 40% test set is held out and NEVER used for feature selection, leakage removal, hyperparameter tuning, or threshold decisions.
* **Train-Only Shortcut Audit (`src/shortcut_audit.py`)**: Runs strictly on the 60% training split. Computes single-feature AUCs, depth-1 decision stump 5-fold CV F1, tree importance dominance, missingness indicator AUCs, and pairwise colinearities. Flags `likely_shortcut = true` if a stump reaches CV F1 $\ge 0.99$ or a feature captures $\ge 90\%$ of tree importance.
* **Feature Selection**: Ranked using training-only importance + SHAP (Mode B top-N: PDF 10, Word 10, Excel 10, HTML 13).
* **Cross-Validation**: 5-fold stratified CV on the training split only.
* **Single Evaluation**: Models evaluated once on the untouched test set for final reporting.
* **Ensemble Diversity Diagnostics**: Pairwise disagreement, error correlation, and all-models-wrong count logged to `training_summary.json`.

## 3. Usage

### Standard Baseline Training
```bash
python train.py --format pdf      # PDF models
python train.py --format word     # Word models
python train.py --format excel    # Excel models
python train.py --format html     # HTML models
python train.py --format all      # All formats sequentially
```

### Training with High-AUC Leakage Removal
```bash
python train.py --format all --remove-high-auc --results-dir results_high_auc_removed --models-dir models_high_auc_removed
```

### Controlled Ablation Suite
Evaluates baseline, without macro/OLE/DDE, without format proxies, without both, and without audit-flagged features:
```bash
python ablation.py --format all   # or --format <pdf|word|excel|html>
```
Outputs: `results/<format>/ablation.csv`.

### Word OOXML-Only Experiment
Evaluates whether restricting Word documents to those with XML parts alters shortcut reliance:
```bash
python -m src.word_ooxml_experiment
```
Outputs: `results_word_ooxml_only/`.

### External Evaluation Harness
Evaluate trained models against new, out-of-distribution feature CSVs:
```bash
python external_eval.py --format <pdf|word|excel|html> --csv <path_to_unseen_features.csv>
```

---

## 4. Key Outputs
* `models/<format>/` : `xgb_model.json`, `rf_model.joblib`, `dt_model.joblib`, `preprocessing.joblib`, `selected_features.json`
* `results/<format>/` : `training_summary.json`, `metrics.csv`, `test_predictions.csv`, `shortcut_audit.json`, `shortcut_audit.csv`, `ablation.csv`, `{xgb,rf,dt}_confusion_matrix.png`, `_feature_importance.csv/.png`, SHAP visualisations.
* `results/model_comparison.csv` and `.json` : Unified comparison across all formats.
