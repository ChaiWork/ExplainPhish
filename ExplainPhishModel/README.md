# ExplainPhish - Training Pipeline

Explainable phishing-attachment detection (Scam Defence track). This repo contains ONLY the
machine-learning training pipeline (no UI, no agents). Files are analysed as static feature
tables; no macro, script or document payload is ever executed.

## 1. Objective
For each format (PDF, Word, Excel, HTML) train XGBoost, Random Forest and Decision Tree on
CIC-Trap4Phish2025 features -> 12 models, with evaluation, feature importance and SHAP explanations.

## 2. Pipeline
Data stabilization -> class-balance check -> stratified 60/40 split -> feature selection (train only)
-> 5-fold stratified CV (train only) -> final training -> one evaluation on the untouched 40% test set
-> feature importance -> SHAP -> save models/preprocessing/selected features.

## 3. Dataset structure (assumptions)
* One folder per format: `data/pdf/`, `data/word/`, `data/excel/`, `data/html/`.
* Each folder holds one or more **CSV** files (they are stacked together).
* Columns = feature columns + one label column (auto-detected: `label`, `class`, `target`, ...;
  add your name to `LABEL_COLUMN_CANDIDATES` in `config/config.py` if different).
* Labels may be text (`Benign`/`Malicious`, ...) or 0/1. Unknown values are reported and dropped.
* If there is no label column but files are named like `benign.csv` / `malicious.csv`, labels come from the file names.
* Feature names are never hard-coded. For the authors' selected features, paste them into `PROVIDED_FEATURES`.

## 4. Install
```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 5. Run
```bash
python train.py --format pdf      # Student 1
python train.py --format word     # Student 2
python train.py --format excel    # Student 3
python train.py --format html     # Student 4
python train.py --format all      # everything, same methodology
```
Optional: `--tune` (grid search with 5-fold CV on train) and `--feature-mode auto|provided|own`.
All settings (seed, split, hyperparameters, TOP_N_FEATURES, excluded columns) live in `config/config.py`.

## 6. Outputs
* `models/<format>/` : `xgb_model.json`, `rf_model.joblib`, `dt_model.joblib`, `preprocessing.joblib`, `selected_features.json`
* `results/<format>/` : `training_summary.json`, `metrics.csv`, `test_predictions.csv`,
  `{xgb,rf,dt}_confusion_matrix.png`, `_feature_importance.csv/.png`, SHAP files, `stabilization/` reports
  (missing values, dtypes, removed columns + reasons, statistics, suspicious outliers)
* `results/model_comparison.csv` and `.json` : combined table of every format trained so far
* `logs/<format>_training.log`

## 7. SHAP
After each final model is trained, `src/explainability.py` writes (prefix `xgb`, `rf`, `dt`):
* Global: `*_shap_summary.png`, `*_shap_bar.png`, `*_shap_importance.csv`
* Local (one document each): `*_shap_local_true_positive|true_negative|false_positive|false_negative.png/.csv`
  showing which features pushed that test file towards Malicious or Benign.

## 8. Later use (voting agent)
`src/inference.py` loads the saved models + preprocessing and returns, per model,
`{"model": "xgboost", "prediction": 1, "probability_malicious": 0.94}`.

## Notes
* Missing values: columns >50% empty are dropped; the rest are imputed (median / category) with values learned from the TRAIN set only.
* Feature selection and CV use the training set only; the test set is used once for final metrics.
* Leakage checks: exact target-like column names, file-name source, and any single feature that separates the classes almost perfectly (AUC >= 0.999) are removed and logged.
