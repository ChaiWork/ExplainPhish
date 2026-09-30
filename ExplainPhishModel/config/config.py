"""
Central configuration for the ExplainPhish training pipeline.
Every student uses the SAME file; only the --format argument changes.
Edit values here instead of touching the source code.
"""
from pathlib import Path

# ----------------------------------------------------------------- paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
RESULTS_DIR = PROJECT_ROOT / "results"
LOGS_DIR = PROJECT_ROOT / "logs"

FORMATS = ["pdf", "word", "excel", "html"]
FORMAT_DISPLAY = {"pdf": "PDF", "word": "Word", "excel": "Excel", "html": "HTML"}

# ----------------------------------------------------------- reproducibility
RANDOM_STATE = 42
TEST_SIZE = 0.40          # 60% train / 40% test
CV_FOLDS = 5              # stratified CV inside the training set only

# ------------------------------------------------------- data stabilization
# Names that may hold the target column (case-insensitive). If none is found,
# the pipeline tries to infer labels from file names (e.g. benign.csv).
LABEL_COLUMN_CANDIDATES = ["label", "class", "target", "malicious",
                           "is_malicious", "y", "category", "type"]

# Label normalisation: everything is compared as lowercase text.
BENIGN_LABELS = {"0", "benign", "legitimate", "legit", "clean", "normal", "safe", "good"}
MALICIOUS_LABELS = {"1", "malicious", "phishing", "phish", "malware", "bad", "suspicious"}

# Columns you want removed for a given format (file names, record IDs, ...).
# Example: EXCLUDE_COLUMNS = {"pdf": ["FileName", "RecordID"]}
EXCLUDE_COLUMNS = {"pdf": [], "word": [], "excel": [], "html": []}

# Column-name tokens that look like identifiers. A match is only removed
# automatically if the column is non-numeric OR (numeric and almost all unique).
# Note: "path" intentionally excluded — path_* are real XML-path count features in the Word dataset.
ID_NAME_TOKENS = {"id", "idx", "index", "filename", "name", "hash",
                  "md5", "sha1", "sha256", "uuid", "rownum"}

# Exact column names (lowercase) that reveal the target -> always removed.
LEAKAGE_EXACT_NAMES = {"label", "labels", "class", "target", "y", "verdict",
                       "is_malicious", "malicious", "is_phishing", "benign",
                       "category", "type", "family", "malware_type", "attack_type"}

MAX_MISSING_COLUMN_FRACTION = 0.50   # drop a column if more than 50% is missing
MAX_CATEGORICAL_LEVELS = 50          # text columns with more levels are treated as identifiers
MAX_CATEGORICAL_UNIQUE_RATIO = 0.50

LEAKAGE_AUC_REMOVE = 0.985           # one feature alone separates classes this well -> removed
LEAKAGE_AUC_WARN = 0.98              # warn only
REMOVE_STATISTICAL_LEAKAGE = True

# Per-format override for the remove threshold.  Use 1.001 to effectively
# disable removal for a format whose dataset is too synthetic to survive
# a strict cut.  Word no longer needs an override: with 44 raw columns,
# the standard 0.985 threshold removes ~11 format-proxy features and
# leaves ~24 genuine content features for selection.
LEAKAGE_AUC_REMOVE_OVERRIDE = {}
DROP_CONFLICTING_LABEL_ROWS = True   # identical features but different labels

OUTLIER_IQR_MULTIPLIER = 3.0         # outliers are REPORTED, never deleted
SAVE_CLEANED_DATASET = False

# --------------------------------------------------------- class balancing
BALANCE_TOLERANCE = 0.05             # 45%-55% counts as "approximately 50/50"

# -------------------------------------------------------- feature selection
# "auto"     : use PROVIDED_FEATURES if non-empty, otherwise select from training data
# "provided" : must use PROVIDED_FEATURES
# "own"      : always run our own selection (train set only)
FEATURE_SELECTION_MODE = "auto"

# Mode A: paste the dataset authors' feature names here (must exist as columns).
PROVIDED_FEATURES = {"pdf": [], "word": [], "excel": [], "html": []}

# Mode B: how many features to keep after leakage removal.
TOP_N_FEATURES = {"pdf": 10, "word": 10, "excel": 10, "html": 13}
SHAP_SELECTION_SAMPLES = 2000        # train rows used for SHAP ranking

# ------------------------------------------------------------ model settings
XGB_PARAMS = dict( n_estimators=300,
    max_depth=5,
    learning_rate=0.06,
    subsample=0.85,
    colsample_bytree=0.8,
    reg_alpha=0.1,
    reg_lambda=1.5,
    eval_metric="logloss",
    random_state=RANDOM_STATE,
    n_jobs=-1,)


RF_PARAMS = dict(   n_estimators=250,
    max_depth=16,
    min_samples_leaf=2,
    max_features="sqrt",
    random_state=RANDOM_STATE,
    n_jobs=-1,
    
    )

DT_PARAMS = dict(    max_depth=7,
    min_samples_leaf=10,
    min_samples_split=20,
    random_state=RANDOM_STATE,)

# Optional grid search (5-fold CV on the training set only). Off by default.
TUNE_HYPERPARAMETERS = False
TUNING_SCORING = "f1"
PARAM_GRIDS = {
    "xgb": {"max_depth": [3, 6], "learning_rate": [0.05, 0.1], "n_estimators": [200, 400]},
    "rf": {"n_estimators": [100, 200, 300], "max_depth": [None, 10, 20]},
    "dt": {"max_depth": [5, 8, 12, None], "min_samples_leaf": [1, 2, 5]},
}

# ------------------------------------------------------------------- SHAP
SHAP_MAX_SAMPLES = 1000              # test rows used for the global summary plot
SHAP_MAX_DISPLAY = 12                # features shown in plots
