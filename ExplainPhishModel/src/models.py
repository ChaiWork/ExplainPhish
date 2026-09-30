"""The three algorithms, saving/loading, and the prediction format for the future voting agent."""
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

from config import config as cfg

MODEL_KEYS = ["xgb", "rf", "dt"]
MODEL_DISPLAY = {"xgb": "XGBoost", "rf": "Random Forest", "dt": "Decision Tree"}
MODEL_IDS = {"xgb": "xgboost", "rf": "random_forest", "dt": "decision_tree"}
MODEL_FILES = {"xgb": "xgb_model.json", "rf": "rf_model.joblib", "dt": "dt_model.joblib"}


def build_model(key):
    """Create an untrained model with the hyperparameters from config.py."""
    if key == "xgb":
        return XGBClassifier(**cfg.XGB_PARAMS)
    if key == "rf":
        return RandomForestClassifier(**cfg.RF_PARAMS)
    if key == "dt":
        return DecisionTreeClassifier(**cfg.DT_PARAMS)
    raise ValueError(f"Unknown model key: {key}")


def save_model(key, model, folder):
    path = folder / MODEL_FILES[key]
    if key == "xgb":
        model.save_model(str(path))      # XGBoost native JSON format
    else:
        joblib.dump(model, path)
    return path


def load_model(key, folder):
    path = folder / MODEL_FILES[key]
    if key == "xgb":
        model = XGBClassifier()
        model.load_model(str(path))
        return model
    return joblib.load(path)


def predict_with_model(key, model, X):
    """One dict per row: {'model', 'prediction', 'probability_malicious'} (voting-agent ready)."""
    proba = model.predict_proba(X)[:, 1]
    return [{"model": MODEL_IDS[key], "prediction": int(p >= 0.5), "probability_malicious": round(float(p), 4)}
            for p in proba]
