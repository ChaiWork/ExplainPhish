"""5-fold stratified cross-validation (on TRAIN only), optional tuning, and final training."""
import numpy as np
from sklearn.base import clone
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_validate

from config import config as cfg
from src.utils import Timer

CV_SCORING = {"accuracy": "accuracy", "precision": "precision", "recall": "recall",
              "f1": "f1", "roc_auc": "roc_auc"}


def make_cv():
    return StratifiedKFold(n_splits=cfg.CV_FOLDS, shuffle=True, random_state=cfg.RANDOM_STATE)


def tune_model(key, model, X_train, y_train, logger):
    """Optional grid search using CV on the training set only."""
    search = GridSearchCV(clone(model), cfg.PARAM_GRIDS[key], cv=make_cv(),
                          scoring=cfg.TUNING_SCORING, n_jobs=1)
    search.fit(X_train, y_train)
    logger.info(f"  best params for {key}: {search.best_params_}")
    model.set_params(**search.best_params_)
    return model, search.best_params_


def cross_validate_model(model, X_train, y_train):
    """Return mean and std of each metric over the CV folds."""
    with Timer() as timer:
        scores = cross_validate(clone(model), X_train, y_train, cv=make_cv(),
                                scoring=CV_SCORING, n_jobs=1)
    result = {"cv_seconds": timer.seconds}
    for name in CV_SCORING:
        values = scores[f"test_{name}"]
        result[f"cv_{name}_mean"] = round(float(np.mean(values)), 4)
        result[f"cv_{name}_std"] = round(float(np.std(values)), 4)
    return result


def train_final(model, X_train, y_train):
    """Fit on the full 60% training set."""
    with Timer() as timer:
        model.fit(X_train, y_train)
    return model, timer.seconds
