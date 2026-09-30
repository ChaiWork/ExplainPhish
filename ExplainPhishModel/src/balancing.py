"""STAGE 2 - CLASS BALANCING: verify 50/50, otherwise random undersampling (fixed seed)."""
import numpy as np
import pandas as pd

from config import config as cfg


def check_and_balance(X, y, logger):
    """Return (X, y, info). Never uses synthetic oversampling."""
    counts = y.value_counts().reindex([0, 1], fill_value=0)
    total = int(counts.sum())
    if counts.min() == 0:
        raise ValueError(f"Only one class present after cleaning: {counts.to_dict()}")
    share_malicious = counts[1] / total
    logger.info(f"Original class distribution: Benign={counts[0]} ({100 * (1 - share_malicious):.2f}%), "
                f"Malicious={counts[1]} ({100 * share_malicious:.2f}%)")

    info = {"before": {"benign": int(counts[0]), "malicious": int(counts[1])},
            "malicious_share_before": round(float(share_malicious), 4)}
    balanced = abs(share_malicious - 0.5) <= cfg.BALANCE_TOLERANCE
    if balanced:
        logger.info("Dataset is approximately 50/50 - keeping all samples.")
        info["method"] = "none (already balanced)"
    else:
        rng = np.random.RandomState(cfg.RANDOM_STATE)
        n_keep = int(counts.min())
        kept = []
        for label in (0, 1):
            idx = y.index[y == label].to_numpy()
            kept.append(idx if len(idx) == n_keep else rng.choice(idx, size=n_keep, replace=False))
        keep_index = np.sort(np.concatenate(kept))
        X, y = X.loc[keep_index], y.loc[keep_index]
        info["method"] = f"random undersampling of majority class (seed {cfg.RANDOM_STATE})"
        logger.info(f"Not balanced -> undersampled majority class to {n_keep} rows.")

    final = y.value_counts().reindex([0, 1], fill_value=0)
    info["after"] = {"benign": int(final[0]), "malicious": int(final[1])}
    logger.info(f"Final class distribution: Benign={final[0]}, Malicious={final[1]}")
    return X, y, info
