"""
Voting agent: combine the three per-model predictions into a consensus verdict.

Input (from src/inference.py → predict_all_models):
    [
      {"model": "xgboost",       "prediction": 1, "probability_malicious": 0.94},
      {"model": "random_forest", "prediction": 1, "probability_malicious": 0.91},
      {"model": "decision_tree", "prediction": 0, "probability_malicious": 0.42},
    ]

Output (VoteResult dict):
    {
      "verdict":              "MALICIOUS" | "BENIGN",
      "confidence":           0.76,          # mean probability of winning class
      "confidence_band":      "HIGH" | "MEDIUM" | "LOW",
      "vote_counts":          {"malicious": 2, "benign": 1},
      "uncertain":            True,          # True when models disagree
      "model_predictions":    [...],         # original list, passed through
      "mean_prob_malicious":  0.757,
    }
"""
from __future__ import annotations

from typing import TypedDict


# ── thresholds (tune these as needed) ─────────────────────────────────────────
_CONFIDENCE_HIGH   = 0.85   # mean prob above this → HIGH
_CONFIDENCE_MEDIUM = 0.65   # mean prob above this → MEDIUM, else LOW
_UNCERTAIN_AGREE   = 3      # "uncertain" only when fewer than this many models agree


class VoteResult(TypedDict):
    verdict: str
    confidence: float
    confidence_band: str
    vote_counts: dict[str, int]
    uncertain: bool
    model_predictions: list[dict]
    mean_prob_malicious: float


def majority_vote(predictions: list[dict]) -> VoteResult:
    """
    Combine three (or any number of) model outputs into a single consensus.

    Parameters
    ----------
    predictions : list of dicts
        Each dict must have keys: "model", "prediction" (0|1),
        "probability_malicious" (float 0-1).

    Returns
    -------
    VoteResult
    """
    if not predictions:
        raise ValueError("predictions list is empty")

    mal_votes  = sum(1 for p in predictions if p["prediction"] == 1)
    ben_votes  = len(predictions) - mal_votes
    mean_prob  = sum(p["probability_malicious"] for p in predictions) / len(predictions)

    # Majority decides verdict; tie → MALICIOUS (conservative / safer default)
    if mal_votes >= ben_votes:
        verdict     = "MALICIOUS"
        confidence  = mean_prob
    else:
        verdict     = "BENIGN"
        confidence  = 1.0 - mean_prob

    # Confidence band
    if confidence >= _CONFIDENCE_HIGH:
        band = "HIGH"
    elif confidence >= _CONFIDENCE_MEDIUM:
        band = "MEDIUM"
    else:
        band = "LOW"

    # Uncertain flag: not all models agree
    max_agreeing = max(mal_votes, ben_votes)
    uncertain = max_agreeing < _UNCERTAIN_AGREE

    return VoteResult(
        verdict=verdict,
        confidence=round(confidence, 4),
        confidence_band=band,
        vote_counts={"malicious": mal_votes, "benign": ben_votes},
        uncertain=uncertain,
        model_predictions=predictions,
        mean_prob_malicious=round(mean_prob, 4),
    )
