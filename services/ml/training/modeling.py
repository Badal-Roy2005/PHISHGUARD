"""Model pipelines, threshold tuning and evaluation metrics.

Target convention
-----------------
The dataset labels are ``0 = phishing``, ``1 = legitimate``. Training on that
column directly would make ``predict_proba[:, 1]`` mean "legitimate", which is a
reliable source of inverted explanations.

Every model here is trained on an explicit derived target::

    y = 1 if dataset label == 0 (phishing) else 0

So class 1 is always phishing. The dataset mapping still lives in the contract
and in ``LABEL_MAP``; only the model's internal target is flipped, and
``training/tests`` assert both directions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from .config import PHISHING_LABEL, RANDOM_STATE

ALGORITHMS = ("logistic_regression", "random_forest", "xgboost")

#: Empty cells in the source file are zero, but a live caller can omit a feature.
#: The imputer is fitted on training medians; inference reports every imputed name
#: so a median is never mistaken for a measurement.
IMPUTER_STRATEGY = "median"


def build_pipeline(
    algorithm: str,
    feature_names: list[str],
    random_state: int = RANDOM_STATE,
) -> Pipeline:
    """Return an unfitted pipeline for one algorithm and feature order."""
    if algorithm not in ALGORITHMS:
        raise ValueError(f"unknown algorithm: {algorithm}")
    if not feature_names:
        raise ValueError("feature_names must not be empty")

    imputer = SimpleImputer(strategy=IMPUTER_STRATEGY)
    if algorithm == "logistic_regression":
        steps: list[tuple[str, Any]] = [
            ("imputer", imputer),
            ("scaler", StandardScaler()),
            ("model", LogisticRegression(max_iter=2000, random_state=random_state)),
        ]
    elif algorithm == "random_forest":
        steps = [
            ("imputer", imputer),
            (
                "model",
                RandomForestClassifier(
                    n_estimators=200,
                    min_samples_leaf=2,
                    n_jobs=-1,
                    random_state=random_state,
                ),
            ),
        ]
    else:
        steps = [
            ("imputer", imputer),
            (
                "model",
                XGBClassifier(
                    n_estimators=300,
                    max_depth=6,
                    learning_rate=0.1,
                    subsample=0.9,
                    colsample_bytree=0.9,
                    tree_method="hist",
                    eval_metric="logloss",
                    n_jobs=-1,
                    random_state=random_state,
                ),
            ),
        ]
    return Pipeline(steps)


def is_phishing(labels: Any) -> np.ndarray:
    """Map dataset labels to the model target (1 = phishing)."""
    values = np.asarray(labels)
    return (values == PHISHING_LABEL).astype(int)


def phishing_probability(pipeline: Pipeline, features: np.ndarray) -> np.ndarray:
    """Probability of class 1, which is defined as phishing."""
    return np.asarray(pipeline.predict_proba(features)[:, 1], dtype=float)


def tune_threshold(y_true: np.ndarray, probabilities: np.ndarray) -> dict[str, float]:
    """Pick the threshold that maximises phishing F1 on the validation split.

    Ties are broken by higher recall, then by the higher threshold (fewer
    false positives at the same F1). The search grid is fixed and coarse so the
    result is reproducible and does not overfit a single lucky cut.
    """
    if len(np.unique(y_true)) < 2:
        raise ValueError("threshold tuning needs both classes")
    grid = np.round(np.arange(0.05, 0.951, 0.005), 3)
    best: dict[str, float] | None = None
    for threshold in grid:
        predicted = (probabilities >= threshold).astype(int)
        f1 = f1_score(y_true, predicted, pos_label=1, zero_division=0)
        recall = recall_score(y_true, predicted, pos_label=1, zero_division=0)
        candidate = {"threshold": float(threshold), "f1": float(f1), "recall": float(recall)}
        if best is None or (candidate["f1"], candidate["recall"], candidate["threshold"]) > (
            best["f1"],
            best["recall"],
            best["threshold"],
        ):
            best = candidate
    assert best is not None
    return best


def evaluate(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    """Metrics for the phishing class (1), measured at a fixed threshold."""
    predicted = (probabilities >= threshold).astype(int)
    report = classification_report(
        y_true,
        predicted,
        labels=[0, 1],
        target_names=["legitimate", "phishing"],
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_true, predicted, labels=[0, 1])
    return {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_true, predicted)),
        "precision_phishing": float(
            precision_score(y_true, predicted, pos_label=1, zero_division=0)
        ),
        "recall_phishing": float(recall_score(y_true, predicted, pos_label=1, zero_division=0)),
        "f1_phishing": float(f1_score(y_true, predicted, pos_label=1, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, probabilities)),
        "pr_auc": float(average_precision_score(y_true, probabilities)),
        "support": {
            "legitimate": int(report["legitimate"]["support"]),
            "phishing": int(report["phishing"]["support"]),
        },
        "confusion_matrix": {
            "labels": ["legitimate", "phishing"],
            "matrix": matrix.astype(int).tolist(),
        },
        "classification_report": report,
    }


@dataclass(frozen=True)
class TrainedModel:
    algorithm: str
    feature_names: tuple[str, ...]
    pipeline: Pipeline
    threshold: float
    validation: dict[str, Any]
    test: dict[str, Any]

    def predict_probabilities(self, features: np.ndarray) -> np.ndarray:
        return phishing_probability(self.pipeline, features)
