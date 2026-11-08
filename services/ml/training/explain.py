"""SHAP attribution for the served models.

Class 1 is phishing (see ``modeling``), so a positive SHAP value increases the
phishing score. Values are returned in the model's margin/log-odds space, not as
probabilities: they explain *why* the score moved, they are not an additive
decomposition of the probability itself.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
import shap
from sklearn.pipeline import Pipeline

logger = logging.getLogger("phishguard.ml.shap")


class ExplainerUnavailable(RuntimeError):
    """Raised when no SHAP explainer can be built for a pipeline."""


def _feature_transform(pipeline: Pipeline):
    """Everything before the final estimator (imputer, scaler, ...)."""
    return pipeline[:-1]


def _estimator(pipeline: Pipeline):
    return pipeline[-1]


def _positive_class(values: Any) -> np.ndarray:
    array = np.asarray(values)
    if array.ndim == 3:
        # (n_samples, n_features, n_classes) -> phishing class
        array = array[:, :, 1]
    if array.ndim != 2:
        raise ExplainerUnavailable(f"unexpected SHAP shape: {array.shape}")
    return array


def build_explainer(pipeline: Pipeline, background: np.ndarray) -> tuple[Any, str]:
    """Build a TreeExplainer or LinearExplainer and report which was used."""
    transform = _feature_transform(pipeline)
    estimator = _estimator(pipeline)
    transformed = np.asarray(transform.transform(background))

    try:
        explainer = shap.TreeExplainer(estimator)
        return explainer, "tree"
    except Exception as exc:  # noqa: BLE001 - SHAP raises several unrelated types
        logger.info("TreeExplainer unavailable (%s); trying LinearExplainer", exc)

    try:
        explainer = shap.LinearExplainer(estimator, transformed)
        return explainer, "linear"
    except Exception as exc:  # noqa: BLE001
        raise ExplainerUnavailable(f"no SHAP explainer for {type(estimator).__name__}") from exc


def shap_values(
    pipeline: Pipeline,
    explainer: Any,
    features: np.ndarray,
) -> np.ndarray:
    transform = _feature_transform(pipeline)
    transformed = np.asarray(transform.transform(features))
    return _positive_class(explainer.shap_values(transformed))


def row_contributions(
    pipeline: Pipeline,
    explainer: Any,
    feature_names: tuple[str, ...],
    row: dict[str, float],
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Top-|SHAP| contributions for one row, in phishing direction."""
    matrix = np.array([[row[name] for name in feature_names]], dtype=float)
    values = shap_values(pipeline, explainer, matrix)[0]
    order = np.argsort(-np.abs(values))[:limit]
    return [
        {
            "feature": feature_names[index],
            "value": float(matrix[0, index]),
            "shap": float(values[index]),
        }
        for index in order
    ]


def global_importance(
    pipeline: Pipeline,
    explainer: Any,
    feature_names: tuple[str, ...],
    features: np.ndarray,
    max_rows: int = 2000,
) -> list[dict[str, float]]:
    """Mean absolute SHAP per feature over a bounded sample, descending."""
    sample = features if len(features) <= max_rows else features[:max_rows]
    values = shap_values(pipeline, explainer, sample)
    means = np.abs(values).mean(axis=0)
    order = np.argsort(-means)
    return [
        {"feature": feature_names[index], "mean_abs_shap": float(means[index])}
        for index in order
    ]
