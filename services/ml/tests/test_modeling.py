from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from training.config import LABEL_COLUMN, URL_ONLY_FEATURES
from training.modeling import (
    build_pipeline,
    evaluate,
    is_phishing,
    phishing_probability,
    tune_threshold,
)


def _xy(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    return (
        frame[list(URL_ONLY_FEATURES)].to_numpy(dtype=float),
        is_phishing(frame[LABEL_COLUMN]),
    )


def test_is_phishing_uses_the_dataset_zero_label() -> None:
    labels = pd.Series([0, 1, 0, 1])
    assert is_phishing(labels).tolist() == [1, 0, 1, 0]


def test_imputer_learns_training_medians_not_zero(synthetic_frame: pd.DataFrame) -> None:
    frame = synthetic_frame.copy()
    frame.loc[0, "URLLength"] = np.nan
    frame.loc[1, "URLLength"] = np.nan
    pipeline = build_pipeline("logistic_regression", list(URL_ONLY_FEATURES))
    x_train, y_train = _xy(frame)
    pipeline.fit(x_train, y_train)

    imputer = pipeline.named_steps["imputer"]
    position = list(URL_ONLY_FEATURES).index("URLLength")
    expected = frame["URLLength"].median()
    assert imputer.statistics_[position] == pytest.approx(expected)
    assert expected != 0


@pytest.mark.parametrize("algorithm", ["logistic_regression", "random_forest"])
def test_training_is_reproducible(
    algorithm: str, synthetic_frame: pd.DataFrame
) -> None:
    x_train, y_train = _xy(synthetic_frame)
    first = build_pipeline(algorithm, list(URL_ONLY_FEATURES), random_state=42)
    second = build_pipeline(algorithm, list(URL_ONLY_FEATURES), random_state=42)
    first.fit(x_train, y_train)
    second.fit(x_train, y_train)
    first_probability = phishing_probability(first, x_train)
    second_probability = phishing_probability(second, x_train)
    # n_jobs=-1 may reorder float additions at the last bit, but the decision
    # boundary itself must be identical.
    np.testing.assert_allclose(first_probability, second_probability, rtol=0, atol=1e-12)
    assert np.array_equal(first_probability >= 0.5, second_probability >= 0.5)


def test_serialization_roundtrip_preserves_predictions(
    synthetic_frame: pd.DataFrame, tmp_path
) -> None:
    import joblib

    x_train, y_train = _xy(synthetic_frame)
    pipeline = build_pipeline("logistic_regression", list(URL_ONLY_FEATURES))
    pipeline.fit(x_train, y_train)
    path = tmp_path / "model.joblib"
    joblib.dump(pipeline, path)
    restored = joblib.load(path)
    assert np.array_equal(
        phishing_probability(pipeline, x_train),
        phishing_probability(restored, x_train),
    )


def test_phishing_probability_runs_in_the_expected_direction(
    synthetic_frame: pd.DataFrame,
) -> None:
    x_train, y_train = _xy(synthetic_frame)
    pipeline = build_pipeline("random_forest", list(URL_ONLY_FEATURES))
    pipeline.fit(x_train, y_train)
    probabilities = phishing_probability(pipeline, x_train)
    assert probabilities[y_train == 1].mean() > probabilities[y_train == 0].mean()


def test_threshold_tuning_picks_the_best_f1() -> None:
    y_true = np.array([1, 1, 1, 0, 0, 0, 0, 0])
    probabilities = np.array([0.9, 0.8, 0.4, 0.7, 0.6, 0.2, 0.1, 0.05])
    tuned = tune_threshold(y_true, probabilities)
    best_f1 = max(
        evaluate(y_true, probabilities, float(threshold))["f1_phishing"]
        for threshold in np.round(np.arange(0.05, 0.951, 0.005), 3)
    )
    assert tuned["f1"] == pytest.approx(best_f1)


def test_evaluate_reports_phishing_class_metrics() -> None:
    y_true = np.array([1, 1, 0, 0])
    probabilities = np.array([0.9, 0.4, 0.6, 0.1])
    metrics = evaluate(y_true, probabilities, 0.5)
    # predicted: [1, 0, 1, 0] -> TP=1, FN=1, FP=1, TN=1
    assert metrics["precision_phishing"] == pytest.approx(0.5)
    assert metrics["recall_phishing"] == pytest.approx(0.5)
    assert metrics["f1_phishing"] == pytest.approx(0.5)
    assert metrics["accuracy"] == pytest.approx(0.5)
    assert metrics["confusion_matrix"]["matrix"] == [[1, 1], [1, 1]]
    assert metrics["support"] == {"legitimate": 2, "phishing": 2}


def test_threshold_tuning_requires_both_classes() -> None:
    with pytest.raises(ValueError, match="both classes"):
        tune_threshold(np.array([1, 1, 1]), np.array([0.9, 0.8, 0.7]))


def test_unknown_algorithm_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown algorithm"):
        build_pipeline("magic", list(URL_ONLY_FEATURES))
