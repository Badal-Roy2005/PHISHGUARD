"""Shared fixtures: a small synthetic PhiUSIIL-shaped dataset and real artifacts.

The synthetic frame keeps the exact 56-column shape of the official file, so the
production code paths run unmodified. It is deliberately small (60 domains), which
makes training and inference tests fast and deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import pytest

from app.inference import ModelService
from training.config import (
    ALL_NUMERIC_FEATURES,
    FEATURE_CONTRACT_VERSION,
    LABEL_COLUMN,
    MODEL_VERSION,
    URL_ONLY_FEATURES,
    feature_sets,
)
from training.dataset import build_splits
from training.features import build_feature_contract, build_manifest
from training.modeling import build_pipeline, evaluate, is_phishing, phishing_probability

IDENTIFIER_COLUMNS = ["FILENAME", "URL", "Domain", "TLD", "Title"]
COLUMNS = IDENTIFIER_COLUMNS + [*ALL_NUMERIC_FEATURES, LABEL_COLUMN]


def make_frame(n_domains: int = 60, seed: int = 7) -> pd.DataFrame:
    """60 unique registrable domains, alternating phishing/legitimate."""
    rng = np.random.default_rng(seed)
    rows: list[dict[str, Any]] = []
    for index in range(n_domains):
        label = 0 if index % 2 == 0 else 1
        domain = f"site{index}.com"
        row: dict[str, Any] = {
            "FILENAME": f"page{index}.html",
            "URL": f"https://{domain}/path",
            "Domain": domain,
            "TLD": "com",
            "Title": f"Site {index}",
        }
        for position, name in enumerate(ALL_NUMERIC_FEATURES):
            value = rng.normal(20.0 + position, 1.5)
            if label == 0:  # phishing rows drift upward on even features
                value += 4.0 if position % 2 == 0 else -1.0
            row[name] = round(float(value), 6)
        row[LABEL_COLUMN] = label
        rows.append(row)
    return pd.DataFrame(rows, columns=COLUMNS)


@pytest.fixture()
def synthetic_frame() -> pd.DataFrame:
    return make_frame()


@pytest.fixture()
def csv_path(tmp_path: Path, synthetic_frame: pd.DataFrame) -> Path:
    path = tmp_path / "synthetic_phiusiil.csv"
    synthetic_frame.to_csv(path, index=False)
    return path


@pytest.fixture(scope="session")
def manifest() -> dict[str, Any]:
    return build_manifest()


def write_artifacts(
    directory: Path,
    splits: Any,
    algorithm: str = "logistic_regression",
) -> dict[str, Any]:
    """Train a small model and write the same artifact set that train.py writes."""
    directory.mkdir(parents=True, exist_ok=True)
    columns = URL_ONLY_FEATURES
    train = splits.train.frame
    test = splits.test.frame

    pipeline = build_pipeline(algorithm, list(columns))
    pipeline.fit(
        train[list(columns)].to_numpy(dtype=float),
        is_phishing(train[LABEL_COLUMN]),
    )
    probabilities = phishing_probability(pipeline, test[list(columns)].to_numpy(dtype=float))
    test_metrics = evaluate(is_phishing(test[LABEL_COLUMN]), probabilities, 0.5)

    model_path = directory / "model.joblib"
    joblib.dump(pipeline, model_path)
    joblib.dump(pipeline[:-1], directory / "preprocessor.joblib")

    contract = build_feature_contract(
        build_manifest(),
        tuple(columns),
        version=FEATURE_CONTRACT_VERSION,
        model_version=MODEL_VERSION,
        dataset={"name": "synthetic", "rows": 60, "feature_count": len(columns)},
    )
    (directory / "feature_contract.json").write_text(json.dumps(contract), encoding="utf-8")

    metadata = {
        "name": f"phiusiil-{algorithm}",
        "version": MODEL_VERSION,
        "trained_at": "2026-11-09T00:00:00Z",
        "dataset": "synthetic",
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "label_map": {"0": "phishing", "1": "legitimate"},
        "metrics": {
            "accuracy": test_metrics["accuracy"],
            "precision": test_metrics["precision_phishing"],
            "recall": test_metrics["recall_phishing"],
            "f1": test_metrics["f1_phishing"],
            "roc_auc": test_metrics["roc_auc"],
            "pr_auc": test_metrics["pr_auc"],
        },
    }
    selected = {
        "served": {
            "feature_set": "live",
            "algorithm": algorithm,
            "feature_count": len(columns),
            "threshold": 0.5,
            "test": test_metrics,
        },
        "model": metadata,
        "feature_contract_version": FEATURE_CONTRACT_VERSION,
        "feature_order": list(columns),
        "threshold": 0.5,
    }
    (directory / "selected.json").write_text(json.dumps(selected), encoding="utf-8")
    return selected


@pytest.fixture()
def splits(synthetic_frame: pd.DataFrame) -> Any:
    return build_splits(synthetic_frame)


@pytest.fixture()
def artifacts_dir(tmp_path: Path, splits: Any) -> Path:
    directory = tmp_path / "artifacts"
    write_artifacts(directory, splits)
    return directory


@pytest.fixture()
def service(artifacts_dir: Path) -> ModelService:
    return ModelService(
        artifacts_dir / "model.joblib",
        artifacts_dir / "feature_contract.json",
    )


def sample_features(strategy: str = "median") -> dict[str, float]:
    frame = make_frame()
    if strategy == "phishing":
        row = frame[frame[LABEL_COLUMN] == 0].iloc[0]
    elif strategy == "legitimate":
        row = frame[frame[LABEL_COLUMN] == 1].iloc[0]
    else:
        row = frame.iloc[0]
    return {name: float(row[name]) for name in URL_ONLY_FEATURES}


def live_feature_sets():
    return feature_sets(list(ALL_NUMERIC_FEATURES))
