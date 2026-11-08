from __future__ import annotations

import math

import pytest
from phishguard_contracts import PredictRequest

from app.inference import (
    InvalidFeatureValueError,
    ModelNotAvailable,
    ModelService,
    UnknownFeatureError,
)
from tests.conftest import sample_features


def test_predict_returns_ok_when_every_feature_is_present(service: ModelService) -> None:
    response = service.predict(PredictRequest(features=sample_features()), explain=False)
    assert response.status == "ok"
    assert response.missing_features == []
    assert 0.0 <= response.probability_phishing <= 1.0
    assert response.label in {"phishing", "legitimate"}
    assert response.model.version == "1.0.0"
    assert response.model.feature_contract_version == "2"
    assert response.model.label_map == {"0": "phishing", "1": "legitimate"}


def test_feature_order_does_not_change_the_probability(service: ModelService) -> None:
    features = sample_features()
    reversed_features = dict(reversed(list(features.items())))
    first = service.predict(PredictRequest(features=features), explain=False)
    second = service.predict(PredictRequest(features=reversed_features), explain=False)
    assert first.probability_phishing == pytest.approx(second.probability_phishing, abs=1e-12)


def test_one_missing_feature_is_partial_and_reported(service: ModelService) -> None:
    features = sample_features()
    features.pop("URLLength")
    response = service.predict(PredictRequest(features=features), explain=False)
    assert response.status == "partial"
    assert response.missing_features == ["URLLength"]
    assert 0.0 <= response.probability_phishing <= 1.0


def test_mostly_missing_features_are_unknown_not_safe(service: ModelService) -> None:
    features = {"URLLength": 40.0}
    response = service.predict(PredictRequest(features=features), explain=False)
    assert response.status == "unknown"
    assert response.label == "unknown"
    assert len(response.missing_features) == 17


def test_booleans_and_numeric_strings_are_accepted(service: ModelService) -> None:
    features = sample_features()
    features["IsHTTPS"] = True
    features["URLLength"] = "41"
    response = service.predict(PredictRequest(features=features), explain=False)
    assert response.status == "ok"


def test_unknown_feature_names_are_rejected(service: ModelService) -> None:
    features = sample_features()
    features["HasPasswordField"] = 1
    with pytest.raises(UnknownFeatureError, match="HasPasswordField"):
        service.predict(PredictRequest(features=features), explain=False)


def test_non_numeric_values_are_rejected(service: ModelService) -> None:
    features = sample_features()
    features["URLLength"] = "not-a-number"
    with pytest.raises(InvalidFeatureValueError, match="URLLength"):
        service.predict(PredictRequest(features=features), explain=False)


def test_non_finite_values_are_rejected(service: ModelService) -> None:
    features = sample_features()
    features["URLLength"] = math.inf
    with pytest.raises(InvalidFeatureValueError, match="finite"):
        service.predict(PredictRequest(features=features), explain=False)


def test_explanations_name_only_contract_features(service: ModelService) -> None:
    response = service.predict(PredictRequest(features=sample_features()), explain=True)
    assert response.contributions, "SHAP should produce contributions for a linear model"
    assert len(response.contributions) <= 20
    assert {contribution.feature for contribution in response.contributions} <= set(
        service.load().feature_order
    )


def test_missing_artifacts_raise_model_not_available(tmp_path) -> None:
    service = ModelService(tmp_path / "model.joblib", tmp_path / "feature_contract.json")
    with pytest.raises(ModelNotAvailable, match="missing artifacts"):
        service.predict(PredictRequest(features=sample_features()))
    assert not service.loaded


def test_info_reports_the_contract_and_missing_policy(service: ModelService) -> None:
    info = service.info()
    assert info["model"]["version"] == "1.0.0"
    assert len(info["feature_order"]) == 18
    assert info["feature_count"] == 18
    assert info["missing_policy"]["insufficient_evidence"] == "status=unknown, label=unknown"
    assert info["explainer"] in {"tree", "linear", "unavailable"}
