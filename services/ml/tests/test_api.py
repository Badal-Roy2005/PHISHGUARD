from __future__ import annotations

import math
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from phishguard_contracts import PredictResponse

from app.main import create_app
from app.settings import load_settings
from tests.conftest import sample_features

TOKEN = "dev-only-change-me-please"
HEADERS = {"X-Service-Token": TOKEN}


def _client(artifacts_dir: Path) -> TestClient:
    settings = load_settings({"ENV": "test", "ARTIFACTS_DIR": str(artifacts_dir)})
    return TestClient(create_app(settings))


@pytest.fixture()
def client(artifacts_dir: Path) -> TestClient:
    return _client(artifacts_dir)


def test_health_reports_ready_model(client: TestClient) -> None:
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["checks"]["model"] == "ready"
    assert body["feature_schema_version"] == "2"


def test_model_info_exposes_metadata_and_feature_schema(client: TestClient) -> None:
    response = client.get("/model/info")
    assert response.status_code == 200
    body = response.json()
    assert body["model"]["version"] == "1.0.0"
    assert body["model"]["feature_contract_version"] == "2"
    assert body["feature_contract"]["version"] == "2"
    assert [feature["name"] for feature in body["feature_contract"]["features"]] == body[
        "feature_order"
    ]
    assert body["feature_count"] == 18


def test_predict_requires_a_service_token(client: TestClient) -> None:
    response = client.post("/predict", json={"features": sample_features()})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_predict_matches_the_wire_contract(client: TestClient) -> None:
    response = client.post("/predict", json={"features": sample_features()}, headers=HEADERS)
    assert response.status_code == 200
    parsed = PredictResponse.model_validate(response.json())
    assert parsed.status == "ok"
    assert parsed.model.version == "1.0.0"
    assert parsed.model.feature_contract_version == "2"
    assert 0.0 <= parsed.probability_phishing <= 1.0
    assert parsed.missing_features == []


def test_predict_reports_missing_features(client: TestClient) -> None:
    features = sample_features()
    features.pop("DomainLength")
    response = client.post("/predict", json={"features": features}, headers=HEADERS)
    parsed = PredictResponse.model_validate(response.json())
    assert parsed.status == "partial"
    assert parsed.missing_features == ["DomainLength"]


def test_explain_returns_attributions(client: TestClient) -> None:
    response = client.post("/explain", json={"features": sample_features()}, headers=HEADERS)
    assert response.status_code == 200
    parsed = PredictResponse.model_validate(response.json())
    assert parsed.contributions
    assert all(math.isfinite(contribution.shap) for contribution in parsed.contributions)


def test_predict_rejects_an_empty_feature_map(client: TestClient) -> None:
    response = client.post("/predict", json={"features": {}}, headers=HEADERS)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_predict_rejects_unknown_features(client: TestClient) -> None:
    features = sample_features()
    features["HasPasswordField"] = 1
    response = client.post("/predict", json={"features": features}, headers=HEADERS)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert "HasPasswordField" in response.json()["error"]["message"]


def test_predict_rejects_non_numeric_values(client: TestClient) -> None:
    features = sample_features()
    features["URLLength"] = "abc"
    response = client.post("/predict", json={"features": features}, headers=HEADERS)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_endpoints_report_unavailable_without_artifacts(tmp_path: Path) -> None:
    client = _client(tmp_path / "nothing-here")
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["checks"]["model"] == "not_loaded"
    assert client.get("/model/info").status_code == 503
    predict = client.post("/predict", json={"features": sample_features()}, headers=HEADERS)
    assert predict.status_code == 503
    assert predict.json()["error"]["code"] == "upstream_unavailable"
