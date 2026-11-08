from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app
from app.settings import load_settings


def _client() -> TestClient:
    return TestClient(create_app(load_settings({"ENV": "test"})))


def test_health_reports_not_loaded_model_without_lying() -> None:
    response = _client().get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "ml"
    assert body["checks"]["model"] in {"present", "not_loaded"}


def test_predict_requires_token() -> None:
    response = _client().post("/predict", json={"features": {"URLLength": 10}})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_predict_returns_explicit_unavailable_before_m2() -> None:
    response = _client().post(
        "/predict",
        json={"features": {"URLLength": 10}},
        headers={"X-Service-Token": "dev-only-change-me-please"},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "upstream_unavailable"


def test_predict_rejects_empty_feature_map() -> None:
    response = _client().post(
        "/predict",
        json={"features": {}},
        headers={"X-Service-Token": "dev-only-change-me-please"},
    )
    assert response.status_code == 400
