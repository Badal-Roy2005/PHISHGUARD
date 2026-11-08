from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from phishguard_contracts import CONTRACT_VERSION, FEATURE_SCHEMA_VERSION

from app.main import create_app
from app.settings import load_settings


def _client(artifacts_dir: Path) -> TestClient:
    """Point the app at an empty directory so no real artifact is required."""
    settings = load_settings({"ENV": "test", "ARTIFACTS_DIR": str(artifacts_dir)})
    return TestClient(create_app(settings))


def test_health_stays_up_without_artifacts(tmp_path: Path) -> None:
    response = _client(tmp_path / "missing").get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "ml"
    assert body["contract_version"] == CONTRACT_VERSION
    assert body["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert body["checks"] == {
        "config": "ok",
        "model": "not_loaded",
        "feature_contract": "missing",
    }


def test_version_endpoint_matches_the_contract(tmp_path: Path) -> None:
    body = _client(tmp_path / "missing").get("/version").json()
    assert body["contract_version"] == CONTRACT_VERSION
    assert body["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert body["version"] == "0.1.0"


def test_predict_requires_token(tmp_path: Path) -> None:
    response = _client(tmp_path / "missing").post("/predict", json={"features": {"URLLength": 10}})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


def test_predict_is_explicitly_unavailable_without_a_model(tmp_path: Path) -> None:
    response = _client(tmp_path / "missing").post(
        "/predict",
        json={"features": {"URLLength": 10}},
        headers={"X-Service-Token": "dev-only-change-me-please"},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "upstream_unavailable"


def test_predict_rejects_empty_feature_map(tmp_path: Path) -> None:
    response = _client(tmp_path / "missing").post(
        "/predict",
        json={"features": {}},
        headers={"X-Service-Token": "dev-only-change-me-please"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
