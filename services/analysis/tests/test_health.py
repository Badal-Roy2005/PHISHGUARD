from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app
from app.settings import load_settings


def _client() -> TestClient:
    return TestClient(create_app(load_settings({"ENV": "test"})))


def test_health_reports_ok_and_versions() -> None:
    response = _client().get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "analysis"
    assert body["version"] == "0.1.0"
    assert body["contract_version"] == "2026-11-09.1"
    assert body["checks"]["config"] == "ok"


def test_version_endpoint_exposes_feature_schema_version() -> None:
    response = _client().get("/version")
    assert response.status_code == 200
    assert response.json()["feature_schema_version"] == "2"


def test_request_id_is_echoed() -> None:
    response = _client().get("/health", headers={"X-Request-ID": "req_test_1"})
    assert response.headers["X-Request-ID"] == "req_test_1"


def test_config_summary_requires_service_token() -> None:
    assert _client().get("/internal/config").status_code == 401


def test_analyze_rejects_invalid_scheme_before_any_work() -> None:
    client = _client()
    response = client.post(
        "/internal/analyze",
        json={"url": "javascript:alert(1)"},
        headers={"X-Service-Token": "dev-only-change-me-please"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_url"


def test_analyze_accepts_valid_url_then_reports_not_implemented() -> None:
    client = _client()
    response = client.post(
        "/internal/analyze",
        json={"url": "https://example.com/login"},
        headers={"X-Service-Token": "dev-only-change-me-please"},
    )
    # Explicit 501, never a fabricated verdict.
    assert response.status_code == 501
    assert response.json()["error"]["code"] == "internal"
