from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.settings import load_settings
from scanner import ScanResult


def _fake_scan(url, config):
    return ScanResult(
        scan_id="fake-health-scan",
        url=url,
        status="complete",
        risk_band="low",
        findings=[],
        evidence={
            "requested_url": url,
            "final_url": url,
            "http_status": 200,
            "content_type": "text/html",
            "redirect_chain": [url],
            "response_headers": {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=()",
            },
            "set_cookie_headers": [],
            "tls_information": {
                "enabled": True,
                "verified": True,
                "protocol": "TLSv1.3",
                "cipher": {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLSv1.3", "bits": 256},
                "alpn": "http/1.1",
                "server_hostname": "example.com",
                "certificate": {
                    "subject": [[("commonName", "example.com")]],
                    "issuer": [[("commonName", "Example CA")]],
                    "notBefore": "Nov  1 00:00:00 2026 GMT",
                    "notAfter": "Nov  1 00:00:00 2027 GMT",
                    "subjectAltName": [["DNS", "example.com"]],
                },
                "error": None,
            },
        },
        duration_ms=1.0,
    )


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    monkeypatch.setattr("app.transport.scan_url", _fake_scan)


def _client() -> TestClient:
    return TestClient(create_app(load_settings({"ENV": "test"})))


def test_health_reports_ok_and_versions() -> None:
    response = _client().get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "analysis"
    assert body["version"] == "0.1.0"
    assert body["contract_version"] == "2026-11-09.2"
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


def test_analyze_returns_assessment_with_explicit_missing_evidence() -> None:
    client = _client()
    response = client.post(
        "/internal/analyze",
        json={"url": "https://example.com/login"},
        headers={"X-Service-Token": "dev-only-change-me-please"},
    )
    # M7 publishes a deterministic assessment even when engines are missing.
    # Missing evidence is visible as incomplete coverage, never as a safe verdict.
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "partial"
    assert body["risk"] is not None
    assert body["risk"]["policy"]["version"] == "m7-2026-11-09.2"
    assert body["risk"]["confidence"]["incomplete"] is True
    assert body["explanation"] is not None
    assert body["engines"]["url"]["status"] == "ok"
    assert body["engines"]["tls"]["status"] == "ok"
    assert body["engines"]["http"]["status"] == "ok"
    assert body["engines"]["tls"]["evidence"]["ct"]["status"] == "skipped"
    assert body["engines"]["intel"]["status"] == "skipped"
    providers = body["engines"]["intel"]["evidence"]["providers"]
    assert providers["google_safe_browsing"]["status"] == "unavailable"
    assert providers["google_safe_browsing"]["reason"] == "missing_credentials"
    assert providers["urlhaus"]["reason"] == "missing_credentials"
