"""M6 transport-engine integration tests with injected scanner and CT client."""

from __future__ import annotations

import httpx

from app.settings import load_settings
from app.transport import run_transport_assessment
from certificate_transparency import CertificateTransparencyClient, CTConfig, CTStatus
from scanner import ScanResult


def _tls_info() -> dict:
    return {
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
    }


def _fake_scan(url, config):
    return ScanResult(
        scan_id="fake-transport-scan",
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
            "tls_information": _tls_info(),
        },
        duration_ms=1.0,
    )


def _ct_client() -> CertificateTransparencyClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[
                {
                    "id": 1,
                    "common_name": "example.com",
                    "issuer_name": "Example CA",
                    "not_before": "2026-01-01T00:00:00",
                    "not_after": "2027-01-01T00:00:00",
                    "name_value": "example.com",
                }
            ],
        )

    return CertificateTransparencyClient(
        CTConfig(timeout_seconds=1.0, max_response_bytes=4096),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_transport_reports_tls_and_http_engines() -> None:
    tls, http, extra = run_transport_assessment(
        "https://example.com/login",
        load_settings({"ENV": "test"}),
        scanner=_fake_scan,
    )

    assert tls.engine == "tls"
    assert tls.status == "ok"
    assert http.engine == "http"
    assert http.status == "ok"
    assert extra["scanner_status"] == "complete"
    assert extra["ct_status"] == CTStatus.SKIPPED


def test_requested_ct_disabled_by_config_makes_tls_partial() -> None:
    tls, _, _ = run_transport_assessment(
        "https://example.com/login",
        load_settings({"ENV": "test"}),
        include_ct=True,
        scanner=_fake_scan,
    )

    assert tls.status == "partial"
    assert tls.evidence["ct"]["status"] == CTStatus.SKIPPED
    assert tls.evidence["ct"]["reason"] == "disabled_by_config"
    assert "disabled" in (tls.error or "").lower()


def test_requested_ct_success_is_preserved() -> None:
    tls, _, _ = run_transport_assessment(
        "https://example.com/login",
        load_settings({"ENV": "test", "CT_ENABLED": "true"}),
        include_ct=True,
        scanner=_fake_scan,
        ct_client=_ct_client(),
    )

    assert tls.status == "ok"
    assert tls.evidence["ct"]["status"] == CTStatus.OK
    assert tls.evidence["ct"]["certificate_count"] == 1


def test_ct_failure_does_not_discard_tls_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    client = CertificateTransparencyClient(
        CTConfig(timeout_seconds=1.0),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    tls, _, _ = run_transport_assessment(
        "https://example.com/login",
        load_settings({"ENV": "test", "CT_ENABLED": "true"}),
        include_ct=True,
        scanner=_fake_scan,
        ct_client=client,
    )

    assert tls.status == "partial"
    assert tls.evidence["protocol"] == "TLSv1.3"
    assert tls.evidence["ct"]["status"] == CTStatus.UNAVAILABLE
    assert "rate limit" in (tls.error or "").lower()


def test_scanner_failure_is_unknown_not_safe() -> None:
    def failed_scan(url, config):
        return ScanResult(
            scan_id="failed",
            url=url,
            status="failed",
            risk_band="critical",
            findings=[],
            evidence={"final_url": url, "error": "blocked target"},
            duration_ms=0.0,
        )

    tls, http, extra = run_transport_assessment(
        "https://example.com/",
        load_settings({"ENV": "test"}),
        scanner=failed_scan,
    )

    assert tls.status == "unknown"
    assert http.status == "unknown"
    assert extra["scanner_status"] == "failed"
