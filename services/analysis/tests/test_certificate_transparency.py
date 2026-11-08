"""Deterministic M6 Certificate Transparency tests. No live crt.sh calls."""

from __future__ import annotations

import httpx

from certificate_transparency import (
    CertificateTransparencyClient,
    CTConfig,
    CTReason,
    CTStatus,
)


def _client(handler) -> CertificateTransparencyClient:
    return CertificateTransparencyClient(
        CTConfig(timeout_seconds=1.0, max_response_bytes=4096, max_records=10),
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_lookup_parses_and_deduplicates_records() -> None:
    records = [
        {
            "id": 1,
            "common_name": "example.com",
            "issuer_name": "Example CA",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2027-01-01T00:00:00",
            "name_value": "example.com\nwww.example.com",
        },
        {
            "id": 1,
            "common_name": "example.com",
            "issuer_name": "Example CA",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2027-01-01T00:00:00",
            "name_value": "example.com",
        },
        {
            "id": 2,
            "common_name": "example.com",
            "issuer_name": "Other CA",
            "not_before": "2026-02-01T00:00:00",
            "not_after": "2027-02-01T00:00:00",
            "name_value": "example.com",
        },
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["q"] == "%.example.com"
        assert request.url.params["output"] == "json"
        return httpx.Response(200, json=records)

    result = _client(handler).lookup("https://example.com/login?token=secret")

    assert result.status == CTStatus.OK
    assert result.domain == "example.com"
    assert result.certificate_count == 2
    assert result.unique_issuers == ("Example CA", "Other CA")
    assert result.records_examined == 3
    assert result.records_processed == 3
    assert result.first_seen == "2026-01-01T00:00:00"
    assert result.last_seen == "2026-02-01T00:00:00"
    assert result.recent_certificates[0]["id"] == 2
    assert "secret" not in repr(result.to_evidence())


def test_no_records_is_ok_but_not_safe() -> None:
    result = _client(lambda request: httpx.Response(200, json=[])).lookup(
        "https://example.com/"
    )

    assert result.status == CTStatus.OK
    assert result.certificate_count == 0
    assert result.to_evidence()["policy"]["no_certificate_is_not_safe"] is True


def test_rate_limit_is_unavailable() -> None:
    result = _client(lambda request: httpx.Response(429)).lookup("https://example.com/")

    assert result.status == CTStatus.UNAVAILABLE
    assert result.reason == CTReason.RATE_LIMITED


def test_timeout_is_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timeout")

    result = _client(handler).lookup("https://example.com/")

    assert result.status == CTStatus.UNAVAILABLE
    assert result.reason == CTReason.TIMEOUT


def test_malformed_json_is_error() -> None:
    result = _client(
        lambda request: httpx.Response(200, content=b"not-json")
    ).lookup("https://example.com/")

    assert result.status == CTStatus.ERROR
    assert result.reason == CTReason.MALFORMED_RESPONSE


def test_oversized_response_is_error() -> None:
    result = _client(
        lambda request: httpx.Response(
            200,
            headers={"Content-Length": "9999"},
            content=b"[]",
        )
    ).lookup("https://example.com/")

    assert result.status == CTStatus.ERROR
    assert result.reason == CTReason.RESPONSE_TOO_LARGE


def test_ip_and_credential_targets_are_rejected() -> None:
    client = _client(lambda request: httpx.Response(200, json=[]))

    ip_result = client.lookup("https://127.0.0.1/")
    credential_result = client.lookup("https://user:pass@example.com/")

    assert ip_result.status == CTStatus.ERROR
    assert ip_result.reason == CTReason.INVALID_DOMAIN
    assert credential_result.status == CTStatus.ERROR
    assert credential_result.reason == CTReason.INVALID_DOMAIN


def test_upstream_5xx_is_unavailable() -> None:
    result = _client(lambda request: httpx.Response(503)).lookup("https://example.com/")

    assert result.status == CTStatus.UNAVAILABLE
    assert result.reason == CTReason.UPSTREAM_UNAVAILABLE
