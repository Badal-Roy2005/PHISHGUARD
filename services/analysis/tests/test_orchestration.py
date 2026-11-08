"""M5B orchestration integration tests. No live provider calls."""

from __future__ import annotations

import json

import httpx
from phishguard_contracts import ScanRequest

from app.orchestration import build_scan_result
from app.settings import load_settings
from scanner import ScanResult
from threat_intel import SafeBrowsingProvider, URLhausProvider

URL = "https://example.com/login"


def _settings():
    return load_settings({"ENV": "test"})


def _fake_scan(url, config):
    return ScanResult(
        scan_id="fake-scan",
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
            "set_cookie_headers": ["session=secret; Secure; HttpOnly; SameSite=Lax"],
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


def _sb_match() -> SafeBrowsingProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]},
        )

    return SafeBrowsingProvider(
        "sb-test-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def _sb_no_match() -> SafeBrowsingProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={})

    return SafeBrowsingProvider(
        "sb-test-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def _urlhaus_no_match() -> URLhausProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "no_results"})

    return URLhausProvider(
        "urlhaus-test-key",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_match_is_visible_but_scan_is_not_promoted_to_safe() -> None:
    result = build_scan_result(
        ScanRequest(url=URL),
        _settings(),
        providers=[_sb_match(), _urlhaus_no_match()],
        scanner=_fake_scan,
    )

    assert result.status == "partial"
    assert result.risk is not None
    assert result.risk.score == 35
    assert result.risk.band == "guarded"
    assert result.risk.incomplete is True
    assert "intel_confirmed_match" in result.risk.reason_codes
    assert result.explanation is not None
    assert result.engines.intel.status == "ok"
    assert len(result.engines.intel.findings) == 1
    assert result.engines.intel.findings[0].severity == "high"
    assert result.evidence["intel_provider_statuses"] == {
        "google_safe_browsing": "match",
        "urlhaus": "no_match",
    }


def test_no_match_is_not_a_safe_scan_verdict() -> None:
    result = build_scan_result(
        ScanRequest(url=URL),
        _settings(),
        providers=[_sb_no_match(), _urlhaus_no_match()],
        scanner=_fake_scan,
    )

    assert result.status == "partial"
    assert result.risk is not None
    assert result.risk.score == 0
    assert result.risk.band == "low"
    assert result.risk.incomplete is True
    assert "intel_no_match" in result.risk.reason_codes
    assert result.engines.intel.status == "ok"
    assert result.engines.intel.findings == []
    assert result.evidence["intel_provider_statuses"] == {
        "google_safe_browsing": "no_match",
        "urlhaus": "no_match",
    }
    serialized = json.dumps(result.model_dump(mode="json"))
    assert '"safe"' not in serialized.lower()


def test_intel_can_be_disabled_per_request() -> None:
    result = build_scan_result(
        ScanRequest(url=URL, options={"include_intel": False}),
        _settings(),
        providers=[],
        scanner=_fake_scan,
    )

    assert result.status == "partial"
    assert result.risk is not None
    assert result.risk.score is None
    assert result.risk.band == "insufficient_evidence"
    assert result.engines.intel.status == "skipped"
    assert result.engines.intel.evidence["disabled_by_request"] is True
    assert result.evidence["intel_provider_statuses"] == {}


def test_url_engine_evidence_omits_sensitive_query_components() -> None:
    result = build_scan_result(
        ScanRequest(url="https://example.com/path?token=very-secret"),
        _settings(),
        providers=[],
        scanner=_fake_scan,
    )

    assert result.engines.url.status == "ok"
    evidence = json.dumps(result.engines.url.evidence)
    assert "very-secret" not in evidence
    assert "token" not in evidence
    assert "query" not in result.engines.url.evidence["features"]


def test_m6_transport_engines_are_wired_without_safe_promotion() -> None:
    result = build_scan_result(
        ScanRequest(url=URL),
        _settings(),
        providers=[],
        scanner=_fake_scan,
    )

    assert result.status == "partial"
    assert result.risk is not None
    assert result.risk.policy.version == "m7-2026-11-09.2"
    assert result.engines.tls.status == "ok"
    assert result.engines.http.status == "ok"
    assert result.engines.tls.evidence["ct"]["status"] == "skipped"
    assert result.evidence["transport"]["scanner_status"] == "complete"
    serialized = json.dumps(result.model_dump(mode="json"))
    assert "secret" not in serialized
