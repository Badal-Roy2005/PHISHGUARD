"""M5B threat-intelligence tests using mocked provider responses only.

No test contacts Google Safe Browsing, URLhaus, or any live malicious URL.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs

import httpx
import pytest

from threat_intel import (
    LookupStatus,
    ProviderConfig,
    ProviderReason,
    SafeBrowsingProvider,
    TTLCache,
    URLhausProvider,
    run_intel_engine,
    validate_lookup_url,
)

URL = "https://example.com/login?token=secret"


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _config(**overrides) -> ProviderConfig:
    values = {"retry_backoff_seconds": 0.0}
    values.update(overrides)
    return ProviderConfig(**values)


def _safe_browsing(handler, **kwargs) -> SafeBrowsingProvider:
    return SafeBrowsingProvider(
        kwargs.pop("api_key", "sb-test-key"),
        client=_client(handler),
        config=kwargs.pop("config", _config()),
        **kwargs,
    )


def _urlhaus(handler, **kwargs) -> URLhausProvider:
    return URLhausProvider(
        kwargs.pop("api_key", "urlhaus-test-key"),
        client=_client(handler),
        config=kwargs.pop("config", _config()),
        **kwargs,
    )


def test_safe_browsing_match_is_normalized_with_metadata() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.params.get("key") == "sb-test-key"
        payload = json.loads(request.content)
        assert payload["threatInfo"]["threatEntries"][0]["url"] == URL
        return httpx.Response(
            200,
            json={
                "matches": [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threatEntryType": "URL",
                        "threat": {"url": URL},
                        "cacheDuration": "300s",
                    }
                ]
            },
        )

    result = _safe_browsing(handler).lookup(URL)

    assert result.status == LookupStatus.MATCH
    assert result.reason is None
    assert result.expires_at is not None
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.provider == "google_safe_browsing"
    assert finding.status == "match"
    assert finding.queried_url == URL
    assert finding.category == "social_engineering"
    assert finding.severity == "high"
    assert finding.provider_reference is None
    assert finding.looked_up_at.endswith("Z")
    assert finding.metadata["threat_type"] == "SOCIAL_ENGINEERING"
    assert finding.metadata["provider_payload"]["cacheDuration"] == "300s"


def test_safe_browsing_no_match_is_not_safe() -> None:
    result = _safe_browsing(lambda request: httpx.Response(200, json={})).lookup(URL)

    assert result.status == LookupStatus.NO_MATCH
    assert result.findings[0].status == "no_match"
    assert result.findings[0].category is None
    assert result.expires_at is not None


def test_safe_browsing_malformed_response_is_error() -> None:
    result = _safe_browsing(
        lambda request: httpx.Response(200, content=b"not-json")
    ).lookup(URL)

    assert result.status == LookupStatus.ERROR
    assert result.reason == ProviderReason.MALFORMED_RESPONSE


def test_safe_browsing_timeout_is_unavailable_and_retries() -> None:
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        raise httpx.ReadTimeout("timed out")

    provider = _safe_browsing(handler, config=_config(max_retries=1))
    result = provider.lookup(URL)

    assert result.status == LookupStatus.UNAVAILABLE
    assert result.reason == ProviderReason.TIMEOUT
    assert calls["count"] == 2


def test_retryable_5xx_is_retried_once() -> None:
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            return httpx.Response(503)
        return httpx.Response(200, json={})

    result = _safe_browsing(handler, config=_config(max_retries=1)).lookup(URL)

    assert result.status == LookupStatus.NO_MATCH
    assert calls["count"] == 2


def test_safe_browsing_rate_limit_is_unavailable_without_retry() -> None:
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(429, json={"error": "quota"})

    result = _safe_browsing(handler, config=_config(max_retries=2)).lookup(URL)

    assert result.status == LookupStatus.UNAVAILABLE
    assert result.reason == ProviderReason.RATE_LIMITED
    assert calls["count"] == 1


def test_safe_browsing_auth_failure_is_unavailable() -> None:
    result = _safe_browsing(lambda request: httpx.Response(401)).lookup(URL)

    assert result.status == LookupStatus.UNAVAILABLE
    assert result.reason == ProviderReason.AUTHENTICATION_FAILED


def test_missing_key_skips_network_and_is_unavailable() -> None:
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json={})

    result = _safe_browsing(handler, api_key="").lookup(URL)

    assert result.status == LookupStatus.UNAVAILABLE
    assert result.reason == ProviderReason.MISSING_CREDENTIALS
    assert calls["count"] == 0


def test_response_size_limit_is_error() -> None:
    result = _safe_browsing(
        lambda request: httpx.Response(200, content=b"{}" * 1000),
        config=_config(max_response_bytes=10),
    ).lookup(URL)

    assert result.status == LookupStatus.ERROR
    assert result.reason == ProviderReason.RESPONSE_TOO_LARGE


def test_urlhaus_match_preserves_reference_and_metadata() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.headers.get("Auth-Key") == "urlhaus-test-key"
        form = parse_qs(request.content.decode())
        assert form["url"][0] == URL
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/123456/",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["malware", "exe"],
                "date_added": "2026-01-01 00:00:00 UTC",
                "blacklists": {"spamhaus_dbl": "not listed"},
            },
        )

    result = _urlhaus(handler).lookup(URL)

    assert result.status == LookupStatus.MATCH
    finding = result.findings[0]
    assert finding.provider == "urlhaus"
    assert finding.provider_reference == "https://urlhaus.abuse.ch/url/123456/"
    assert finding.category == "malware"
    assert finding.severity == "high"
    assert finding.metadata["url_status"] == "online"
    assert finding.metadata["tags"] == ["malware", "exe"]


def test_urlhaus_no_results_is_no_match() -> None:
    result = _urlhaus(
        lambda request: httpx.Response(200, json={"query_status": "no_results"})
    ).lookup(URL)

    assert result.status == LookupStatus.NO_MATCH
    assert result.findings[0].status == "no_match"


def test_urlhaus_missing_query_status_is_error() -> None:
    result = _urlhaus(
        lambda request: httpx.Response(200, json={"unexpected": True})
    ).lookup(URL)

    assert result.status == LookupStatus.ERROR
    assert result.reason == ProviderReason.MALFORMED_RESPONSE


def test_urlhaus_auth_failure_is_unavailable() -> None:
    result = _urlhaus(lambda request: httpx.Response(403)).lookup(URL)

    assert result.status == LookupStatus.UNAVAILABLE
    assert result.reason == ProviderReason.AUTHENTICATION_FAILED


def test_urlhaus_rate_limit_is_unavailable() -> None:
    result = _urlhaus(lambda request: httpx.Response(429)).lookup(URL)

    assert result.status == LookupStatus.UNAVAILABLE
    assert result.reason == ProviderReason.RATE_LIMITED


def test_cache_returns_cached_result_and_expires() -> None:
    clock = {"now": 1000.0}
    cache = TTLCache(clock=lambda: clock["now"])
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json={})

    provider = _safe_browsing(
        handler,
        cache=cache,
        ttl_seconds=60,
        config=_config(max_retries=0),
    )

    first = provider.lookup(URL)
    second = provider.lookup(URL)
    assert first.cached is False
    assert second.cached is True
    assert second.looked_up_at == first.looked_up_at
    assert calls["count"] == 1

    clock["now"] += 61
    third = provider.lookup(URL)
    assert third.cached is False
    assert calls["count"] == 2


def test_unavailable_results_are_not_cached() -> None:
    clock = {"now": 1000.0}
    cache = TTLCache(clock=lambda: clock["now"])
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(503)

    provider = _safe_browsing(
        handler,
        cache=cache,
        ttl_seconds=60,
        config=_config(max_retries=0),
    )

    assert provider.lookup(URL).status == LookupStatus.UNAVAILABLE
    assert provider.lookup(URL).status == LookupStatus.UNAVAILABLE
    assert calls["count"] == 2
    assert len(cache) == 0


def test_one_provider_failure_does_not_suppress_another_match() -> None:
    def sb_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"matches": [{"threatType": "MALWARE", "threat": {"url": URL}}]},
        )

    def urlhaus_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    result = run_intel_engine(
        URL,
        [
            _safe_browsing(sb_handler, config=_config(max_retries=0)),
            _urlhaus(urlhaus_handler, config=_config(max_retries=0)),
        ],
    )

    assert result.status == "partial"
    assert len(result.findings) == 1
    assert result.findings[0].id.startswith("intel-google_safe_browsing")
    assert result.evidence["provider_statuses"] == {
        "google_safe_browsing": "match",
        "urlhaus": "unavailable",
    }
    assert result.evidence["unavailable_providers"] == ["urlhaus"]


def test_no_match_plus_unavailable_is_partial_and_not_safe() -> None:
    result = run_intel_engine(
        URL,
        [
            _safe_browsing(
                lambda request: httpx.Response(200, json={}),
                config=_config(max_retries=0),
            ),
            _urlhaus(
                lambda request: httpx.Response(503),
                config=_config(max_retries=0),
            ),
        ],
    )

    assert result.status == "partial"
    assert result.findings == ()
    assert result.evidence["no_match_providers"] == ["google_safe_browsing"]
    assert result.evidence["unavailable_providers"] == ["urlhaus"]
    assert result.evidence["policy"]["no_match_is_not_safe"] is True


def test_all_no_match_is_usable_but_produces_no_findings() -> None:
    result = run_intel_engine(
        URL,
        [
            _safe_browsing(lambda request: httpx.Response(200, json={})),
            _urlhaus(
                lambda request: httpx.Response(200, json={"query_status": "no_results"})
            ),
        ],
    )

    assert result.status == "ok"
    assert result.findings == ()
    assert result.evidence["no_match_providers"] == [
        "google_safe_browsing",
        "urlhaus",
    ]


def test_all_unavailable_is_unknown() -> None:
    result = run_intel_engine(
        URL,
        [
            _safe_browsing(
                lambda request: httpx.Response(503),
                config=_config(max_retries=0),
            ),
            _urlhaus(
                lambda request: httpx.Response(503),
                config=_config(max_retries=0),
            ),
        ],
    )

    assert result.status == "unknown"
    assert result.findings == ()


def test_all_errors_is_error() -> None:
    result = run_intel_engine(
        URL,
        [
            _safe_browsing(
                lambda request: httpx.Response(200, content=b"bad"),
                config=_config(max_retries=0),
            ),
            _urlhaus(
                lambda request: httpx.Response(200, content=b"bad"),
                config=_config(max_retries=0),
            ),
        ],
    )

    assert result.status == "error"
    assert result.findings == ()


def test_missing_credentials_are_reported_as_skipped() -> None:
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json={})

    result = run_intel_engine(
        URL,
        [
            _safe_browsing(handler, api_key=""),
            _urlhaus(handler, api_key=""),
        ],
    )

    assert result.status == "skipped"
    assert calls["count"] == 0
    assert result.evidence["provider_statuses"] == {
        "google_safe_browsing": "unavailable",
        "urlhaus": "unavailable",
    }
    assert (
        result.evidence["providers"]["google_safe_browsing"]["reason"]
        == ProviderReason.MISSING_CREDENTIALS
    )


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://example.com/",
        "https://user:pass@example.com/",
        "http://" + "a" * 2050,
    ],
)
def test_invalid_lookup_urls_are_rejected(url: str) -> None:
    valid, error = validate_lookup_url(url)
    assert valid is False
    assert error
