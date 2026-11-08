"""Threat-intelligence provider integration for PHISHGUARD M5B.

The module keeps provider-specific request/response handling behind a small
common interface.  Providers return normalized results whose status is one of
``match``, ``no_match``, ``unavailable`` or ``error``.  A no-match is only
evidence that the provider did not report a match; it is never a safe verdict.
Provider outages, missing credentials, quota exhaustion and timeouts are
``unavailable``.  Malformed or unexpected responses are ``error``.  None of
these states may be converted into ``safe`` by callers.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from phishguard_contracts import SERVICE_VERSION, EngineReport, Finding

logger = logging.getLogger("phishguard.intel")

SAFE_BROWSING_PROVIDER = "google_safe_browsing"
URLHAUS_PROVIDER = "urlhaus"

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"

SAFE_BROWSING_THREAT_TYPES = (
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
)

MAX_URL_LENGTH = 2048
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_RESPONSE_BYTES = 256_000
DEFAULT_MAX_RETRIES = 1
RETRYABLE_STATUSES = frozenset({500, 502, 503, 504})


class LookupStatus:
    """Normalized provider lookup states.  These are intentionally strings."""

    MATCH = "match"
    NO_MATCH = "no_match"
    UNAVAILABLE = "unavailable"
    ERROR = "error"

    ALL = frozenset({MATCH, NO_MATCH, UNAVAILABLE, ERROR})
    USABLE = frozenset({MATCH, NO_MATCH})


class ProviderReason:
    """Machine-readable reason attached to unavailable/error results."""

    MISSING_CREDENTIALS = "missing_credentials"
    INVALID_INPUT = "invalid_input"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXHAUSTED = "quota_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    UPSTREAM_UNAVAILABLE = "upstream_unavailable"
    MALFORMED_RESPONSE = "malformed_response"
    RESPONSE_TOO_LARGE = "response_too_large"
    HTTP_ERROR = "http_error"
    PROVIDER_ERROR = "provider_error"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class ProviderConfig:
    """Bounded network behaviour shared by all adapters."""

    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    max_retries: int = DEFAULT_MAX_RETRIES
    retry_backoff_seconds: float = 0.1
    user_agent: str = "PHISHGUARD-Intel/1.0"


@dataclass(frozen=True)
class NormalizedFinding:
    """One provider result or one provider match, normalized for the pipeline."""

    provider: str
    status: str
    queried_url: str
    provider_reference: str | None = None
    category: str | None = None
    severity: str = "info"
    metadata: dict[str, Any] = field(default_factory=dict)
    looked_up_at: str = ""
    expires_at: str | None = None
    source: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status,
            "queried_url": self.queried_url,
            "provider_reference": self.provider_reference,
            "category": self.category,
            "severity": self.severity,
            "metadata": self.metadata,
            "looked_up_at": self.looked_up_at,
            "expires_at": self.expires_at,
            "source": self.source,
            "error": self.error,
        }


@dataclass(frozen=True)
class ProviderResult:
    """Normalized result for one provider lookup."""

    provider: str
    status: str
    findings: tuple[NormalizedFinding, ...] = ()
    reason: str | None = None
    error: str | None = None
    duration_ms: float = 0.0
    looked_up_at: str = ""
    expires_at: str | None = None
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status,
            "reason": self.reason,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "looked_up_at": self.looked_up_at,
            "expires_at": self.expires_at,
            "cached": self.cached,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True)
class IntelEngineResult:
    """Aggregated result of all configured providers, shaped like an engine."""

    status: str
    findings: tuple[Finding, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)
    source: str = "threat-intel"
    duration_ms: float = 0.0
    error: str | None = None
    provider_results: tuple[ProviderResult, ...] = ()

    def to_engine_report(self) -> EngineReport:
        return EngineReport(
            engine="intel",
            status=self.status,
            findings=list(self.findings),
            evidence=self.evidence,
            source=self.source,
            duration_ms=self.duration_ms,
            error=self.error,
        )


@dataclass(frozen=True)
class _CacheEntry:
    result: ProviderResult
    expires_monotonic: float


class TTLCache:
    """Small thread-safe in-process TTL cache for usable provider results."""

    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = 4096,
    ) -> None:
        self._clock = clock
        self._max_entries = max(1, max_entries)
        self._entries: dict[tuple[str, str], _CacheEntry] = {}
        self._lock = threading.Lock()

    def get(self, key: tuple[str, str]) -> ProviderResult | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_monotonic <= self._clock():
                self._entries.pop(key, None)
                return None
            return replace(entry.result, cached=True)

    def set(self, key: tuple[str, str], result: ProviderResult, ttl_seconds: int) -> None:
        now = self._clock()
        with self._lock:
            if len(self._entries) >= self._max_entries:
                expired = [
                    entry_key
                    for entry_key, entry in self._entries.items()
                    if entry.expires_monotonic <= now
                ]
                for entry_key in expired:
                    self._entries.pop(entry_key, None)
            while len(self._entries) >= self._max_entries:
                self._entries.pop(next(iter(self._entries)), None)
            self._entries[key] = _CacheEntry(
                result=result,
                expires_monotonic=now + max(1, int(ttl_seconds)),
            )

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


DEFAULT_CACHE = TTLCache()


class ProviderTransportError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ProviderResponseTooLarge(RuntimeError):
    pass


class MalformedResponse(RuntimeError):
    pass


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000, 3)


def _url_fingerprint(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def validate_lookup_url(url: str) -> tuple[bool, str | None]:
    """Validate a URL before it is sent to a provider.

    Providers are not fetched, so this is intentionally a structural check, not
    the scanner's SSRF policy.  Credentials are rejected because they would be
    disclosed to a third party.
    """
    if not isinstance(url, str) or not url.strip():
        return False, "URL is empty or not a string"
    if len(url) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum length of {MAX_URL_LENGTH} characters"
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        return False, "Only http and https URLs can be queried"
    if not parsed.hostname:
        return False, "URL has no hostname"
    if parsed.username or parsed.password:
        return False, "URL must not contain credentials"
    return True, None


def _read_limited(response: httpx.Response, max_bytes: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise ProviderResponseTooLarge
        except ValueError:
            pass
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise ProviderResponseTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def _json_object(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedResponse("response is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise MalformedResponse("response is not a JSON object")
    return payload


class BaseProvider:
    """Common adapter interface and bounded HTTP transport."""

    name = "provider"
    display_name = "Provider"
    ttl_seconds = 3600

    def __init__(
        self,
        api_key: str | None,
        *,
        config: ProviderConfig | None = None,
        client: httpx.Client | None = None,
        cache: TTLCache | None = None,
        ttl_seconds: int | None = None,
    ) -> None:
        self._api_key = (api_key or "").strip()
        self.config = config or ProviderConfig()
        if ttl_seconds is not None:
            self.ttl_seconds = max(1, int(ttl_seconds))
        self._cache = cache
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(self.config.timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": self.config.user_agent},
        )

    @property
    def configured(self) -> bool:
        return bool(self._api_key)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> BaseProvider:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def lookup(
        self,
        url: str,
        *,
        timeout_seconds: float | None = None,
        deadline: float | None = None,
    ) -> ProviderResult:
        start = time.monotonic()
        checked_at = utc_now_iso()

        if not self.configured:
            return self._status_result(
                url,
                LookupStatus.UNAVAILABLE,
                reason=ProviderReason.MISSING_CREDENTIALS,
                error=f"{self.display_name} credentials are not configured",
                checked_at=checked_at,
                start=start,
            )

        valid, validation_error = validate_lookup_url(url)
        if not valid:
            return self._status_result(
                url,
                LookupStatus.ERROR,
                reason=ProviderReason.INVALID_INPUT,
                error=validation_error or "invalid URL",
                checked_at=checked_at,
                start=start,
            )

        if self._cache is not None:
            cached = self._cache.get((self.name, url))
            if cached is not None:
                self._log_result(cached, url)
                return cached

        try:
            result = self._lookup(
                url,
                checked_at=checked_at,
                start=start,
                timeout_seconds=timeout_seconds,
                deadline=deadline,
            )
        except MalformedResponse:
            result = self._status_result(
                url,
                LookupStatus.ERROR,
                reason=ProviderReason.MALFORMED_RESPONSE,
                error=f"{self.display_name} returned a malformed response",
                checked_at=checked_at,
                start=start,
            )
        except ProviderResponseTooLarge:
            result = self._status_result(
                url,
                LookupStatus.ERROR,
                reason=ProviderReason.RESPONSE_TOO_LARGE,
                error=f"{self.display_name} response exceeded the size limit",
                checked_at=checked_at,
                start=start,
            )
        except ProviderTransportError as exc:
            result = self._status_result(
                url,
                LookupStatus.UNAVAILABLE,
                reason=exc.reason,
                error=f"{self.display_name} request failed ({exc.reason})",
                checked_at=checked_at,
                start=start,
            )
        except Exception as exc:  # noqa: BLE001 - never fail a scan on one provider
            logger.warning(
                "provider=%s unexpected_error=%s url_fingerprint=%s",
                self.name,
                type(exc).__name__,
                _url_fingerprint(url),
            )
            result = self._status_result(
                url,
                LookupStatus.ERROR,
                reason=ProviderReason.INTERNAL_ERROR,
                error=f"{self.display_name} lookup failed unexpectedly",
                checked_at=checked_at,
                start=start,
            )

        if self._cache is not None and result.status in LookupStatus.USABLE:
            self._cache.set((self.name, url), result, self.ttl_seconds)

        self._log_result(result, url)
        return result

    def unavailable_result(
        self,
        url: str,
        *,
        reason: str,
        error: str,
        checked_at: str | None = None,
    ) -> ProviderResult:
        return self._status_result(
            url,
            LookupStatus.UNAVAILABLE,
            reason=reason,
            error=error,
            checked_at=checked_at or utc_now_iso(),
            start=time.monotonic(),
        )

    def _lookup(
        self,
        url: str,
        *,
        checked_at: str,
        start: float,
        timeout_seconds: float | None,
        deadline: float | None,
    ) -> ProviderResult:
        raise NotImplementedError

    def _expires_at(self) -> str:
        return _iso(datetime.now(UTC) + timedelta(seconds=self.ttl_seconds))

    def _status_result(
        self,
        url: str,
        status: str,
        *,
        reason: str | None,
        error: str | None,
        checked_at: str,
        start: float,
        expires_at: str | None = None,
    ) -> ProviderResult:
        finding = NormalizedFinding(
            provider=self.name,
            status=status,
            queried_url=url,
            metadata={},
            looked_up_at=checked_at,
            expires_at=expires_at,
            source=self.name,
            error=error,
        )
        return ProviderResult(
            provider=self.name,
            status=status,
            findings=(finding,),
            reason=reason,
            error=error,
            duration_ms=_elapsed_ms(start),
            looked_up_at=checked_at,
            expires_at=expires_at,
        )

    def _match_result(
        self,
        findings: list[NormalizedFinding],
        *,
        checked_at: str,
        start: float,
    ) -> ProviderResult:
        expires_at = self._expires_at()
        normalized = [
            replace(finding, expires_at=expires_at)
            for finding in findings
        ]
        return ProviderResult(
            provider=self.name,
            status=LookupStatus.MATCH,
            findings=tuple(normalized),
            duration_ms=_elapsed_ms(start),
            looked_up_at=checked_at,
            expires_at=expires_at,
        )

    def _no_match_result(self, url: str, *, checked_at: str, start: float) -> ProviderResult:
        return self._status_result(
            url,
            LookupStatus.NO_MATCH,
            reason=None,
            error=None,
            checked_at=checked_at,
            start=start,
            expires_at=self._expires_at(),
        )

    def _http_status_result(
        self,
        url: str,
        status_code: int,
        *,
        checked_at: str,
        start: float,
    ) -> ProviderResult:
        if status_code in (401, 403):
            status = LookupStatus.UNAVAILABLE
            reason = ProviderReason.AUTHENTICATION_FAILED
            error = f"{self.display_name} authentication failed"
        elif status_code == 429:
            status = LookupStatus.UNAVAILABLE
            reason = ProviderReason.RATE_LIMITED
            error = f"{self.display_name} rate limit or quota exhausted"
        elif status_code == 408:
            status = LookupStatus.UNAVAILABLE
            reason = ProviderReason.TIMEOUT
            error = f"{self.display_name} request timed out"
        elif 500 <= status_code <= 599:
            status = LookupStatus.UNAVAILABLE
            reason = ProviderReason.UPSTREAM_UNAVAILABLE
            error = f"{self.display_name} is unavailable (HTTP {status_code})"
        else:
            status = LookupStatus.ERROR
            reason = ProviderReason.HTTP_ERROR
            error = f"{self.display_name} returned HTTP {status_code}"
        return self._status_result(
            url,
            status,
            reason=reason,
            error=error,
            checked_at=checked_at,
            start=start,
        )

    def _post(
        self,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        data: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: float | None = None,
        deadline: float | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        timeout = self.config.timeout_seconds
        if timeout_seconds is not None:
            timeout = min(timeout, timeout_seconds)
        timeout = max(0.1, timeout)

        attempts = max(1, self.config.max_retries + 1)
        for attempt in range(attempts):
            attempt_timeout = timeout
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProviderTransportError(ProviderReason.TIMEOUT)
                attempt_timeout = max(0.1, min(timeout, remaining))
            try:
                with self._client.stream(
                    "POST",
                    url,
                    json=json_body,
                    data=data,
                    params=params,
                    headers=headers,
                    timeout=httpx.Timeout(attempt_timeout),
                    follow_redirects=False,
                ) as response:
                    body = _read_limited(response, self.config.max_response_bytes)
                    response_headers = {key: value for key, value in response.headers.items()}
                    if response.status_code in RETRYABLE_STATUSES and attempt + 1 < attempts:
                        if deadline is not None and time.monotonic() >= deadline:
                            return response.status_code, body, response_headers
                        if self.config.retry_backoff_seconds:
                            time.sleep(self.config.retry_backoff_seconds)
                        continue
                    return response.status_code, body, response_headers
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                reason = (
                    ProviderReason.TIMEOUT
                    if isinstance(exc, httpx.TimeoutException)
                    else ProviderReason.UPSTREAM_UNAVAILABLE
                )
                if attempt + 1 >= attempts:
                    raise ProviderTransportError(reason) from exc
                if deadline is not None and time.monotonic() >= deadline:
                    raise ProviderTransportError(reason) from exc
                if self.config.retry_backoff_seconds:
                    time.sleep(self.config.retry_backoff_seconds)
            except httpx.HTTPError as exc:
                raise ProviderTransportError(ProviderReason.UPSTREAM_UNAVAILABLE) from exc

        raise ProviderTransportError(ProviderReason.UPSTREAM_UNAVAILABLE)

    def _log_result(self, result: ProviderResult, url: str) -> None:
        level = (
            logger.info
            if result.status in (LookupStatus.MATCH, LookupStatus.NO_MATCH)
            else logger.warning
        )
        level(
            "provider=%s status=%s reason=%s duration_ms=%.3f cached=%s "
            "url_fingerprint=%s host=%s",
            self.name,
            result.status,
            result.reason,
            result.duration_ms,
            result.cached,
            _url_fingerprint(url),
            urlparse(url).hostname or "",
        )


class SafeBrowsingProvider(BaseProvider):
    """Google Safe Browsing v4 ``threatMatches:find`` adapter."""

    name = SAFE_BROWSING_PROVIDER
    display_name = "Google Safe Browsing"
    ttl_seconds = 3600

    def _lookup(
        self,
        url: str,
        *,
        checked_at: str,
        start: float,
        timeout_seconds: float | None,
        deadline: float | None,
    ) -> ProviderResult:
        payload = {
            "client": {
                "clientId": "phishguard",
                "clientVersion": SERVICE_VERSION,
            },
            "threatInfo": {
                "threatTypes": list(SAFE_BROWSING_THREAT_TYPES),
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        status_code, body, _headers = self._post(
            SAFE_BROWSING_ENDPOINT,
            json_body=payload,
            params={"key": self._api_key},
            headers={"Accept": "application/json"},
            timeout_seconds=timeout_seconds,
            deadline=deadline,
        )
        if status_code != 200:
            return self._http_status_result(
                url, status_code, checked_at=checked_at, start=start
            )

        data = _json_object(body)
        matches = data.get("matches")
        if matches is None:
            return self._no_match_result(url, checked_at=checked_at, start=start)
        if not isinstance(matches, list):
            raise MalformedResponse("matches is not a list")
        if not matches:
            return self._no_match_result(url, checked_at=checked_at, start=start)

        findings: list[NormalizedFinding] = []
        for match in matches:
            if not isinstance(match, dict):
                raise MalformedResponse("match is not an object")
            threat_type = match.get("threatType")
            if not isinstance(threat_type, str) or not threat_type:
                raise MalformedResponse("match has no threatType")
            category, severity = _map_safe_browsing_threat(threat_type)
            findings.append(
                NormalizedFinding(
                    provider=self.name,
                    status=LookupStatus.MATCH,
                    queried_url=url,
                    provider_reference=None,
                    category=category,
                    severity=severity,
                    metadata={
                        "threat_type": threat_type,
                        "platform_type": match.get("platformType"),
                        "threat_entry_type": match.get("threatEntryType"),
                        "cache_duration": match.get("cacheDuration"),
                        "provider_payload": match,
                    },
                    looked_up_at=checked_at,
                    source=self.name,
                )
            )
        return self._match_result(findings, checked_at=checked_at, start=start)


class URLhausProvider(BaseProvider):
    """URLhaus v1 URL lookup adapter."""

    name = URLHAUS_PROVIDER
    display_name = "URLhaus"
    ttl_seconds = 21600

    def _lookup(
        self,
        url: str,
        *,
        checked_at: str,
        start: float,
        timeout_seconds: float | None,
        deadline: float | None,
    ) -> ProviderResult:
        status_code, body, _headers = self._post(
            URLHAUS_ENDPOINT,
            data={"url": url},
            headers={
                "Auth-Key": self._api_key,
                "Accept": "application/json",
            },
            timeout_seconds=timeout_seconds,
            deadline=deadline,
        )
        if status_code != 200:
            return self._http_status_result(
                url, status_code, checked_at=checked_at, start=start
            )

        data = _json_object(body)
        query_status = data.get("query_status")
        if not isinstance(query_status, str) or not query_status:
            raise MalformedResponse("query_status is missing")

        if query_status == "no_results":
            return self._no_match_result(url, checked_at=checked_at, start=start)

        if query_status == "ok":
            threat = data.get("threat")
            tags = data.get("tags")
            category, severity = _map_urlhaus_threat(threat, tags)
            reference = data.get("urlhaus_reference")
            metadata = {
                key: value for key, value in data.items() if key != "query_status"
            }
            metadata["query_status"] = query_status
            finding = NormalizedFinding(
                provider=self.name,
                status=LookupStatus.MATCH,
                queried_url=url,
                provider_reference=reference if isinstance(reference, str) else None,
                category=category,
                severity=severity,
                metadata=metadata,
                looked_up_at=checked_at,
                source=self.name,
            )
            return self._match_result([finding], checked_at=checked_at, start=start)

        if query_status in {"invalid_url", "invalid_host", "invalid_query"}:
            return self._status_result(
                url,
                LookupStatus.ERROR,
                reason=ProviderReason.INVALID_INPUT,
                error=f"URLhaus rejected the URL ({query_status})",
                checked_at=checked_at,
                start=start,
            )
        if query_status in {
            "invalid_auth",
            "unauthorized",
            "authentication_failed",
        }:
            return self._status_result(
                url,
                LookupStatus.UNAVAILABLE,
                reason=ProviderReason.AUTHENTICATION_FAILED,
                error="URLhaus authentication failed",
                checked_at=checked_at,
                start=start,
            )
        if query_status in {"rate_limited", "rate_limit_exceeded"}:
            return self._status_result(
                url,
                LookupStatus.UNAVAILABLE,
                reason=ProviderReason.RATE_LIMITED,
                error="URLhaus rate limit or quota exhausted",
                checked_at=checked_at,
                start=start,
            )
        return self._status_result(
            url,
            LookupStatus.ERROR,
            reason=ProviderReason.PROVIDER_ERROR,
            error=f"URLhaus returned query_status={query_status[:64]}",
            checked_at=checked_at,
            start=start,
        )


def _map_safe_browsing_threat(threat_type: str) -> tuple[str, str]:
    mapping = {
        "MALWARE": ("malware", "high"),
        "SOCIAL_ENGINEERING": ("social_engineering", "high"),
        "UNWANTED_SOFTWARE": ("unwanted_software", "medium"),
        "POTENTIALLY_HARMFUL_APPLICATION": ("potentially_harmful_application", "medium"),
    }
    return mapping.get(threat_type.upper(), (threat_type.lower(), "medium"))


def _map_urlhaus_threat(threat: object, tags: object) -> tuple[str, str]:
    text_parts: list[str] = []
    if isinstance(threat, str):
        text_parts.append(threat)
    if isinstance(tags, list):
        text_parts.extend(str(tag) for tag in tags)
    text = " ".join(text_parts).lower()
    if "malware" in text or "payload" in text:
        return "malware", "high"
    if "phish" in text:
        return "phishing", "high"
    if "scam" in text or "fraud" in text:
        return "scam", "medium"
    return "other", "medium"


def _provider_label(name: str) -> str:
    if name == SAFE_BROWSING_PROVIDER:
        return "Google Safe Browsing"
    if name == URLHAUS_PROVIDER:
        return "URLhaus"
    return name


def _aggregate_status(results: Sequence[ProviderResult]) -> str:
    if not results:
        return "skipped"

    usable = [result for result in results if result.status in LookupStatus.USABLE]
    missing = [
        result
        for result in results
        if result.status == LookupStatus.UNAVAILABLE
        and result.reason == ProviderReason.MISSING_CREDENTIALS
    ]
    failed = [result for result in results if result not in usable and result not in missing]

    if len(missing) == len(results):
        return "skipped"
    if len(usable) == len(results):
        return "ok"
    if usable:
        return "partial"
    if any(result.status == LookupStatus.ERROR for result in failed) and not any(
        result.status == LookupStatus.UNAVAILABLE for result in failed
    ):
        return "error"
    return "unknown"


def _engine_error(status: str, results: Sequence[ProviderResult]) -> str | None:
    if status == "skipped":
        return "No threat-intelligence provider is configured."
    if status == "ok":
        return None
    if status == "partial":
        unavailable = [
            f"{result.provider}={result.reason or result.status}"
            for result in results
            if result.status not in LookupStatus.USABLE
        ]
        return "Partial threat-intelligence coverage: " + ", ".join(unavailable)
    failures = [
        f"{result.provider}={result.reason or result.status}"
        for result in results
        if result.status not in LookupStatus.USABLE
    ]
    return "Threat-intelligence providers did not return a usable verdict: " + ", ".join(
        failures
    )


def run_intel_engine(
    url: str,
    providers: Sequence[BaseProvider],
    *,
    deadline_seconds: float | None = None,
) -> IntelEngineResult:
    """Run every provider and aggregate normalized results.

    One provider failing never suppresses another provider's valid result.  The
    aggregated engine status is ``ok`` only when every provider returned a
    usable match/no-match; otherwise it is ``partial``, ``unknown``, ``error``
    or ``skipped``.  A no-match result produces no finding and is not a safe
    verdict.
    """
    start = time.monotonic()
    deadline = start + deadline_seconds if deadline_seconds is not None else None
    checked_at = utc_now_iso()

    results: list[ProviderResult] = []
    for provider in providers:
        remaining = deadline - time.monotonic() if deadline is not None else None
        if remaining is not None and remaining <= 0:
            results.append(
                provider.unavailable_result(
                    url,
                    reason=ProviderReason.TIMEOUT,
                    error="Threat-intelligence deadline exceeded",
                    checked_at=checked_at,
                )
            )
            continue
        timeout = (
            min(provider.config.timeout_seconds, remaining)
            if remaining is not None
            else None
        )
        results.append(
            provider.lookup(url, timeout_seconds=timeout, deadline=deadline)
        )

    status = _aggregate_status(results)
    findings: list[Finding] = []
    for result in results:
        if result.status != LookupStatus.MATCH:
            continue
        for index, finding in enumerate(result.findings):
            if finding.status != LookupStatus.MATCH:
                continue
            findings.append(
                Finding(
                    id=f"intel-{result.provider}-{len(findings)}",
                    title=f"{_provider_label(result.provider)} reported a threat match",
                    severity=finding.severity,
                    detail=(
                        f"category={finding.category or 'unknown'}; "
                        f"reference={finding.provider_reference or 'not provided'}"
                    )[:4096],
                    evidence_ref=f"intel.providers.{result.provider}.findings.{index}",
                )
            )

    provider_evidence = {result.provider: result.to_dict() for result in results}
    evidence: dict[str, Any] = {
        "providers": provider_evidence,
        "provider_statuses": {result.provider: result.status for result in results},
        "match_providers": [
            result.provider for result in results if result.status == LookupStatus.MATCH
        ],
        "no_match_providers": [
            result.provider for result in results if result.status == LookupStatus.NO_MATCH
        ],
        "unavailable_providers": [
            result.provider
            for result in results
            if result.status == LookupStatus.UNAVAILABLE
        ],
        "error_providers": [
            result.provider for result in results if result.status == LookupStatus.ERROR
        ],
        "cache_hits": [result.provider for result in results if result.cached],
        "policy": {
            "no_match_is_not_safe": True,
            "provider_failure_is_not_safe": True,
            "missing_credentials_is_not_safe": True,
        },
    }

    source = "threat-intel"
    if providers:
        source = "threat-intel:" + ",".join(provider.name for provider in providers)

    result = IntelEngineResult(
        status=status,
        findings=tuple(findings),
        evidence=evidence,
        source=source[:256],
        duration_ms=_elapsed_ms(start),
        error=_engine_error(status, results),
        provider_results=tuple(results),
    )
    logger.info(
        "intel_engine status=%s providers=%s findings=%d duration_ms=%.3f "
        "url_fingerprint=%s",
        status,
        ",".join(f"{result.provider}:{result.status}" for result in results),
        len(findings),
        result.duration_ms,
        _url_fingerprint(url),
    )
    return result
