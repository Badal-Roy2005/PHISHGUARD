"""Certificate Transparency lookup via crt.sh for PHISHGUARD M6.

The endpoint is fixed and the queried domain is a parameter, never a connection
host. Lookups are bounded by timeout, response size and record count. A CT
failure is reported explicitly and is never treated as a clean TLS result.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("phishguard.certificate_transparency")

CT_ENDPOINT = "https://crt.sh/"
CT_SOURCE = "crt.sh"
DOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
RECENT_CERTIFICATE_LIMIT = 5


class CTStatus:
    OK = "ok"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class CTReason:
    INVALID_DOMAIN = "invalid_domain"
    DISABLED_BY_CONFIG = "disabled_by_config"
    NOT_REQUESTED = "not_requested"
    NOT_HTTPS = "not_https"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    AUTHENTICATION_FAILED = "authentication_failed"
    UPSTREAM_UNAVAILABLE = "upstream_unavailable"
    RESPONSE_TOO_LARGE = "response_too_large"
    MALFORMED_RESPONSE = "malformed_response"
    HTTP_ERROR = "http_error"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class CTConfig:
    timeout_seconds: float = 5.0
    max_response_bytes: int = 1_000_000
    max_records: int = 1_000
    user_agent: str = "PHISHGUARD-CT/1.0"


@dataclass(frozen=True)
class CTResult:
    status: str
    domain: str
    certificate_count: int = 0
    unique_issuers: tuple[str, ...] = ()
    first_seen: str | None = None
    last_seen: str | None = None
    recent_certificates: tuple[dict[str, Any], ...] = ()
    records_examined: int = 0
    records_processed: int = 0
    reason: str | None = None
    error: str | None = None
    duration_ms: float = 0.0
    source: str = CT_SOURCE

    def to_evidence(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "domain": self.domain,
            "certificate_count": self.certificate_count,
            "unique_issuers": list(self.unique_issuers),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "recent_certificates": list(self.recent_certificates),
            "records_examined": self.records_examined,
            "records_processed": self.records_processed,
            "reason": self.reason,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "source": self.source,
            "policy": {
                "failure_is_not_safe": True,
                "no_certificate_is_not_safe": True,
            },
        }


class CTResponseTooLarge(RuntimeError):
    pass


class CTMalformedResponse(RuntimeError):
    pass


def _elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000, 3)


def _normalize_domain(target: str) -> str:
    raw = target.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        if parsed.username or parsed.password:
            raise ValueError("URL must not contain credentials")
    else:
        host = raw.split("/", 1)[0]

    host = host.rstrip(".").lower()
    if not host:
        raise ValueError("domain is empty")

    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("domain is not valid IDNA") from exc

    if len(host) > 253 or not DOMAIN_PATTERN.fullmatch(host):
        raise ValueError("domain is not a valid hostname")

    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError("Certificate Transparency requires a domain name, not an IP")


def _safe_domain_label(target: str) -> str:
    try:
        return (urlparse(target).hostname or target)[:253]
    except ValueError:
        return target[:253]


def _read_limited(response: httpx.Response, max_bytes: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            if int(content_length) > max_bytes:
                raise CTResponseTooLarge
        except ValueError:
            pass

    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > max_bytes:
            raise CTResponseTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_records(body: bytes, max_records: int) -> tuple[list[dict[str, Any]], int, int]:
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CTMalformedResponse("crt.sh response is not valid JSON") from exc

    if not isinstance(payload, list):
        raise CTMalformedResponse("crt.sh response is not a JSON array")

    processed = payload[: max(1, max_records)]
    records = [record for record in processed if isinstance(record, dict)]
    return records, len(payload), len(processed)


def _certificate_record(record: dict[str, Any]) -> dict[str, Any]:
    name_value = record.get("name_value")
    if name_value is not None:
        name_value = str(name_value).replace("\r", "\n").strip()[:2048]
    return {
        "id": record.get("id"),
        "common_name": (str(record.get("common_name") or "")[:256] or None),
        "issuer_name": (str(record.get("issuer_name") or "")[:512] or None),
        "not_before": record.get("not_before"),
        "not_after": record.get("not_after"),
        "name_value": name_value,
    }


def _dedupe_key(record: dict[str, Any]) -> tuple[Any, ...]:
    if record.get("id") is not None:
        return ("id", record["id"])
    return (
        "tuple",
        record.get("common_name"),
        record.get("not_before"),
        record.get("not_after"),
    )


class CertificateTransparencyClient:
    """Bounded crt.sh client. The endpoint is fixed and never user-controlled."""

    def __init__(
        self,
        config: CTConfig | None = None,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self.config = config or CTConfig()
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(self.config.timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": self.config.user_agent},
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> CertificateTransparencyClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def lookup(
        self,
        target: str,
        *,
        timeout_seconds: float | None = None,
        deadline: float | None = None,
    ) -> CTResult:
        start = time.monotonic()
        try:
            domain = _normalize_domain(target)
        except ValueError as exc:
            return self._result(
                CTStatus.ERROR,
                domain=_safe_domain_label(target),
                reason=CTReason.INVALID_DOMAIN,
                error=str(exc),
                start=start,
            )

        timeout = self.config.timeout_seconds
        if timeout_seconds is not None:
            timeout = min(timeout, timeout_seconds)
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return self._result(
                    CTStatus.UNAVAILABLE,
                    domain=domain,
                    reason=CTReason.TIMEOUT,
                    error="Certificate Transparency lookup exceeded the deadline.",
                    start=start,
                )
            timeout = min(timeout, remaining)
        timeout = max(0.1, timeout)

        try:
            with self._client.stream(
                "GET",
                CT_ENDPOINT,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=httpx.Timeout(timeout),
                follow_redirects=False,
            ) as response:
                if response.status_code == 429:
                    return self._result(
                        CTStatus.UNAVAILABLE,
                        domain=domain,
                        reason=CTReason.RATE_LIMITED,
                        error="crt.sh rate limit or quota exhausted.",
                        start=start,
                    )
                if response.status_code in (401, 403):
                    return self._result(
                        CTStatus.UNAVAILABLE,
                        domain=domain,
                        reason=CTReason.AUTHENTICATION_FAILED,
                        error="crt.sh authentication failed.",
                        start=start,
                    )
                if 500 <= response.status_code <= 599:
                    return self._result(
                        CTStatus.UNAVAILABLE,
                        domain=domain,
                        reason=CTReason.UPSTREAM_UNAVAILABLE,
                        error=f"crt.sh is unavailable (HTTP {response.status_code}).",
                        start=start,
                    )
                if response.status_code != 200:
                    return self._result(
                        CTStatus.ERROR,
                        domain=domain,
                        reason=CTReason.HTTP_ERROR,
                        error=f"crt.sh returned HTTP {response.status_code}.",
                        start=start,
                    )
                body = _read_limited(response, self.config.max_response_bytes)

            records, examined, processed = _parse_records(
                body, self.config.max_records
            )
        except CTResponseTooLarge:
            return self._result(
                CTStatus.ERROR,
                domain=domain,
                reason=CTReason.RESPONSE_TOO_LARGE,
                error="crt.sh response exceeded the size limit.",
                start=start,
            )
        except CTMalformedResponse as exc:
            return self._result(
                CTStatus.ERROR,
                domain=domain,
                reason=CTReason.MALFORMED_RESPONSE,
                error=str(exc),
                start=start,
            )
        except httpx.TimeoutException:
            return self._result(
                CTStatus.UNAVAILABLE,
                domain=domain,
                reason=CTReason.TIMEOUT,
                error="crt.sh request timed out.",
                start=start,
            )
        except httpx.HTTPError:
            return self._result(
                CTStatus.UNAVAILABLE,
                domain=domain,
                reason=CTReason.UPSTREAM_UNAVAILABLE,
                error="crt.sh request failed.",
                start=start,
            )
        except Exception as exc:  # noqa: BLE001 - CT must not fail the whole scan
            logger.warning(
                "ct_unexpected_error=%s domain=%s",
                type(exc).__name__,
                domain,
            )
            return self._result(
                CTStatus.ERROR,
                domain=domain,
                reason=CTReason.INTERNAL_ERROR,
                error="Certificate Transparency lookup failed unexpectedly.",
                start=start,
            )

        certificates: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for record in records:
            certificate = _certificate_record(record)
            key = _dedupe_key(certificate)
            if key in seen:
                continue
            seen.add(key)
            certificates.append(certificate)

        issuers = sorted(
            {
                certificate["issuer_name"]
                for certificate in certificates
                if certificate["issuer_name"]
            }
        )
        not_before_values = [
            certificate["not_before"]
            for certificate in certificates
            if isinstance(certificate["not_before"], str)
        ]
        recent = sorted(
            certificates,
            key=lambda certificate: str(certificate.get("not_before") or ""),
            reverse=True,
        )[:RECENT_CERTIFICATE_LIMIT]

        return self._result(
            CTStatus.OK,
            domain=domain,
            certificate_count=len(certificates),
            unique_issuers=tuple(issuers),
            first_seen=min(not_before_values) if not_before_values else None,
            last_seen=max(not_before_values) if not_before_values else None,
            recent_certificates=tuple(recent),
            records_examined=examined,
            records_processed=processed,
            start=start,
        )

    def _result(
        self,
        status: str,
        *,
        domain: str,
        reason: str | None = None,
        error: str | None = None,
        certificate_count: int = 0,
        unique_issuers: tuple[str, ...] = (),
        first_seen: str | None = None,
        last_seen: str | None = None,
        recent_certificates: tuple[dict[str, Any], ...] = (),
        records_examined: int = 0,
        records_processed: int = 0,
        start: float,
    ) -> CTResult:
        return CTResult(
            status=status,
            domain=domain,
            certificate_count=certificate_count,
            unique_issuers=unique_issuers,
            first_seen=first_seen,
            last_seen=last_seen,
            recent_certificates=recent_certificates,
            records_examined=records_examined,
            records_processed=records_processed,
            reason=reason,
            error=error,
            duration_ms=_elapsed_ms(start),
        )


def skipped_result(domain: str, *, reason: str, error: str) -> CTResult:
    return CTResult(
        status=CTStatus.SKIPPED,
        domain=domain,
        reason=reason,
        error=error,
        duration_ms=0.0,
    )
