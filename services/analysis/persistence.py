"""Server-only scan persistence for M8.

The analysis service is the only writer of assessment records. It uses the
Supabase service-role key and never returns that key to the web tier or browser.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from uuid import UUID

import httpx
from phishguard_contracts import ScanResult

from app.settings import Settings


class PersistenceError(RuntimeError):
    """Raised when a completed scan cannot be persisted."""


@dataclass(frozen=True)
class ScanRecord:
    id: str
    user_id: str | None
    url: str
    normalized_url: str
    url_hash: str
    status: str
    risk_score: int | None
    risk_band: str | None
    confidence: float | None
    policy_version: str | None
    result: dict[str, Any]
    created_at: str
    completed_at: str | None
    expires_at: str

    def to_row(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "url_hash": self.url_hash,
            "status": self.status,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "confidence": self.confidence,
            "policy_version": self.policy_version,
            "result": self.result,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "expires_at": self.expires_at,
        }


class ScanStore(Protocol):
    def save(self, record: ScanRecord) -> None: ...


def _parse_iso(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _url_hash(normalized_url: str) -> str:
    return hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()


def build_scan_record(
    scan: ScanResult,
    *,
    user_id: str | None,
    retention_days: int,
) -> ScanRecord:
    """Build a persistence row from a contract-validated scan result."""
    if user_id is not None:
        try:
            UUID(user_id)
        except ValueError as exc:
            raise PersistenceError("user_id must be a UUID") from exc

    risk = scan.risk
    expires = _parse_iso(scan.completed_at or scan.created_at) + timedelta(
        days=retention_days
    )
    return ScanRecord(
        id=scan.scan_id,
        user_id=user_id,
        url=scan.url,
        normalized_url=scan.normalized_url,
        url_hash=_url_hash(scan.normalized_url),
        status=scan.status,
        risk_score=risk.score if risk else None,
        risk_band=risk.band if risk else None,
        confidence=risk.confidence.score if risk else None,
        policy_version=risk.policy.version if risk else None,
        result=scan.model_dump(mode="json"),
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        expires_at=expires.isoformat().replace("+00:00", "Z"),
    )


class SupabaseScanStore:
    """Minimal PostgREST writer. Only server-side code may construct this."""

    def __init__(
        self,
        supabase_url: str,
        service_role_key: str,
        *,
        timeout_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        base = supabase_url.rstrip("/")
        if not base.startswith(("http://", "https://")):
            raise PersistenceError("SUPABASE_URL must be an absolute http(s) URL")
        if not service_role_key:
            raise PersistenceError("SUPABASE_SERVICE_ROLE_KEY is required")
        self._base_url = base
        self._service_role_key = service_role_key
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    def save(self, record: ScanRecord) -> None:
        headers = {
            "apikey": self._service_role_key,
            "Authorization": f"Bearer {self._service_role_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates,return=minimal",
        }
        try:
            with httpx.Client(
                timeout=self._timeout_seconds,
                transport=self._transport,
            ) as client:
                response = client.post(
                    f"{self._base_url}/rest/v1/scans?on_conflict=id",
                    headers=headers,
                    json=record.to_row(),
                )
        except httpx.HTTPError as exc:
            raise PersistenceError("Supabase persistence request failed") from exc

        if response.status_code not in {200, 201, 204}:
            raise PersistenceError(
                f"Supabase persistence failed with status {response.status_code}"
            )


def build_scan_store(settings: Settings) -> SupabaseScanStore | None:
    if settings.persistence != "supabase":
        return None
    if not settings.supabase_url or not settings.supabase_service_role_key:
        raise PersistenceError("Supabase persistence is not configured")
    return SupabaseScanStore(
        settings.supabase_url,
        settings.supabase_service_role_key,
    )


def persist_scan(
    store: ScanStore,
    scan: ScanResult,
    *,
    user_id: str,
    retention_days: int,
) -> None:
    store.save(
        build_scan_record(
            scan,
            user_id=user_id,
            retention_days=retention_days,
        )
    )
