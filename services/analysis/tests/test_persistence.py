from __future__ import annotations

import uuid
from datetime import UTC, datetime

import httpx
import pytest
from phishguard_contracts import (
    ConfidenceScore,
    EngineReport,
    Engines,
    Explanation,
    LikelihoodScore,
    PostureScore,
    RiskAssessment,
    RiskBandRange,
    RiskPolicyMetadata,
    RiskWeights,
    ScanResult,
)

from app.settings import Settings
from persistence import (
    PersistenceError,
    ScanRecord,
    SupabaseScanStore,
    build_scan_record,
    build_scan_store,
    persist_scan,
)


def _make_scan_result(scan_id: str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") -> ScanResult:
    risk = RiskAssessment(
        score=42,
        band="suspicious",
        verdict="suspicious",
        incomplete=False,
        likelihood=LikelihoodScore(score=0.5, band="suspicious"),
        posture=PostureScore(score=50.0, grade="C", status="ok"),
        confidence=ConfidenceScore(
            score=0.9,
            engines_ok=3,
            engines_total=6,
            covered_weight=50,
            total_weight=100,
            incomplete=False,
        ),
        policy=RiskPolicyMetadata(
            version="m7-2026-11-09.2",
            calibrated=False,
            weights=RiskWeights(
                intel=20, url=30, brand=0, redirect=0, tls=25, http=25,
            ),
            bands=[
                RiskBandRange(band="low", min_score=0, max_score=33),
                RiskBandRange(band="suspicious", min_score=34, max_score=66),
                RiskBandRange(band="high", min_score=67, max_score=100),
            ],
            min_coverage_for_score=0.5,
            min_coverage_for_low=0.8,
        ),
    )
    ok_report = EngineReport(
        engine="url", status="ok", findings=[], evidence={},
        source="phishguard-url@0.1.0", duration_ms=0.0,
    )
    skipped_report = EngineReport(
        engine="intel", status="skipped", findings=[], evidence={},
        source="threat-intel", duration_ms=0.0,
    )
    unknown_report = EngineReport(
        engine="ml", status="unknown", findings=[], evidence={},
        source="not-implemented", duration_ms=0.0,
        error="ML inference is not wired into scan orchestration yet; probability is separate.",
    )
    return ScanResult(
        scan_id=scan_id,
        url="https://example.com/",
        normalized_url="https://example.com/",
        status="complete",
        created_at=datetime.now(UTC).isoformat(),
        completed_at=datetime.now(UTC).isoformat(),
        duration_ms=10.0,
        risk=risk,
        engines=Engines(
            ml=unknown_report,
            url=ok_report,
            tls=ok_report,
            http=ok_report,
            intel=skipped_report,
            community=skipped_report,
        ),
        explanation=Explanation(top_factors=[], summary="test"),
        evidence={},
    )


def test_build_scan_record_sets_fields_and_hash() -> None:
    scan = _make_scan_result()
    record = build_scan_record(
        scan, user_id="11111111-1111-4111-8111-111111111111", retention_days=90
    )
    assert record.id == scan.scan_id
    assert record.user_id == "11111111-1111-4111-8111-111111111111"
    assert record.url == scan.url
    assert record.normalized_url == scan.normalized_url
    assert record.url_hash == __import__("hashlib").sha256(
        scan.normalized_url.encode("utf-8")
    ).hexdigest()
    assert record.status == "complete"
    assert record.risk_score == 42
    assert record.risk_band == "suspicious"
    assert record.confidence == 0.9
    assert record.policy_version == "m7-2026-11-09.2"
    assert record.expires_at.endswith("Z")


def test_build_scan_record_rejects_non_uuid_user_id() -> None:
    scan = _make_scan_result()
    with pytest.raises(PersistenceError, match="user_id must be a UUID"):
        build_scan_record(scan, user_id="not-a-uuid", retention_days=90)


def test_build_scan_record_accepts_none_user_id() -> None:
    scan = _make_scan_result()
    record = build_scan_record(scan, user_id=None, retention_days=90)
    assert record.user_id is None


def test_build_scan_store_returns_none_for_memory() -> None:
    settings = Settings(
        env="development",
        log_level="INFO",
        persistence="memory",
        service_token="x",
        ml_service_url="http://localhost:8001",
        ml_service_token="x",
        allowed_origins=("http://localhost:3000",),
        supabase_url=None,
        supabase_service_role_key=None,
        safe_browsing_key=None,
        urlhaus_key=None,
        intel_timeout_seconds=5.0,
        intel_max_response_bytes=256000,
        intel_max_retries=1,
        intel_cache_enabled=True,
        intel_safe_browsing_cache_ttl_seconds=3600,
        intel_urlhaus_cache_ttl_seconds=21600,
        ct_enabled=False,
        ct_timeout_seconds=5.0,
        ct_max_response_bytes=1000000,
        ct_max_records=1000,
        max_concurrent_scans=8,
        rate_limit_anon_per_min=10,
        rate_limit_user_per_min=30,
        scan_retention_days=90,
    )
    assert build_scan_store(settings) is None


def test_build_scan_store_raises_without_credentials() -> None:
    settings = Settings(
        env="development",
        log_level="INFO",
        persistence="supabase",
        service_token="x",
        ml_service_url="http://localhost:8001",
        ml_service_token="x",
        allowed_origins=("http://localhost:3000",),
        supabase_url=None,
        supabase_service_role_key=None,
        safe_browsing_key=None,
        urlhaus_key=None,
        intel_timeout_seconds=5.0,
        intel_max_response_bytes=256000,
        intel_max_retries=1,
        intel_cache_enabled=True,
        intel_safe_browsing_cache_ttl_seconds=3600,
        intel_urlhaus_cache_ttl_seconds=21600,
        ct_enabled=False,
        ct_timeout_seconds=5.0,
        ct_max_response_bytes=1000000,
        ct_max_records=1000,
        max_concurrent_scans=8,
        rate_limit_anon_per_min=10,
        rate_limit_user_per_min=30,
        scan_retention_days=90,
    )
    with pytest.raises(PersistenceError, match="not configured"):
        build_scan_store(settings)


def test_persist_scan_calls_store_save(monkeypatch: pytest.MonkeyPatch) -> None:
    saved = []

    class FakeStore:
        def save(self, record: ScanRecord) -> None:
            saved.append(record)

    scan = _make_scan_result()
    persist_scan(
        FakeStore(),
        scan,
        user_id="11111111-1111-4111-8111-111111111111",
        retention_days=90,
    )
    assert len(saved) == 1
    assert saved[0].id == scan.scan_id


def test_supabase_scan_store_rejects_bad_url() -> None:
    with pytest.raises(PersistenceError, match="SUPABASE_URL must be an absolute"):
        SupabaseScanStore("ftp://example.com", "key")


def test_supabase_scan_store_rejects_empty_key() -> None:
    with pytest.raises(PersistenceError, match="required"):
        SupabaseScanStore("https://example.supabase.co", "")


def test_supabase_scan_store_saves_via_post(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class FakeResponse:
        status_code = 201

    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.kwargs = kwargs

        def post(self, url, headers, json):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return FakeResponse()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(httpx, "Client", FakeClient)

    store = SupabaseScanStore("https://example.supabase.co", "service-role-key")
    record = ScanRecord(
        id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        user_id="11111111-1111-4111-8111-111111111111",
        url="https://example.com/",
        normalized_url="https://example.com/",
        url_hash="x" * 64,
        status="complete",
        risk_score=42,
        risk_band="suspicious",
        confidence=0.9,
        policy_version="m7-2026-11-09.2",
        result={},
        created_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:00Z",
        expires_at="2026-04-01T00:00:00Z",
    )
    store.save(record)
    assert "/rest/v1/scans?on_conflict=id" in captured["url"]
    assert captured["headers"]["apikey"] == "service-role-key"
    assert captured["headers"]["Authorization"] == "Bearer service-role-key"
    assert captured["json"]["user_id"] == "11111111-1111-4111-8111-111111111111"
    # The service-role key must never leak into the request body.
    assert "service-role-key" not in repr(captured["json"])


def test_non_2xx_status_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status_code = 500

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def post(self, url, headers, json):
            return FakeResponse()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(httpx, "Client", FakeClient)

    store = SupabaseScanStore("https://example.supabase.co", "key")
    record = ScanRecord(
        id=str(uuid.uuid4()),
        user_id=None,
        url="https://example.com/",
        normalized_url="https://example.com/",
        url_hash="x" * 64,
        status="complete",
        risk_score=None,
        risk_band=None,
        confidence=None,
        policy_version=None,
        result={},
        created_at="2026-01-01T00:00:00Z",
        completed_at=None,
        expires_at="2026-04-01T00:00:00Z",
    )
    with pytest.raises(PersistenceError, match="failed with status 500"):
        store.save(record)
