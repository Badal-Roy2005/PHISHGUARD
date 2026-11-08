"""Environment validation with fail-fast semantics.

No third-party settings library: the surface is small enough that explicit
validation is clearer and avoids another dependency.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

VALID_ENVS = frozenset({"development", "test", "staging", "production"})
VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
VALID_PERSISTENCE = frozenset({"memory", "supabase"})
DEFAULT_DEV_TOKEN = "dev-only-change-me-please"
MIN_TOKEN_LENGTH = 16


class ConfigError(RuntimeError):
    """Raised when the service is misconfigured. Never starts in this state."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass(frozen=True)
class Settings:
    env: str
    log_level: str
    persistence: str
    service_token: str
    ml_service_url: str
    ml_service_token: str
    allowed_origins: tuple[str, ...]
    supabase_url: str | None
    supabase_service_role_key: str | None
    safe_browsing_key: str | None
    urlhaus_key: str | None
    intel_timeout_seconds: float
    intel_max_response_bytes: int
    intel_max_retries: int
    intel_cache_enabled: bool
    intel_safe_browsing_cache_ttl_seconds: int
    intel_urlhaus_cache_ttl_seconds: int
    ct_enabled: bool
    ct_timeout_seconds: float
    ct_max_response_bytes: int
    ct_max_records: int
    max_concurrent_scans: int
    rate_limit_anon_per_min: int
    rate_limit_user_per_min: int
    scan_retention_days: int
    scanner_allow_loopback_for_tests: bool = field(default=False)

    @property
    def is_production(self) -> bool:
        return self.env == "production"


def _int(env: Mapping[str, str], name: str, default: int, low: int, high: int) -> int:
    raw = env.get(name, "").strip()
    if raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not (low <= value <= high):
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


def _float(
    env: Mapping[str, str],
    name: str,
    default: float,
    low: float,
    high: float,
) -> float:
    raw = env.get(name, "").strip()
    if raw == "":
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not (low <= value <= high):
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name, "").strip().lower()
    if raw == "":
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be one of true/false/1/0")


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    source = os.environ if env is None else env
    problems: list[str] = []

    environment = source.get("ENV", "development").strip().lower()
    if environment not in VALID_ENVS:
        problems.append(f"ENV must be one of {sorted(VALID_ENVS)}")

    log_level = source.get("LOG_LEVEL", "INFO").strip().upper()
    if log_level not in VALID_LOG_LEVELS:
        problems.append(f"LOG_LEVEL must be one of {sorted(VALID_LOG_LEVELS)}")

    persistence = source.get("PERSISTENCE", "memory").strip().lower()
    if persistence not in VALID_PERSISTENCE:
        problems.append(f"PERSISTENCE must be one of {sorted(VALID_PERSISTENCE)}")

    service_token = source.get("INTERNAL_SERVICE_TOKEN", DEFAULT_DEV_TOKEN).strip()
    ml_service_token = source.get("ML_SERVICE_TOKEN", DEFAULT_DEV_TOKEN).strip()
    if environment == "production":
        if service_token == DEFAULT_DEV_TOKEN or len(service_token) < MIN_TOKEN_LENGTH:
            problems.append("INTERNAL_SERVICE_TOKEN must be set to a strong value in production")
        if ml_service_token == DEFAULT_DEV_TOKEN or len(ml_service_token) < MIN_TOKEN_LENGTH:
            problems.append("ML_SERVICE_TOKEN must be set to a strong value in production")

    ml_service_url = source.get("ML_SERVICE_URL", "http://localhost:8001").strip()
    if not ml_service_url.startswith(("http://", "https://")):
        problems.append("ML_SERVICE_URL must be an absolute http(s) URL")

    origins_raw = source.get("ALLOWED_ORIGINS", "http://localhost:3000")
    origins = tuple(o.strip().rstrip("/") for o in origins_raw.split(",") if o.strip())
    if not origins:
        problems.append("ALLOWED_ORIGINS must contain at least one origin")
    if environment == "production" and any(o == "*" for o in origins):
        problems.append("ALLOWED_ORIGINS must not be '*' in production")

    supabase_url = source.get("SUPABASE_URL", "").strip() or None
    service_role = source.get("SUPABASE_SERVICE_ROLE_KEY", "").strip() or None
    if persistence == "supabase":
        if not supabase_url:
            problems.append("SUPABASE_URL is required when PERSISTENCE=supabase")
        if not service_role:
            problems.append("SUPABASE_SERVICE_ROLE_KEY is required when PERSISTENCE=supabase")

    allow_loopback = source.get("SCANNER_ALLOW_LOOPBACK_FOR_TESTS", "").strip() == "1"
    if allow_loopback and environment == "production":
        problems.append("SCANNER_ALLOW_LOOPBACK_FOR_TESTS must never be set in production")

    try:
        max_concurrent = _int(source, "MAX_CONCURRENT_SCANS", 8, 1, 64)
        anon_rate = _int(source, "RATE_LIMIT_ANON_PER_MIN", 10, 1, 600)
        user_rate = _int(source, "RATE_LIMIT_USER_PER_MIN", 30, 1, 600)
        intel_timeout = _float(source, "INTEL_HTTP_TIMEOUT_SECONDS", 5.0, 0.5, 15.0)
        intel_max_bytes = _int(
            source, "INTEL_MAX_RESPONSE_BYTES", 256_000, 1_024, 2_000_000
        )
        intel_max_retries = _int(source, "INTEL_MAX_RETRIES", 1, 0, 2)
        intel_sb_ttl = _int(
            source, "INTEL_SAFE_BROWSING_CACHE_TTL_SECONDS", 3_600, 60, 86_400
        )
        intel_urlhaus_ttl = _int(
            source, "INTEL_URLHAUS_CACHE_TTL_SECONDS", 21_600, 60, 86_400
        )
        intel_cache_enabled = _bool(source, "INTEL_CACHE_ENABLED", True)
        ct_enabled = _bool(source, "CT_ENABLED", False)
        ct_timeout = _float(source, "CT_TIMEOUT_SECONDS", 5.0, 0.5, 15.0)
        ct_max_bytes = _int(source, "CT_MAX_RESPONSE_BYTES", 1_000_000, 1_024, 2_000_000)
        ct_max_records = _int(source, "CT_MAX_RECORDS", 1_000, 1, 5_000)
        scan_retention_days = _int(source, "SCAN_RETENTION_DAYS", 90, 1, 3_650)
    except ValueError as exc:
        problems.append(str(exc))
        max_concurrent, anon_rate, user_rate = 8, 10, 30
        intel_timeout, intel_max_bytes, intel_max_retries = 5.0, 256_000, 1
        intel_sb_ttl, intel_urlhaus_ttl, intel_cache_enabled = 3_600, 21_600, True
        ct_enabled, ct_timeout, ct_max_bytes, ct_max_records = False, 5.0, 1_000_000, 1_000
        scan_retention_days = 90

    if problems:
        raise ConfigError(problems)

    return Settings(
        env=environment,
        log_level=log_level,
        persistence=persistence,
        service_token=service_token,
        ml_service_url=ml_service_url,
        ml_service_token=ml_service_token,
        allowed_origins=origins,
        supabase_url=supabase_url,
        supabase_service_role_key=service_role,
        safe_browsing_key=source.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip() or None,
        urlhaus_key=source.get("URLHAUS_API_KEY", "").strip() or None,
        intel_timeout_seconds=intel_timeout,
        intel_max_response_bytes=intel_max_bytes,
        intel_max_retries=intel_max_retries,
        intel_cache_enabled=intel_cache_enabled,
        intel_safe_browsing_cache_ttl_seconds=intel_sb_ttl,
        intel_urlhaus_cache_ttl_seconds=intel_urlhaus_ttl,
        ct_enabled=ct_enabled,
        ct_timeout_seconds=ct_timeout,
        ct_max_response_bytes=ct_max_bytes,
        ct_max_records=ct_max_records,
        max_concurrent_scans=max_concurrent,
        rate_limit_anon_per_min=anon_rate,
        rate_limit_user_per_min=user_rate,
        scan_retention_days=scan_retention_days,
        scanner_allow_loopback_for_tests=allow_loopback,
    )


def redacted_summary(settings: Settings) -> dict[str, object]:
    """Safe to log and to expose on /health. Never includes secret values."""
    return {
        "env": settings.env,
        "log_level": settings.log_level,
        "persistence": settings.persistence,
        "ml_service_url": settings.ml_service_url,
        "allowed_origins": list(settings.allowed_origins),
        "max_concurrent_scans": settings.max_concurrent_scans,
        "threat_intel": {
            "google_safe_browsing": "configured" if settings.safe_browsing_key else "skipped",
            "urlhaus": "configured" if settings.urlhaus_key else "skipped",
            "timeout_seconds": settings.intel_timeout_seconds,
            "max_response_bytes": settings.intel_max_response_bytes,
            "max_retries": settings.intel_max_retries,
            "cache_enabled": settings.intel_cache_enabled,
            "cache_ttl_seconds": {
                "google_safe_browsing": settings.intel_safe_browsing_cache_ttl_seconds,
                "urlhaus": settings.intel_urlhaus_cache_ttl_seconds,
            },
        },
        "certificate_transparency": {
            "enabled": settings.ct_enabled,
            "timeout_seconds": settings.ct_timeout_seconds,
            "max_response_bytes": settings.ct_max_response_bytes,
            "max_records": settings.ct_max_records,
        },
        "supabase": "configured" if settings.supabase_url else "not_configured",
        "scan_retention_days": settings.scan_retention_days,
    }
