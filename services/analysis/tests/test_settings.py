from __future__ import annotations

import pytest

from app.settings import ConfigError, load_settings


def test_dev_defaults_are_permissive() -> None:
    settings = load_settings({"ENV": "development"})
    assert settings.env == "development"
    assert settings.persistence == "memory"
    assert settings.safe_browsing_key is None


def test_production_requires_strong_tokens() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings({"ENV": "production"})
    joined = " ".join(excinfo.value.problems)
    assert "INTERNAL_SERVICE_TOKEN" in joined
    assert "ML_SERVICE_TOKEN" in joined


def test_loopback_override_is_refused_in_production() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings(
            {
                "ENV": "production",
                "INTERNAL_SERVICE_TOKEN": "a" * 32,
                "ML_SERVICE_TOKEN": "b" * 32,
                "SCANNER_ALLOW_LOOPBACK_FOR_TESTS": "1",
            }
        )
    assert any("LOOPBACK" in p for p in excinfo.value.problems)


def test_supabase_persistence_requires_credentials() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings({"ENV": "development", "PERSISTENCE": "supabase"})
    joined = " ".join(excinfo.value.problems)
    assert "SUPABASE_URL" in joined
    assert "SUPABASE_SERVICE_ROLE_KEY" in joined


def test_invalid_numeric_bounds_are_reported() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings({"ENV": "development", "MAX_CONCURRENT_SCANS": "999"})
    assert any("MAX_CONCURRENT_SCANS" in p for p in excinfo.value.problems)


def test_invalid_intel_bounds_are_reported() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings({"ENV": "development", "INTEL_HTTP_TIMEOUT_SECONDS": "99"})
    assert any("INTEL_HTTP_TIMEOUT_SECONDS" in p for p in excinfo.value.problems)


def test_intel_cache_can_be_disabled() -> None:
    settings = load_settings({"ENV": "development", "INTEL_CACHE_ENABLED": "false"})
    assert settings.intel_cache_enabled is False


def test_redacted_summary_never_contains_secrets() -> None:
    from app.settings import redacted_summary

    settings = load_settings(
        {
            "ENV": "development",
            "GOOGLE_SAFE_BROWSING_API_KEY": "super-secret-key",
            "SUPABASE_SERVICE_ROLE_KEY": "service-role-secret",
            "SUPABASE_URL": "https://example.supabase.co",
        }
    )
    summary = redacted_summary(settings)
    serialized = repr(summary)
    assert "super-secret-key" not in serialized
    assert "service-role-secret" not in serialized
    assert summary["threat_intel"]["google_safe_browsing"] == "configured"


def test_ct_is_disabled_by_default_and_bounded() -> None:
    settings = load_settings({"ENV": "development"})
    assert settings.ct_enabled is False
    assert settings.ct_timeout_seconds == 5.0
    assert settings.ct_max_response_bytes == 1_000_000
    assert settings.ct_max_records == 1_000


def test_ct_settings_are_validated() -> None:
    settings = load_settings(
        {
            "ENV": "development",
            "CT_ENABLED": "true",
            "CT_TIMEOUT_SECONDS": "2.5",
            "CT_MAX_RESPONSE_BYTES": "2048",
            "CT_MAX_RECORDS": "50",
        }
    )
    assert settings.ct_enabled is True
    assert settings.ct_timeout_seconds == 2.5
    assert settings.ct_max_response_bytes == 2048
    assert settings.ct_max_records == 50

    with pytest.raises(ConfigError) as excinfo:
        load_settings({"ENV": "development", "CT_TIMEOUT_SECONDS": "99"})
    assert any("CT_TIMEOUT_SECONDS" in p for p in excinfo.value.problems)


def test_redacted_summary_reports_ct_without_secrets() -> None:
    from app.settings import redacted_summary

    summary = redacted_summary(load_settings({"ENV": "development"}))
    assert summary["certificate_transparency"]["enabled"] is False
    assert "CT_TIMEOUT" not in repr(summary)
