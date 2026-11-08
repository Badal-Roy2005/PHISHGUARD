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
