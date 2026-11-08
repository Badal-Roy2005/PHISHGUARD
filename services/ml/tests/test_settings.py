from __future__ import annotations

import pytest

from app.settings import ConfigError, load_settings


def test_dev_defaults() -> None:
    settings = load_settings({"ENV": "development"})
    assert settings.env == "development"
    assert not settings.require_model


def test_production_requires_strong_token() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings({"ENV": "production"})
    assert any("ML_SERVICE_TOKEN" in p for p in excinfo.value.problems)


def test_production_requires_model_when_flagged(tmp_path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings(
            {
                "ENV": "production",
                "ML_SERVICE_TOKEN": "a" * 32,
                "ML_REQUIRE_MODEL": "1",
                "MODEL_PATH": str(tmp_path / "missing.joblib"),
            }
        )
    assert any("MODEL_PATH" in p for p in excinfo.value.problems)
