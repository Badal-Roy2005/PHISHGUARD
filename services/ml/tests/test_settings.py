from __future__ import annotations

from pathlib import Path

import pytest

from app.settings import ConfigError, load_settings, redacted_summary


def test_dev_defaults_derive_paths_from_artifacts_dir() -> None:
    settings = load_settings({"ENV": "development"})
    assert settings.env == "development"
    assert not settings.require_model
    assert settings.artifacts_dir == Path("artifacts")
    assert settings.model_path == Path("artifacts/model.joblib")
    assert settings.feature_contract_path == Path("artifacts/feature_contract.json")


def test_artifacts_dir_override_derives_paths() -> None:
    settings = load_settings({"ENV": "test", "ARTIFACTS_DIR": "/srv/models"})
    assert settings.artifacts_dir == Path("/srv/models")
    assert settings.model_path == Path("/srv/models/model.joblib")
    assert settings.feature_contract_path == Path("/srv/models/feature_contract.json")


def test_explicit_paths_win_over_the_artifacts_dir() -> None:
    settings = load_settings(
        {
            "ENV": "test",
            "ARTIFACTS_DIR": "/srv/models",
            "MODEL_PATH": "/opt/model.joblib",
            "FEATURE_CONTRACT_PATH": "/opt/contract.json",
        }
    )
    assert settings.model_path == Path("/opt/model.joblib")
    assert settings.feature_contract_path == Path("/opt/contract.json")


def test_production_requires_strong_token() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings({"ENV": "production"})
    assert any("ML_SERVICE_TOKEN" in p for p in excinfo.value.problems)


def test_production_requires_artifacts_when_flagged(tmp_path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_settings(
            {
                "ENV": "production",
                "ML_SERVICE_TOKEN": "a" * 32,
                "ML_REQUIRE_MODEL": "1",
                "ARTIFACTS_DIR": str(tmp_path / "missing"),
            }
        )
    problems = " ".join(excinfo.value.problems)
    assert "required artifact does not exist" in problems
    assert "model.joblib" in problems


def test_production_accepts_present_artifacts(tmp_path) -> None:
    for name in ("model.joblib", "feature_contract.json", "selected.json"):
        (tmp_path / name).write_text("{}", encoding="utf-8")
    settings = load_settings(
        {
            "ENV": "production",
            "ML_SERVICE_TOKEN": "a" * 32,
            "ML_REQUIRE_MODEL": "1",
            "ARTIFACTS_DIR": str(tmp_path),
        }
    )
    assert settings.require_model
    assert redacted_summary(settings)["model_present"] is True
