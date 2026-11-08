"""ML service configuration.

Deliberately separate from services/analysis: the ML service owns no database
credentials and performs no outbound network access.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

VALID_ENVS = frozenset({"development", "test", "staging", "production"})
VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
DEFAULT_DEV_TOKEN = "dev-only-change-me-please"
MIN_TOKEN_LENGTH = 16


class ConfigError(RuntimeError):
    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass(frozen=True)
class Settings:
    env: str
    log_level: str
    service_token: str
    model_path: Path
    feature_contract_path: Path
    require_model: bool

    @property
    def is_production(self) -> bool:
        return self.env == "production"


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    source = os.environ if env is None else env
    problems: list[str] = []

    environment = source.get("ENV", "development").strip().lower()
    if environment not in VALID_ENVS:
        problems.append(f"ENV must be one of {sorted(VALID_ENVS)}")

    log_level = source.get("LOG_LEVEL", "INFO").strip().upper()
    if log_level not in VALID_LOG_LEVELS:
        problems.append(f"LOG_LEVEL must be one of {sorted(VALID_LOG_LEVELS)}")

    token = source.get("ML_SERVICE_TOKEN", DEFAULT_DEV_TOKEN).strip()
    weak_token = token == DEFAULT_DEV_TOKEN or len(token) < MIN_TOKEN_LENGTH
    if environment == "production" and weak_token:
        problems.append("ML_SERVICE_TOKEN must be set to a strong value in production")

    model_path = Path(source.get("MODEL_PATH", "artifacts/model.joblib"))
    contract_path = Path(source.get("FEATURE_CONTRACT_PATH", "artifacts/feature_contract.json"))
    require_model = source.get("ML_REQUIRE_MODEL", "").strip() == "1"
    if require_model and environment == "production" and not model_path.exists():
        problems.append(f"MODEL_PATH does not exist: {model_path}")

    if problems:
        raise ConfigError(problems)

    return Settings(
        env=environment,
        log_level=log_level,
        service_token=token,
        model_path=model_path,
        feature_contract_path=contract_path,
        require_model=require_model,
    )


def redacted_summary(settings: Settings) -> dict[str, object]:
    return {
        "env": settings.env,
        "log_level": settings.log_level,
        "model_path": str(settings.model_path),
        "model_present": settings.model_path.exists(),
        "feature_contract": str(settings.feature_contract_path),
        "feature_contract_present": settings.feature_contract_path.exists(),
    }
