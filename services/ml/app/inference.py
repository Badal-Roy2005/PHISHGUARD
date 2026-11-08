"""Model loading and inference.

The served model is the URL-only ``live`` model. Every feature it consumes is
documented in ``artifacts/feature_contract.json``; nothing here can introduce a
page-content feature or a corpus statistic at request time.

Missing-feature policy (mirrors ``default_policy: "unknown"`` in the contract):

* all features present -> ``status: "ok"``
* up to 25% missing   -> ``status: "partial"``, the pipeline's training median is
  used and every imputed name is returned in ``missing_features``
* more than 25% missing -> ``status: "unknown"`` and ``label: "unknown"``; the
  probability is still returned because the wire contract requires the field, but
  it is explicitly not a usable verdict.
"""

from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from phishguard_contracts import (
    Contribution,
    FeatureContract,
    ModelMetadata,
    PredictRequest,
    PredictResponse,
)

logger = logging.getLogger("phishguard.ml.inference")

MAX_MISSING_FRACTION = 0.25


class ModelNotAvailable(RuntimeError):
    """No usable artifact is on disk."""


class UnknownFeatureError(ValueError):
    """A caller supplied a feature name that is not in the contract."""


class InvalidFeatureValueError(ValueError):
    """A caller supplied a value that cannot be coerced to a finite number."""


@dataclass
class LoadedModel:
    pipeline: Any
    feature_order: tuple[str, ...]
    threshold: float
    metadata: ModelMetadata
    contract: FeatureContract
    artifacts: dict[str, Any] = field(default_factory=dict)
    _explainer: Any = None
    _explainer_method: str | None = None
    _background: np.ndarray | None = None

    def _ensure_explainer(self) -> str | None:
        if self._explainer_method is not None:
            return self._explainer_method
        try:
            from training.explain import build_explainer

            background = self._background
            if background is None:
                background = np.zeros((1, len(self.feature_order)), dtype=float)
            self._explainer, self._explainer_method = build_explainer(self.pipeline, background)
        except Exception as exc:  # noqa: BLE001 - explanations must not break inference
            logger.warning("SHAP unavailable: %s", exc)
            self._explainer = None
            self._explainer_method = "unavailable"
        return self._explainer_method

    def contributions(
        self, vector: dict[str, float], limit: int = 20
    ) -> list[Contribution]:
        if self._ensure_explainer() in (None, "unavailable"):
            return []
        from training.explain import row_contributions

        rows = row_contributions(
            self.pipeline,
            self._explainer,
            self.feature_order,
            vector,
            limit=limit,
        )
        return [Contribution.model_validate(row) for row in rows]


class ModelService:
    """Loads one artifact set and answers prediction/explanation requests."""

    def __init__(
        self,
        model_path: str | Path,
        contract_path: str | Path,
        selected_path: str | Path | None = None,
    ) -> None:
        self.model_path = Path(model_path)
        self.contract_path = Path(contract_path)
        self.selected_path = (
            Path(selected_path)
            if selected_path is not None
            else self.model_path.parent / "selected.json"
        )
        self._model: LoadedModel | None = None
        self._load_error: str | None = None

    @property
    def loaded(self) -> bool:
        return self._model is not None

    @property
    def load_error(self) -> str | None:
        return self._load_error

    def load(self) -> LoadedModel:
        if self._model is not None:
            return self._model
        missing = [
            str(path)
            for path in (self.model_path, self.contract_path, self.selected_path)
            if not path.exists()
        ]
        if missing:
            self._load_error = f"missing artifacts: {missing}"
            raise ModelNotAvailable(self._load_error)

        try:
            pipeline = joblib.load(self.model_path)
            raw_contract = json.loads(self.contract_path.read_text(encoding="utf-8"))
            selected = json.loads(self.selected_path.read_text(encoding="utf-8"))
            contract = FeatureContract.model_validate(raw_contract)
            metadata = ModelMetadata.model_validate(selected["model"])
        except Exception as exc:  # noqa: BLE001 - surfaced as 503, not a crash
            self._load_error = f"invalid artifacts: {exc}"
            raise ModelNotAvailable(self._load_error) from exc

        feature_order = tuple(selected.get("feature_order") or [f.name for f in contract.features])
        contract_names = [f.name for f in contract.features]
        if list(feature_order) != contract_names:
            self._load_error = "selected.json feature_order does not match the contract"
            raise ModelNotAvailable(self._load_error)

        threshold = float(selected.get("threshold", 0.5))
        self._model = LoadedModel(
            pipeline=pipeline,
            feature_order=feature_order,
            threshold=threshold,
            metadata=metadata,
            contract=contract,
            artifacts={
                "model": str(self.model_path),
                "contract": str(self.contract_path),
                "selected": str(self.selected_path),
            },
        )
        return self._model

    def info(self) -> dict[str, Any]:
        model = self.load()
        return {
            "model": model.metadata.model_dump(),
            "feature_contract": model.contract.model_dump(),
            "threshold": model.threshold,
            "feature_order": list(model.feature_order),
            "feature_count": len(model.feature_order),
            "missing_policy": {
                "max_missing_fraction_for_partial": MAX_MISSING_FRACTION,
                "imputation": "training median, always reported in missing_features",
                "insufficient_evidence": "status=unknown, label=unknown",
            },
            "explainer": model._ensure_explainer(),
            "artifacts": model.artifacts,
        }

    def _coerce(self, name: str, value: Any) -> float:
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, (int, float)):
            number = float(value)
        elif isinstance(value, str):
            try:
                number = float(value.strip())
            except (TypeError, ValueError) as exc:
                raise InvalidFeatureValueError(f"{name} must be numeric, got {value!r}") from exc
        else:
            raise InvalidFeatureValueError(f"{name} must be numeric, got {type(value).__name__}")
        if not math.isfinite(number):
            raise InvalidFeatureValueError(f"{name} must be finite, got {value!r}")
        return number

    def predict(self, request: PredictRequest, explain: bool | None = None) -> PredictResponse:
        model = self.load()
        supplied = request.features
        unknown = sorted(set(supplied) - set(model.feature_order))
        if unknown:
            raise UnknownFeatureError(f"unknown features: {unknown}")

        vector: dict[str, float] = {}
        missing: list[str] = []
        for name in model.feature_order:
            if name in supplied:
                vector[name] = self._coerce(name, supplied[name])
            else:
                vector[name] = math.nan
                missing.append(name)

        row = np.array([[vector[name] for name in model.feature_order]], dtype=float)
        probability = float(model.pipeline.predict_proba(row)[0, 1])

        missing_fraction = len(missing) / len(model.feature_order)
        if missing_fraction == 0:
            status = "ok"
        elif missing_fraction <= MAX_MISSING_FRACTION:
            status = "partial"
        else:
            status = "unknown"

        if status == "unknown":
            label = "unknown"
        else:
            label = "phishing" if probability >= model.threshold else "legitimate"

        want_explanation = request.explain if explain is None else explain
        contributions = model.contributions(vector) if want_explanation else []

        return PredictResponse(
            label=label,
            probability_phishing=probability,
            contributions=contributions,
            missing_features=missing,
            status=status,
            model=model.metadata,
        )
