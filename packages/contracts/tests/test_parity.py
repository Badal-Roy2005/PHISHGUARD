"""Contract parity: every fixture must satisfy BOTH the JSON Schema and the
Pydantic model. If the two drift apart, this test fails.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from phishguard_contracts import SCHEMA_MODELS, FeatureContract, RiskWeights, ScanResult

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = PACKAGE_ROOT / "schemas"
FIXTURE_DIR = PACKAGE_ROOT / "fixtures"

BASE = "https://phishguard.local/schemas"


def _registry() -> Registry:
    resources = []
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        contents = json.loads(path.read_text(encoding="utf-8"))
        resources.append(
            (contents["$id"], Resource.from_contents(contents, default_specification=DRAFT202012))
        )
    return Registry().with_resources(resources)


REGISTRY = _registry()


def _schema(ref: str) -> dict:
    return {"$ref": f"{BASE}/{ref}"}


#: (fixture file, schema ref, pydantic model key)
CASES = [
    ("scan-request.json", "scan-request.schema.json", "scan-request"),
    ("scan-accepted.json", "scan-accepted.schema.json", "scan-accepted"),
    ("scan-result.queued.json", "scan-result.schema.json", "scan-result"),
    ("scan-result.complete.json", "scan-result.schema.json", "scan-result"),
    ("scan-result.partial.json", "scan-result.schema.json", "scan-result"),
    ("error.json", "error.schema.json", "error"),
    ("ml-predict-request.json", "ml.schema.json#/$defs/PredictRequest", "ml-predict-request"),
    (
        "ml-predict-response.json",
        "ml.schema.json#/$defs/PredictResponse",
        "ml-predict-response",
    ),
    (
        "report-create-request.json",
        "report.schema.json#/$defs/CreateReportRequest",
        "report-create-request",
    ),
    ("report.json", "report.schema.json#/$defs/Report", "report"),
]


@pytest.mark.parametrize(("fixture", "schema_ref", "model_key"), CASES)
def test_fixture_matches_json_schema_and_model(
    fixture: str, schema_ref: str, model_key: str
) -> None:
    payload = json.loads((FIXTURE_DIR / fixture).read_text(encoding="utf-8"))

    validator = Draft202012Validator(_schema(schema_ref), registry=REGISTRY)
    schema_errors = sorted(validator.iter_errors(payload), key=lambda e: e.path)
    assert not schema_errors, [f"{list(e.path)}: {e.message}" for e in schema_errors]

    model = SCHEMA_MODELS[model_key].model_validate(payload)
    # Keep explicit nulls: the contract requires risk/explanation to be present.
    round_tripped = json.loads(model.model_dump_json())
    Draft202012Validator(_schema(schema_ref), registry=REGISTRY).validate(round_tripped)


def test_schema_files_are_valid_json_schema() -> None:
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        contents = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(contents)


def test_partial_scan_keeps_all_six_engines() -> None:
    payload = json.loads((FIXTURE_DIR / "scan-result.partial.json").read_text(encoding="utf-8"))
    result = ScanResult.model_validate(payload)
    assert set(result.engines.model_dump().keys()) == {
        "ml", "url", "tls", "http", "intel", "community"
    }
    # A failed engine is explicit, never silently absent.
    assert result.engines.ml.status == "unknown"
    assert result.engines.intel.status == "skipped"


def test_label_mapping_is_enforced() -> None:
    contract = {
        "version": "1",
        "model_version": "1.0.0",
        "label_map": {"0": "legitimate", "1": "phishing"},
        "features": [
            {
                "name": "URLLength",
                "dataset_column": "URLLength",
                "dtype": "integer",
                "required": True,
                "live_source": "url",
                "default_policy": "reject",
            }
        ],
    }
    with pytest.raises(ValueError, match="label_map"):
        FeatureContract.model_validate(contract)


def test_inverted_label_map_is_rejected_by_schema() -> None:
    validator = Draft202012Validator(
        _schema("common.schema.json#/$defs/FeatureContract"), registry=REGISTRY
    )
    bad = {
        "version": "1",
        "model_version": "1.0.0",
        "label_map": {"0": "legitimate", "1": "phishing"},
        "features": [
            {
                "name": "x",
                "dataset_column": "x",
                "dtype": "integer",
                "required": True,
                "live_source": "url",
                "default_policy": "reject",
            }
        ],
    }
    assert not validator.is_valid(bad)


def test_extra_fields_are_rejected() -> None:
    payload = json.loads((FIXTURE_DIR / "scan-request.json").read_text(encoding="utf-8"))
    payload["surprise"] = True
    assert not Draft202012Validator(
        _schema("scan-request.schema.json"), registry=REGISTRY
    ).is_valid(payload)
    with pytest.raises(ValueError):
        SCHEMA_MODELS["scan-request"].model_validate(payload)


def test_terminal_scan_requires_assessment() -> None:
    payload = json.loads((FIXTURE_DIR / "scan-result.queued.json").read_text(encoding="utf-8"))
    payload["status"] = "complete"
    with pytest.raises(ValueError, match="risk and explanation"):
        ScanResult.model_validate(payload)


def test_risk_weights_must_sum_to_100() -> None:
    with pytest.raises(ValueError, match="sum to 100"):
        RiskWeights(intel=35, url=15, brand=15, redirect=10, tls=15, http=9)


def test_guarded_risk_band_is_valid() -> None:
    payload = json.loads((FIXTURE_DIR / "scan-result.partial.json").read_text(encoding="utf-8"))
    payload["risk"]["band"] = "guarded"
    assert Draft202012Validator(
        _schema("scan-result.schema.json"), registry=REGISTRY
    ).is_valid(payload)
    ScanResult.model_validate(payload)
