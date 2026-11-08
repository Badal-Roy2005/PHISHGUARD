from __future__ import annotations

from typing import Any

import pytest
from phishguard_contracts import FEATURE_SCHEMA_VERSION, FeatureContract

from training.config import (
    ALL_NUMERIC_FEATURES,
    FEATURE_CONTRACT_VERSION,
    LEAKAGE_PRONE_COLUMNS,
    URL_ONLY_FEATURES,
    feature_sets,
)
from training.features import build_feature_contract, contract_entries


def test_manifest_documents_every_dataset_feature(manifest: dict[str, Any]) -> None:
    names = [feature["name"] for feature in manifest["features"]]
    assert len(names) == 53
    assert len(set(names)) == 53
    # Identifiers are documented as excluded, not as features.
    assert set(manifest["identifiers_not_model_inputs"]) == {"FILENAME", "URL", "label"}


def test_manifest_marks_url_only_and_inspection_features(manifest: dict[str, Any]) -> None:
    by_name = {feature["name"]: feature for feature in manifest["features"]}
    for name in URL_ONLY_FEATURES:
        assert by_name[name]["available_from_url_only"] is True
        assert by_name[name]["requires_controlled_webpage_inspection"] is False
    for name in ("HasPasswordField", "HasTitle", "NoOfiFrame", "LineOfCode"):
        assert by_name[name]["available_from_url_only"] is False
        assert by_name[name]["requires_controlled_webpage_inspection"] is True
    # Domain and TLD are derivable from a URL too, but they are identifiers.
    url_only_names = {
        feature["name"] for feature in manifest["features"] if feature["available_from_url_only"]
    }
    assert url_only_names == set(URL_ONLY_FEATURES) | {"Domain", "TLD"}
    assert manifest["counts"]["url_only"] == len(URL_ONLY_FEATURES) + 2
    assert manifest["counts"]["requires_inspection"] >= 25


def test_feature_sets_exclude_leakage_and_identifiers() -> None:
    sets = {entry.name: entry for entry in feature_sets(list(ALL_NUMERIC_FEATURES))}
    assert set(sets) == {"full_offline", "live"}
    for leakage in LEAKAGE_PRONE_COLUMNS:
        assert leakage not in sets["full_offline"].columns
        assert leakage not in sets["live"].columns
    for identifier in ("FILENAME", "URL", "Domain", "TLD", "Title", "label"):
        assert identifier not in sets["full_offline"].columns
        assert identifier not in sets["live"].columns
    assert sets["live"].columns == URL_ONLY_FEATURES
    assert len(sets["live"].columns) == 18
    assert len(sets["full_offline"].columns) == len(ALL_NUMERIC_FEATURES) - len(
        LEAKAGE_PRONE_COLUMNS
    )


def test_live_contract_has_only_url_features_in_order(manifest: dict[str, Any]) -> None:
    contract = build_feature_contract(
        manifest,
        URL_ONLY_FEATURES,
        version=FEATURE_CONTRACT_VERSION,
        model_version="1.0.0",
    )
    parsed = FeatureContract.model_validate(contract)
    assert [feature.name for feature in parsed.features] == list(URL_ONLY_FEATURES)
    assert all(feature.live_source == "url" for feature in parsed.features)
    assert all(feature.required is True for feature in parsed.features)
    assert all(feature.default_policy == "unknown" for feature in parsed.features)


def test_contract_refuses_a_page_content_feature(manifest: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="cannot be served from a URL alone"):
        contract_entries(manifest, ("URLLength", "HasPasswordField"))


def test_contract_refuses_an_undocumented_feature(manifest: dict[str, Any]) -> None:
    with pytest.raises(KeyError, match="not documented"):
        contract_entries(manifest, ("NotAFeature",))


def test_feature_schema_version_is_pinned() -> None:
    assert FEATURE_SCHEMA_VERSION == "2"
    assert FEATURE_CONTRACT_VERSION == FEATURE_SCHEMA_VERSION
