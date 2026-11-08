from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from training.config import LABEL_COLUMN, PHISHING_LABEL, RANDOM_STATE
from training.dataset import (
    DatasetError,
    audit_dataset,
    build_splits,
    load_dataset,
    registrable_domain,
)


def test_registrable_domain_groups_subdomains_and_keeps_ip_literals() -> None:
    assert registrable_domain("www.southbankmosaics.com") == "southbankmosaics.com"
    assert registrable_domain("docs.google.com") == "google.com"
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("1.2.3.4") == "1.2.3.4"


def test_load_dataset_rejects_missing_columns(tmp_path: Path) -> None:
    path = tmp_path / "broken.csv"
    path.write_text("URL,label\nhttps://example.com,1\n", encoding="utf-8")
    with pytest.raises(DatasetError, match="missing required columns"):
        load_dataset(path)


def test_load_dataset_strips_the_utf8_bom(tmp_path: Path, synthetic_frame: pd.DataFrame) -> None:
    path = tmp_path / "bom.csv"
    path.write_text("\ufeff" + synthetic_frame.to_csv(index=False), encoding="utf-8")
    frame = load_dataset(path)
    assert "FILENAME" in frame.columns
    assert "\ufeffFILENAME" not in frame.columns


def test_load_dataset_rejects_unknown_labels(
    tmp_path: Path, synthetic_frame: pd.DataFrame
) -> None:
    broken = synthetic_frame.copy()
    broken.loc[0, LABEL_COLUMN] = 7
    path = tmp_path / "bad_label.csv"
    broken.to_csv(path, index=False)
    with pytest.raises(DatasetError, match="unexpected label values"):
        load_dataset(path)


def test_audit_measures_duplicates_and_ambiguous_domains(synthetic_frame: pd.DataFrame) -> None:
    frame = synthetic_frame.copy()
    duplicate = frame.iloc[[0]].copy()
    frame = pd.concat([frame, duplicate], ignore_index=True)

    # One registrable domain now carries both labels.
    conflicting = frame.iloc[[1]].copy()
    conflicting["URL"] = "https://site0.com/other"
    conflicting["Domain"] = "www.site0.com"
    conflicting[LABEL_COLUMN] = 1
    frame = pd.concat([frame, conflicting], ignore_index=True)

    audit = audit_dataset(frame)
    assert audit["rows"] == len(frame)
    assert audit["missing_values"] == 0
    assert audit["duplicate_urls"] == 1
    assert audit["duplicate_urls_with_conflicting_labels"] == 0
    assert audit["domains_with_both_labels"] == 1
    assert audit["class_counts"]["0_phishing"] > 0
    assert audit["class_counts"]["1_legitimate"] > 0


def test_label_map_is_never_inverted() -> None:
    from phishguard_contracts import LABEL_MAP

    assert LABEL_MAP["0"] == "phishing"
    assert LABEL_MAP["1"] == "legitimate"
    assert PHISHING_LABEL == 0


def test_duplicate_urls_are_removed_before_splitting(synthetic_frame: pd.DataFrame) -> None:
    frame = pd.concat([synthetic_frame, synthetic_frame.iloc[[0]]], ignore_index=True)
    splits = build_splits(frame)
    seen = pd.concat(
        [splits.train.frame, splits.validation.frame, splits.test.frame], ignore_index=True
    )
    assert len(seen) == len(synthetic_frame)
    assert not seen.duplicated(subset=["URL"]).any()
    assert splits.summary["duplicate_url_rows_removed"] == 1


def test_domains_carrying_both_labels_are_dropped(synthetic_frame: pd.DataFrame) -> None:
    frame = synthetic_frame.copy()
    conflicting = frame.iloc[[1]].copy()
    conflicting["URL"] = "https://site0.com/other"
    conflicting["Domain"] = "www.site0.com"
    conflicting[LABEL_COLUMN] = 1
    frame = pd.concat([frame, conflicting], ignore_index=True)

    splits = build_splits(frame)
    assert splits.summary["ambiguous_domains_removed"] == 1
    assert splits.summary["ambiguous_domain_rows_removed"] == 2
    seen = pd.concat(
        [splits.train.frame, splits.validation.frame, splits.test.frame], ignore_index=True
    )
    assert "site0.com" not in seen["Domain"].map(registrable_domain).unique()


def test_splits_do_not_share_a_registrable_domain(synthetic_frame: pd.DataFrame) -> None:
    splits = build_splits(synthetic_frame)
    train_groups = set(splits.train.frame["Domain"].map(registrable_domain))
    val_groups = set(splits.validation.frame["Domain"].map(registrable_domain))
    test_groups = set(splits.test.frame["Domain"].map(registrable_domain))
    assert not train_groups & val_groups
    assert not train_groups & test_groups
    assert not val_groups & test_groups


def test_splits_are_deterministic_for_a_fixed_seed(synthetic_frame: pd.DataFrame) -> None:
    first = build_splits(synthetic_frame, seed=RANDOM_STATE)
    second = build_splits(synthetic_frame, seed=RANDOM_STATE)
    assert first.summary["assignment_sha256"] == second.summary["assignment_sha256"]
    pd.testing.assert_frame_equal(first.train.frame, second.train.frame)
    pd.testing.assert_frame_equal(first.test.frame, second.test.frame)


def test_a_different_seed_changes_the_assignment(synthetic_frame: pd.DataFrame) -> None:
    first = build_splits(synthetic_frame, seed=42)
    second = build_splits(synthetic_frame, seed=43)
    assert first.summary["assignment_sha256"] != second.summary["assignment_sha256"]


def test_split_fractions_are_close_and_both_classes_are_present(
    synthetic_frame: pd.DataFrame,
) -> None:
    splits = build_splits(synthetic_frame)
    total = sum(len(split.frame) for split in (splits.train, splits.validation, splits.test))
    assert total == len(synthetic_frame)
    assert 0.60 <= len(splits.train.frame) / total <= 0.80
    assert 0.08 <= len(splits.validation.frame) / total <= 0.22
    assert 0.08 <= len(splits.test.frame) / total <= 0.22
    for split in (splits.train, splits.validation, splits.test):
        assert set(split.frame[LABEL_COLUMN].unique()) == {0, 1}
