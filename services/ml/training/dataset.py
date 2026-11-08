"""Dataset loading, auditing and leakage-safe splitting.

The PhiUSIIL dataset has two properties that make a naive row split invalid:

1. 425 URLs appear more than once (identical rows, no conflicting labels).
2. Rows are clustered by domain: 5,526 domains contribute more than one row and
   one domain contributes 1,197 rows. A random row split therefore puts the same
   site in train and test, which inflates every metric.

Splits are grouped by *registrable domain* (``tldextract``, offline snapshot) so a
domain is present in exactly one split. Domains that carry both labels are dropped:
there is no honest way to place them without leaking the label across splits.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import tldextract

from .config import (
    LABEL_COLUMN,
    LEGITIMATE_LABEL,
    PHISHING_LABEL,
    RANDOM_STATE,
    TEST_FRACTION,
    TRAIN_FRACTION,
    VAL_FRACTION,
)

#: Offline suffix resolution: no HTTP call at import or training time.
_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


class DatasetError(ValueError):
    """Raised when the dataset does not match the contract we train against."""


@dataclass(frozen=True)
class Split:
    name: str
    frame: pd.DataFrame

    @property
    def labels(self) -> pd.Series:
        return self.frame[LABEL_COLUMN]


@dataclass(frozen=True)
class DatasetSplits:
    train: Split
    validation: Split
    test: Split
    summary: dict[str, Any]


def registrable_domain(host: str) -> str:
    """Return ``example.co.uk`` for ``a.b.example.co.uk``; IP literals unchanged."""
    value = str(host).strip().lower().rstrip(".")
    if not value:
        return value
    extracted = _TLD(value)
    if extracted.suffix and extracted.domain:
        return f"{extracted.domain}.{extracted.suffix}"
    return value


def load_dataset(path: str | Path) -> pd.DataFrame:
    """Load and structurally validate the PhiUSIIL CSV.

    ``utf-8-sig`` is required: the official file starts with a BOM, which would
    otherwise turn the first column into ``\\ufeffFILENAME``.
    """
    csv_path = Path(path)
    if not csv_path.exists():
        raise DatasetError(f"dataset not found: {csv_path}")

    frame = pd.read_csv(csv_path, encoding="utf-8-sig")
    required = {"URL", "Domain", LABEL_COLUMN}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise DatasetError(f"dataset is missing required columns: {missing}")
    if frame.empty:
        raise DatasetError("dataset is empty")

    labels = set(frame[LABEL_COLUMN].unique().tolist())
    if not labels <= {PHISHING_LABEL, LEGITIMATE_LABEL}:
        raise DatasetError(f"unexpected label values: {sorted(labels)}")

    return frame


def _group_table(frame: pd.DataFrame) -> pd.DataFrame:
    groups = pd.DataFrame(
        {
            "group": frame["Domain"].map(registrable_domain),
            LABEL_COLUMN: frame[LABEL_COLUMN].astype(int),
            "row_id": np.arange(len(frame), dtype=np.int64),
        }
    )
    return groups


def audit_dataset(frame: pd.DataFrame) -> dict[str, Any]:
    """Describe the raw dataset before any row is removed.

    Everything here is measured, never assumed. The audit is written to
    ``artifacts/dataset_audit.json`` by the training CLI.
    """
    groups = _group_table(frame)
    per_group = groups.groupby("group")[LABEL_COLUMN].agg(["nunique", "size"])
    duplicates_url = frame[frame.duplicated(subset=["URL"], keep=False)]
    duplicate_labels = duplicates_url.groupby("URL")[LABEL_COLUMN].nunique()

    numeric = [
        column
        for column in frame.columns
        if pd.api.types.is_numeric_dtype(frame[column]) and column != LABEL_COLUMN
    ]
    non_numeric = [column for column in frame.columns if column not in numeric]

    return {
        "rows": int(len(frame)),
        "columns": int(frame.shape[1]),
        "numeric_columns": len(numeric),
        "non_numeric_columns": non_numeric,
        "missing_values": int(frame.isna().sum().sum()),
        "missing_by_column": {
            column: int(count)
            for column, count in frame.isna().sum().items()
            if int(count) > 0
        },
        "exact_duplicate_rows": int(frame.duplicated().sum()),
        "duplicate_url_rows": int(len(duplicates_url)),
        "duplicate_urls": int(duplicates_url["URL"].nunique()),
        "duplicate_urls_with_conflicting_labels": int((duplicate_labels > 1).sum()),
        "class_counts": {
            "0_phishing": int((frame[LABEL_COLUMN] == PHISHING_LABEL).sum()),
            "1_legitimate": int((frame[LABEL_COLUMN] == LEGITIMATE_LABEL).sum()),
        },
        "registrable_domains": int(per_group.shape[0]),
        "domains_with_multiple_rows": int((per_group["size"] > 1).sum()),
        "max_rows_per_domain": int(per_group["size"].max()),
        "domains_with_both_labels": int((per_group["nunique"] > 1).sum()),
        "rows_in_ambiguous_domains": int(
            groups["group"].isin(per_group[per_group["nunique"] > 1].index).sum()
        ),
    }


def _assign_groups(
    groups: pd.DataFrame, seed: int
) -> tuple[pd.Series, dict[str, list[str]]]:
    """Assign whole domains to train/validation/test, stratified by label.

    Deterministic given ``seed``: groups are sorted, shuffled per class, then
    consumed until the row budget for each split is met. This keeps both classes
    represented in every split while never splitting a registrable domain.
    """
    rng = np.random.default_rng(seed)
    assignment: dict[str, str] = {}

    for label_value in (PHISHING_LABEL, LEGITIMATE_LABEL):
        subset = groups[groups[LABEL_COLUMN] == label_value]
        sizes = subset.groupby("group").size()
        names = np.array(sorted(sizes.index.tolist()), dtype=object)
        rng.shuffle(names)
        total = int(sizes.sum())
        train_budget = TRAIN_FRACTION * total
        val_budget = (TRAIN_FRACTION + VAL_FRACTION) * total

        cumulative = 0
        for name in names:
            row_count = int(sizes.loc[name])
            if cumulative < train_budget:
                split_name = "train"
            elif cumulative < val_budget:
                split_name = "validation"
            else:
                split_name = "test"
            assignment[str(name)] = split_name
            cumulative += row_count

    mapping = groups["group"].map(assignment)
    if mapping.isna().any():
        unassigned = sorted(groups.loc[mapping.isna(), "group"].unique().tolist())
        raise DatasetError(f"unassigned domain groups: {unassigned[:5]}")

    by_split: dict[str, list[str]] = {"train": [], "validation": [], "test": []}
    for group, split_name in sorted(assignment.items()):
        by_split[split_name].append(group)

    return mapping, by_split


def _fingerprint(by_split: dict[str, list[str]]) -> str:
    payload = json.dumps(by_split, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_splits(frame: pd.DataFrame, seed: int = RANDOM_STATE) -> DatasetSplits:
    """Deduplicate, drop ambiguous domains, then split by registrable domain."""
    working = frame.drop_duplicates(subset=["URL"], keep="first").copy()
    working = working.reset_index(drop=True)

    working["_group"] = working["Domain"].map(registrable_domain)
    per_group = working.groupby("_group")[LABEL_COLUMN].nunique()
    ambiguous_groups = set(per_group[per_group > 1].index)
    ambiguous_rows = int(working["_group"].isin(ambiguous_groups).sum())
    working = working[~working["_group"].isin(ambiguous_groups)].copy()
    working = working.reset_index(drop=True)

    assignment, by_split = _assign_groups(
        working.rename(columns={"_group": "group"}).assign(
            **{LABEL_COLUMN: working[LABEL_COLUMN].astype(int)}
        ),
        seed,
    )
    working["_split"] = assignment

    train = working[working["_split"] == "train"].drop(columns=["_split"]).reset_index(drop=True)
    validation = (
        working[working["_split"] == "validation"].drop(columns=["_split"]).reset_index(drop=True)
    )
    test = working[working["_split"] == "test"].drop(columns=["_split"]).reset_index(drop=True)

    for split_name, split_frame in (
        ("train", train),
        ("validation", validation),
        ("test", test),
    ):
        observed = set(split_frame[LABEL_COLUMN].unique().tolist())
        if not observed <= {PHISHING_LABEL, LEGITIMATE_LABEL} or len(split_frame) == 0:
            raise DatasetError(f"{split_name} split is empty or has unexpected labels")

    train_groups = set(train["_group"])
    val_groups = set(validation["_group"])
    test_groups = set(test["_group"])
    assert not (train_groups & val_groups), "train/validation domain leakage"
    assert not (train_groups & test_groups), "train/test domain leakage"
    assert not (val_groups & test_groups), "validation/test domain leakage"

    def describe(split_frame: pd.DataFrame) -> dict[str, Any]:
        return {
            "rows": int(len(split_frame)),
            "domains": int(split_frame["_group"].nunique()),
            "class_counts": {
                "0_phishing": int((split_frame[LABEL_COLUMN] == PHISHING_LABEL).sum()),
                "1_legitimate": int((split_frame[LABEL_COLUMN] == LEGITIMATE_LABEL).sum()),
            },
        }

    summary: dict[str, Any] = {
        "seed": seed,
        "fractions": {
            "train": TRAIN_FRACTION,
            "validation": VAL_FRACTION,
            "test": TEST_FRACTION,
        },
        "input_rows": int(len(frame)),
        "rows_after_url_deduplication": int(len(frame.drop_duplicates(subset=["URL"]))),
        "duplicate_url_rows_removed": int(len(frame) - len(frame.drop_duplicates(subset=["URL"]))),
        "ambiguous_domains_removed": len(ambiguous_groups),
        "ambiguous_domain_rows_removed": ambiguous_rows,
        "assignment_sha256": _fingerprint(by_split),
        "assignment_domain_counts": {
            split_name: len(groups) for split_name, groups in by_split.items()
        },
        "splits": {
            "train": describe(train),
            "validation": describe(validation),
            "test": describe(test),
        },
        "grouping_key": "registrable_domain (tldextract, offline snapshot)",
    }
    return DatasetSplits(
        train=Split("train", train.drop(columns=["_group"])),
        validation=Split("validation", validation.drop(columns=["_group"])),
        test=Split("test", test.drop(columns=["_group"])),
        summary=summary,
    )


def write_json(path: str | Path, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
