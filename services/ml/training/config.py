"""Training configuration. Single source of truth for paths, seeds and splits."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from phishguard_contracts import FEATURE_SCHEMA_VERSION

# services/ml/training/config.py -> services/ml
SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_ROOT.parents[1]
DEFAULT_CSV = REPO_ROOT / "PhiUSIIL_Phishing_URL_Dataset.csv"
ARTIFACTS_DIR = SERVICE_ROOT / "artifacts"

#: Model artifact version. Bump when a retrain changes behavior.
MODEL_VERSION = "1.0.0"

#: Feature schema version, shared with packages/contracts.
FEATURE_CONTRACT_VERSION = FEATURE_SCHEMA_VERSION

#: Fixed seed for every stochastic step. Changing this invalidates the artifacts.
RANDOM_STATE = 42

#: 70 / 15 / 15 split fractions, applied to groups (registrable domains).
TRAIN_FRACTION = 0.70
VAL_FRACTION = 0.15
TEST_FRACTION = 0.15

LABEL_COLUMN = "label"
PHISHING_LABEL = 0
LEGITIMATE_LABEL = 1

#: Never used as model input.
IDENTIFIER_COLUMNS = ("FILENAME", "URL", "Domain", "TLD", "Title")

#: Dataset-derived statistics that encode class information. Excluded from every
#: model so reported performance cannot be inflated by corpus leakage.
LEAKAGE_PRONE_COLUMNS = (
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
)

#: Strictly derivable from the URL string, with no network and no corpus lookup.
URL_ONLY_FEATURES = (
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
)

#: All 50 numeric dataset columns (everything except FILENAME/URL/Domain/TLD/Title/label).
#: Declared explicitly so the feature sets are stable even if the CSV column order
#: changes, and so a renamed column fails loudly instead of being skipped.
ALL_NUMERIC_FEATURES = (
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "LineOfCode",
    "LargestLineLength",
    "HasTitle",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasExternalFormSubmit",
    "HasSocialNet",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef",
)


@dataclass(frozen=True)
class FeatureSet:
    name: str
    columns: tuple[str, ...]
    description: str


def feature_sets(all_numeric: list[str]) -> list[FeatureSet]:
    """Return the two evaluated feature sets.

    - ``full_offline``: every numeric feature except leakage-prone ones. Requires
      controlled page inspection to serve, so it is research/reporting only.
    - ``live``: URL-only features. This is the served model.
    """
    full = tuple(
        c for c in all_numeric if c not in LEAKAGE_PRONE_COLUMNS
    )
    return [
        FeatureSet(
            name="full_offline",
            columns=full,
            description=(
                "All numeric features minus identifiers and leakage-prone "
                "dataset statistics. Needs controlled page inspection; not served."
            ),
        ),
        FeatureSet(
            name="live",
            columns=URL_ONLY_FEATURES,
            description=(
                "URL-only lexical features. No network, no corpus lookups; "
                "this is the model the inference service serves."
            ),
        ),
    ]


#: Stable, ordered feature sets used by training and by the contract builder.
FEATURE_SETS = feature_sets(list(ALL_NUMERIC_FEATURES))
