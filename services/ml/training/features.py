"""PhiUSIIL feature manifest.

Every one of the 53 dataset features is documented here: what it is, what input it
needs, whether it can be computed from a URL alone, and whether serving it requires
controlled page inspection.

Generated into ``artifacts/feature_manifest.json`` by ``training.train``.
"""

from __future__ import annotations

from typing import Any

# name -> (dtype, definition, required_input, url_only, needs_inspection, leakage_risk)
_RAW: dict[str, tuple[str, str, str, bool, bool, str]] = {
    # --- identifiers / non-numeric -------------------------------------------------
    "Domain": ("string", "Hostname extracted from the URL.", "URL", True, False, "identifier"),
    "TLD": ("string", "Top-level domain of the URL.", "URL", True, False, "identifier"),
    "Title": ("string", "HTML <title> of the page.", "page", False, True, "none"),
    # --- URL-only lexical signals --------------------------------------------------
    "URLLength": ("integer", "Number of characters in the URL.", "URL", True, False, "none"),
    "DomainLength": (
        "integer",
        "Number of characters in the domain.",
        "URL",
        True,
        False,
        "none",
    ),
    "IsDomainIP": ("boolean", "1 when the domain is an IP literal.", "URL", True, False, "none"),
    "TLDLength": ("integer", "Number of characters in the TLD.", "URL", True, False, "none"),
    "NoOfSubDomain": ("integer", "Count of subdomain labels.", "URL", True, False, "none"),
    "HasObfuscation": ("boolean", "1 when the URL uses obfuscation.", "URL", True, False, "none"),
    "NoOfObfuscatedChar": (
        "integer",
        "Count of obfuscated characters.",
        "URL",
        True,
        False,
        "none",
    ),
    "ObfuscationRatio": (
        "number",
        "Obfuscated characters divided by URL length.",
        "URL",
        True,
        False,
        "none",
    ),
    "NoOfLettersInURL": ("integer", "Letter count in the URL.", "URL", True, False, "none"),
    "LetterRatioInURL": ("number", "Letters divided by URL length.", "URL", True, False, "none"),
    "NoOfDegitsInURL": (
        "integer",
        "Digit count in the URL (dataset spelling).",
        "URL",
        True,
        False,
        "none",
    ),
    "DegitRatioInURL": (
        "number",
        "Digits divided by URL length (dataset spelling).",
        "URL",
        True,
        False,
        "none",
    ),
    "NoOfEqualsInURL": ("integer", "Count of '=' characters.", "URL", True, False, "none"),
    "NoOfQMarkInURL": ("integer", "Count of '?' characters.", "URL", True, False, "none"),
    "NoOfAmpersandInURL": ("integer", "Count of '&' characters.", "URL", True, False, "none"),
    "NoOfOtherSpecialCharsInURL": (
        "integer",
        "Count of other special characters.",
        "URL",
        True,
        False,
        "none",
    ),
    "SpacialCharRatioInURL": (
        "number",
        "Special characters divided by URL length (dataset spelling).",
        "URL",
        True,
        False,
        "none",
    ),
    "IsHTTPS": ("boolean", "1 when the URL scheme is https.", "URL", True, False, "none"),
    # --- corpus-derived statistics (leakage) ---------------------------------------
    "URLSimilarityIndex": (
        "number",
        "Similarity of the URL to a legitimate-URL corpus, 0-100.",
        "corpus",
        False,
        False,
        "high",
    ),
    "CharContinuationRate": (
        "number",
        "Rate of repeated character sequences in the URL.",
        "corpus",
        False,
        False,
        "medium",
    ),
    "TLDLegitimateProb": (
        "number",
        "P(legitimate | TLD) statistic computed over a corpus.",
        "corpus",
        False,
        False,
        "high",
    ),
    "URLCharProb": (
        "number",
        "Character-probability score of the URL from a corpus model.",
        "corpus",
        False,
        False,
        "high",
    ),
    # --- page-content signals (require controlled inspection) ----------------------
    "LineOfCode": ("integer", "Lines in the page source.", "page", False, True, "none"),
    "LargestLineLength": (
        "integer",
        "Length of the longest source line.",
        "page",
        False,
        True,
        "none",
    ),
    "HasTitle": ("boolean", "1 when the page has a <title>.", "page", False, True, "none"),
    "DomainTitleMatchScore": (
        "number",
        "Match score between domain and page title.",
        "page",
        False,
        True,
        "none",
    ),
    "URLTitleMatchScore": (
        "number",
        "Match score between URL and page title.",
        "page",
        False,
        True,
        "none",
    ),
    "HasFavicon": (
        "boolean",
        "1 when the page declares a favicon.",
        "page",
        False,
        True,
        "none",
    ),
    "Robots": ("boolean", "1 when a robots directive is present.", "page", False, True, "none"),
    "IsResponsive": ("boolean", "1 when the page is responsive.", "page", False, True, "none"),
    "NoOfURLRedirect": (
        "integer",
        "Number of redirects observed while loading.",
        "page",
        False,
        True,
        "none",
    ),
    "NoOfSelfRedirect": ("integer", "Number of self-redirects.", "page", False, True, "none"),
    "HasDescription": (
        "boolean",
        "1 when a meta description exists.",
        "page",
        False,
        True,
        "none",
    ),
    "NoOfPopup": ("integer", "Count of popup/alert calls.", "page", False, True, "none"),
    "NoOfiFrame": ("integer", "Count of iframes.", "page", False, True, "none"),
    "HasExternalFormSubmit": (
        "boolean",
        "1 when a form posts to another origin.",
        "page",
        False,
        True,
        "none",
    ),
    "HasSocialNet": (
        "boolean",
        "1 when social-network links are present.",
        "page",
        False,
        True,
        "none",
    ),
    "HasSubmitButton": (
        "boolean",
        "1 when a submit button is present.",
        "page",
        False,
        True,
        "none",
    ),
    "HasHiddenFields": (
        "boolean",
        "1 when hidden form fields are present.",
        "page",
        False,
        True,
        "none",
    ),
    "HasPasswordField": (
        "boolean",
        "1 when a password input is present.",
        "page",
        False,
        True,
        "none",
    ),
    "Bank": ("boolean", "1 when banking keywords appear.", "page", False, True, "none"),
    "Pay": ("boolean", "1 when payment keywords appear.", "page", False, True, "none"),
    "Crypto": ("boolean", "1 when cryptocurrency keywords appear.", "page", False, True, "none"),
    "HasCopyrightInfo": (
        "boolean",
        "1 when a copyright notice is present.",
        "page",
        False,
        True,
        "none",
    ),
    "NoOfImage": ("integer", "Count of images.", "page", False, True, "none"),
    "NoOfCSS": ("integer", "Count of CSS references.", "page", False, True, "none"),
    "NoOfJS": ("integer", "Count of JavaScript references.", "page", False, True, "none"),
    "NoOfSelfRef": ("integer", "Count of same-origin references.", "page", False, True, "none"),
    "NoOfEmptyRef": ("integer", "Count of empty references.", "page", False, True, "none"),
    "NoOfExternalRef": (
        "integer",
        "Count of external references.",
        "page",
        False,
        True,
        "none",
    ),
}


def build_manifest() -> dict[str, Any]:
    features = []
    for name, (dtype, definition, required_input, url_only, needs_inspection, leak) in _RAW.items():
        features.append(
            {
                "name": name,
                "dtype": dtype,
                "definition": definition,
                "required_input": required_input,
                "available_from_url_only": url_only,
                "requires_controlled_webpage_inspection": needs_inspection,
                "leakage_risk": leak,
                "model_input": leak not in {"identifier", "high"},
            }
        )
    return {
        "dataset": "PhiUSIIL Phishing URL (Website) Dataset",
        "source": "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+website+dataset",
        "label_map": {"0": "phishing", "1": "legitimate"},
        "identifiers_not_model_inputs": ["FILENAME", "URL", "label"],
        "features": features,
        "counts": {
            "total_features": len(features),
            "url_only": sum(1 for f in features if f["available_from_url_only"]),
            "requires_inspection": sum(
                1 for f in features if f["requires_controlled_webpage_inspection"]
            ),
            "leakage_prone": sum(1 for f in features if f["leakage_risk"] in {"high", "medium"}),
        },
    }


def contract_entries(manifest: dict[str, Any], columns: tuple[str, ...]) -> list[dict[str, Any]]:
    """Feature-contract entries for one exact, ordered feature set."""
    by_name = {feature["name"]: feature for feature in manifest["features"]}
    entries: list[dict[str, Any]] = []
    for name in columns:
        if name not in by_name:
            raise KeyError(f"feature {name!r} is not documented in the manifest")
        source = by_name[name]
        if not source["available_from_url_only"]:
            raise ValueError(f"feature {name!r} cannot be served from a URL alone")
        entries.append(
            {
                "name": name,
                "dataset_column": name,
                "dtype": source["dtype"],
                "required": True,
                "live_source": "url",
                "default_policy": "unknown",
                "notes": source["definition"][:512],
            }
        )
    return entries


def build_feature_contract(
    manifest: dict[str, Any],
    columns: tuple[str, ...],
    *,
    version: str,
    model_version: str,
    dataset: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Wire-shaped FeatureContract for the served feature set."""
    return {
        "version": version,
        "model_version": model_version,
        "dataset": dataset or {},
        "label_map": {"0": "phishing", "1": "legitimate"},
        "features": contract_entries(manifest, columns),
    }
