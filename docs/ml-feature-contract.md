# ML feature contract

Status: **schema frozen, feature list captured from the real dataset, model not
trained.** M2 finalizes `artifacts/feature_contract.json`.

## Dataset facts (verified from the CSV on disk)

- File: `PhiUSIIL_Phishing_URL_Dataset.csv` (54.2 MB, repository root, gitignored)
- Rows: **235,795** data rows
- Columns: **56** = `FILENAME`, `URL`, **53 numeric/derived features**, `label`
- Class balance (from the project brief): 134,850 legitimate / 100,945 phishing
- `label`: **`0 = phishing`, `1 = legitimate`** — inverted from intuition.
  Asserted in code (`LABEL_MAP`) and in tests.

## The contract problem this dataset creates

Only ~20 of the 53 features are derivable from the URL string alone. About 29 are
**page-content** features that require fetching and parsing the page
(`LineOfCode`, `HasTitle`, `NoOfPopup`, `NoOfiFrame`, `HasPasswordField`, …).
A model trained on all 53 therefore cannot be fully served at scan time without a
content extractor.

**Decision to validate in M2:** train and report two models.

1. `full` — all 53 features, research metrics. Cannot serve live without a fetch
   and a DOM extractor.
2. `live` — URL-derivable + safe derived features only. This is the model the ML
   service serves, so `status` stays `ok` instead of `partial`.

Never silently impute the missing content features at inference.

## Proposed `live_source` classification

| Source | Features |
|---|---|
| `url` (20) | `URLLength`, `Domain`, `DomainLength`, `IsDomainIP`, `TLD`, `TLDLength`, `NoOfSubDomain`, `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`, `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`, `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfOtherSpecialCharsInURL`, `SpacialCharRatioInURL`, `IsHTTPS` |
| `derived` (4) | `URLSimilarityIndex`, `CharContinuationRate`, `TLDLegitimateProb`, `URLCharProb` (computed from dataset/corpus statistics; must be versioned with the model) |
| `http` / content (29) | `LineOfCode`, `LargestLineLength`, `HasTitle`, `Title`, `DomainTitleMatchScore`, `URLTitleMatchScore`, `HasFavicon`, `Robots`, `IsResponsive`, `NoOfURLRedirect`, `NoOfSelfRedirect`, `HasDescription`, `NoOfPopup`, `NoOfiFrame`, `HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField`, `Bank`, `Pay`, `Crypto`, `HasCopyrightInfo`, `NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef` |

Identifiers, never model inputs: `FILENAME`, `URL`, `label`.

## Contract file shape

```jsonc
{
  "version": "1",
  "model_version": "1.0.0",
  "dataset": { "name": "PhiUSIIL", "rows": 235795, "feature_count": 53,
               "class_counts": { "0_phishing": 100945, "1_legitimate": 134850 } },
  "label_map": { "0": "phishing", "1": "legitimate" },
  "features": [
    { "name": "URLLength", "dataset_column": "URLLength", "dtype": "integer",
      "required": true, "live_source": "url", "default_policy": "reject" }
  ]
}
```

`default_policy`:

- `reject` — prediction cannot proceed without it (URL-derivable core features).
- `unknown` — proceed, return `status: "partial"`, reduce confidence.
- `neutral` — no signal either way; never treated as evidence of safety.

## Training rules

1. Leakage audit **before** splitting: exact duplicates, normalized-URL duplicates,
   cross-class registrable-domain overlap.
2. Stratified 70/15/15 with a fixed seed; the test split is never used for tuning.
3. Report accuracy, precision, recall, F1, ROC-AUC, PR-AUC — measured, not target.
4. SHAP (`TreeExplainer`) for the deployed model; persist top-k contributions.
5. Persist `model.joblib`, `preprocessor.joblib`, `feature_contract.json`,
   `metrics.json`, `MODEL_CARD.md`, `manifest.json` (SHA-256) together.
6. A model without its preprocessing object and contract version is invalid.

## Assertions that must exist in code

- `LABEL_MAP["0"] == "phishing"` and `LABEL_MAP["1"] == "legitimate"`.
- Observed class counts match the dataset metadata within tolerance.
- Same input → same probability (no nondeterminism in serving).
- Missing required feature → `status != "ok"`, never a silent `0`.
- SHAP contributions sum approximately to the model margin (tolerance-tested).
