# ML feature contract

Status: **implemented in M2**. Source of truth for wire shape is
`packages/contracts`; the generated manifest is
`services/ml/artifacts/feature_manifest.json` and the served contract is
`services/ml/artifacts/feature_contract.json`.

- `FEATURE_SCHEMA_VERSION = "2"`
- `MODEL_VERSION = "1.0.0"`
- Model artifact: `phiusiil-xgboost` (URL-only `live` feature set)

## Dataset facts (measured from the CSV on disk)

- File: `PhiUSIIL_Phishing_URL_Dataset.csv` (repository root, gitignored)
- Rows: **235,795**; columns: **56**
- Columns: `FILENAME`, `URL`, `Domain`, `TLD`, `Title`, **50 numeric features**,
  `label`
- Missing values: **0**
- Exact duplicate rows: **0**
- Duplicate URLs: **425** (no conflicting labels)
- Registrable domains: **175,509**; **120** carry both labels (1,374 rows)
- Class counts: **100,945 phishing / 134,850 legitimate**
- `label`: **`0 = phishing`, `1 = legitimate`** — inverted from intuition.
  Pinned in `LABEL_MAP` and asserted in tests.

The model target is explicit: `y = 1` when the dataset label is `0`, so class 1
is always phishing. `predict_proba[:, 1]` is therefore the phishing probability.

## Why two feature sets

Of the 50 numeric columns, 46 are usable model inputs. Four are
corpus-derived statistics that leak dataset provenance and are excluded from
**every** model:

`URLSimilarityIndex`, `CharContinuationRate`, `TLDLegitimateProb`, `URLCharProb`.

| Set | Features | Purpose |
|---|---|---|
| `full_offline` | 46 | Research/reporting comparison. Includes page-content features, so it is **not served**. |
| `live` | 18 | Served model. Every feature is derivable from the URL string alone. |

Identifiers/non-numeric columns are never inputs: `FILENAME`, `URL`, `Domain`,
`TLD`, `Title`, `label`.

### `live` (served, 18 features)

`URLLength`, `DomainLength`, `IsDomainIP`, `TLDLength`, `NoOfSubDomain`,
`HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`, `NoOfLettersInURL`,
`LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`, `NoOfEqualsInURL`,
`NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfOtherSpecialCharsInURL`,
`SpacialCharRatioInURL`, `IsHTTPS`.

All 18 have `available_from_url_only: true`, `requires_controlled_webpage_inspection:
false`, `live_source: "url"`, `required: true` and `default_policy: "unknown"`.

### `full_offline` (not served, 46 features)

The `live` set plus 28 page-content features (`LineOfCode`, `HasTitle`,
`HasPasswordField`, `NoOfiFrame`, `NoOfPopup`, `Bank`, `Pay`, `Crypto`,
`NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfExternalRef`, …). They require controlled
inspection and are deliberately excluded from the served contract.

## Missing-feature policy

The ML service never invents a measurement:

| Missing | `status` | `label` | Behaviour |
|---|---|---|---|
| 0% | `ok` | predicted | no imputation |
| ≤ 25% | `partial` | predicted | training-median imputation; every imputed name returned in `missing_features` |
| > 25% | `unknown` | `"unknown"` | probability still returned for wire compatibility, explicitly not a verdict |

Unknown feature names and non-numeric/non-finite values are rejected with
`400 invalid_request`. They are not silently dropped.

## Splitting and leakage

1. Drop duplicate URLs (425 rows).
2. Group by **registrable domain** (`tldextract`, offline snapshot).
3. Drop domains that carry both labels (120 domains / 1,372 rows) — they cannot
   be placed in one split without leaking the label.
4. Deterministic, class-stratified 70/15/15 assignment by domain, seed `42`.

Result: **166,343 train / 32,556 validation / 35,099 test** rows, with no
registrable domain shared across splits. Assignment fingerprint:
`d155592404622e4de879b9b0881d6d0a0ae231f0fd690d8afebcaa48d985ec1e`.

The test split is never used for threshold tuning or model selection; both use
validation only.

## Measured metrics (held-out test split)

Served model: `live` / XGBoost, threshold `0.545` (max validation phishing F1).

| Metric | Validation | Test |
|---|---|---|
| Accuracy | 0.9983 | 0.9968 |
| Phishing precision | 0.9995 | 0.9993 |
| Phishing recall | 0.9960 | 0.9932 |
| Phishing F1 | 0.9977 | 0.9963 |
| ROC-AUC | 0.9987 | 0.9983 |
| PR-AUC | 0.9989 | 0.9986 |

All six runs are in `services/ml/artifacts/metrics.json` and `MODEL_CARD.md`.
These are measured values on one split of one dataset, not production
estimates. PhiUSIIL is highly separable; near-duplicate content across distinct
registrable domains (for example shared IPFS gateways) remains a possible
residual leakage source and has not been resolved.

## Artifacts (written together, versioned together)

| File | Contents |
|---|---|
| `model.joblib` | fitted pipeline (imputer + estimator) |
| `preprocessor.joblib` | fitted transform only |
| `feature_contract.json` | served contract, 18 ordered features |
| `feature_manifest.json` | all 53 documented features + availability flags |
| `selected.json` | served metadata, threshold, feature order |
| `metrics.json` | all six runs, validation and test metrics |
| `MODEL_CARD.md` | generated summary of the served model |
| `checksums.json` | SHA-256 for the contract, manifest and model files |
| `dataset_audit.json` | raw audit before any row is removed |
| `split_summary.json` | counts + assignment fingerprint |
| `shap_global.json` | mean absolute SHAP for the served model |

The dataset CSV and `*.joblib` artifacts are gitignored; JSON metrics, the
manifest, the model card and checksums are tracked.

## Reproduce

```bash
cd services/ml
uv run python -m training.train       # reads the CSV at the repo root
uv run pytest
```

Training is deterministic for a fixed seed. Random Forest predictions may differ
in the last floating-point bit because of `n_jobs=-1`; the decision threshold and
all reported metrics are identical.
