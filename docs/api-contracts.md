# API contracts

**Version: `2026-11-09.2`** · source of truth: `packages/contracts/schemas/*.schema.json`
· Python mirror: `packages/contracts/src/phishguard_contracts/models.py`
· TS mirror: `packages/contracts/src/types.ts`

Parity is enforced by `packages/contracts/tests/test_parity.py`: every fixture must
validate against both the JSON Schema and the Pydantic model.

## Endpoints

| Method | Path | Unit | Auth | State |
|---|---|---|---|---|
| `POST` | `/api/scan` | web | session or anon (rate-limited) | M9 |
| `GET` | `/api/scan/{id}` | web | owner / anon token | M9 |
| `GET` | `/api/reports` | web | public read | M8 |
| `POST` | `/api/reports` | web | authenticated | M8 |
| `POST` | `/internal/analyze` | analysis | `X-Service-Token` | M7: runs url + tls + http + intel engines and returns a deterministic risk assessment |
| `GET` | `/internal/config` | both | `X-Service-Token` | implemented |
| `GET` | `/model/info` | ml | none | **implemented (M2)** |
| `POST` | `/predict` | ml | `X-Service-Token` | **implemented (M2)** |
| `POST` | `/explain` | ml | `X-Service-Token` | **implemented (M2)** |
| `GET` | `/health`, `/version` | both | none | implemented |

## Scan statuses

`queued`, `running`, `complete`, `partial`, `failed`.

- `partial`: at least one engine returned `unknown`, `skipped` or `error`.
- `failed`: no usable assessment was produced.
- Only `complete` implies every engine returned `ok`.

## Engine statuses

`ok`, `partial`, `skipped`, `unknown`, `error`.

| Value | Meaning | Rendered as |
|---|---|---|
| `ok` | usable verdict | normal |
| `partial` | verdict with reduced coverage | warning |
| `skipped` | not configured (e.g. missing API key) | **unavailable** |
| `unknown` | attempted, no verdict (timeout, blocked) | **unavailable** |
| `error` | failed | **unavailable** |

`skipped`, `unknown`, `error` and `partial` must never be shown or scored as safe.

## Engine report envelope

Every engine returns the same shape, so evidence and attribution are uniform:

```json
{
  "engine": "ml",
  "status": "ok",
  "findings": [
    { "id": "ml-high-probability", "title": "Model classifies as phishing",
      "severity": "high", "detail": "p=0.91", "evidence_ref": "ml.contributions" }
  ],
  "evidence": { "probability_phishing": 0.91 },
  "source": "phiUSIIL-xgb@1.0.0",
  "duration_ms": 42,
  "error": null
}
```

- `Findings` take `severity` in `info|low|medium|high|critical`.
- `evidence` is structured data only. Never HTML, never a raw response body.
- `source` is human-readable attribution, always present.
- All six engine keys (`ml`, `url`, `tls`, `http`, `intel`, `community`) are
  required in a `ScanResult`, even while queued, so absence is explicit.

## Scan request / response

```json
POST /api/scan
{ "url": "https://example.com/login",
  "options": { "include_intel": true, "include_ct": false, "timeout_ms": 8000 } }
→ 202
{ "scan_id": "6f1c2a44-...", "status": "queued", "poll_after_ms": 800 }
```

`url` rules (structural only, no DNS, no fetch):

- absolute `http`/`https`
- 8–2048 characters
- no embedded credentials
- `localhost` and `*.localhost` rejected
- unknown top-level fields rejected

`GET /api/scan/{id}` returns `ScanResult`. `risk` is `null` while queued/running;
`complete` and `partial` require `risk` and `explanation` (enforced in both
schema and model).

## Risk block (M7)

One deterministic assessment, with four separate concepts:

```json
{
  "score": 83,
  "band": "high",
  "verdict": "High risk.",
  "incomplete": false,
  "likelihood": { "score": 1.0, "band": "critical",
                  "contributions": [ { "engine": "intel", "weight": 0.4667, "value": 1.0 } ] },
  "posture":    { "score": 68, "grade": "D", "status": "ok",
                  "penalties": [ { "id": "http_finding_hsts_missing", "points": 20 } ] },
  "confidence": { "score": 1.0, "engines_ok": 6, "engines_total": 6,
                  "covered_weight": 100, "total_weight": 100,
                  "incomplete": false, "missing_evidence": [], "notes": [] },
  "factors": [
    { "reason_code": "intel_confirmed_match", "category": "intel", "source": "intel",
      "observed": "google_safe_browsing", "contribution": 35, "max_contribution": 35,
      "direction": "increases_risk", "severity": "high",
      "explanation": "At least one threat-intelligence provider reported a match.",
      "status": "applied" }
  ],
  "reason_codes": ["intel_confirmed_match"],
  "model_probability": {
    "probability_phishing": 0.91, "label": "phishing", "status": "ok",
    "model_version": "1.0.0", "calibrated": false,
    "used_in_risk_score": false, "source": "phiUSIIL-xgb@1.0.0"
  },
  "policy": {
    "version": "m7-2026-11-09.2", "calibrated": false,
    "weights": { "intel": 35, "url": 15, "brand": 15,
                 "redirect": 10, "tls": 15, "http": 10 },
    "bands": [ { "band": "low", "min_score": 0, "max_score": 19 } ],
    "min_coverage_for_score": 0.5, "min_coverage_for_low": 0.75
  }
}
```

- `score` is the provisional 0–100 heuristic sum. It is `null` when coverage is
  too low to publish a score.
- `band`: `low | guarded | suspicious | high | insufficient_evidence`.
  `critical` remains in the enum for older clients but M7 does not emit it.
- `likelihood` is threat likelihood from intel, URL, brand and redirect
  evidence. It is not the ML probability.
- `posture` is website security posture from TLS and HTTP configuration.
- `confidence` is evidence coverage, not certainty that the target is safe.
- `model_probability` is the ML result, exposed separately with
  `used_in_risk_score: false`.
- `factors` are the complete contributing-factor list. Each has a stable
  `reason_code`, source, observed value, contribution, maximum contribution,
  direction, severity, explanation and status.
- Missing, unavailable or errored evidence is visible in
  `confidence.missing_evidence` and in factors; it is never scored as safe.
- Weights and bands are **provisional, uncalibrated heuristics**. See
  `docs/risk-assessment.md`.

## Explanation

```json
{ "top_factors": [ { "feature": "intel_confirmed_match",
                     "value": "google_safe_browsing", "contribution": 35.0,
                     "direction": "increases_risk", "source": "intel" } ],
  "summary": "High risk." }
```

`source` distinguishes model-driven factors from deterministic findings. The
full factor list lives in `risk.factors`; `top_factors` is the ordered subset
for display.

## Errors

```json
{ "error": { "code": "blocked_target",
             "message": "Target resolves to a private address.",
             "request_id": "req_01HZX8K4T9" } }
```

Codes: `invalid_request`, `invalid_url`, `blocked_target`, `rate_limited`,
`not_found`, `unauthorized`, `payload_too_large`, `upstream_unavailable`,
`timeout`, `internal`.

`invalid_request` = a structurally valid HTTP body that cannot be used
(unknown feature name, non-numeric feature value, unknown enum value at a
non-schema layer). It is distinct from `invalid_url`, which is a URL-policy
rejection.

`request_id` is echoed in the `X-Request-ID` response header.

## ML contracts

`GET /model/info` returns the served model metadata, the full ordered
`feature_contract`, the tuned threshold and the missing-feature policy. It does
not return a prediction.

`POST /predict` and `POST /explain` share the same request and response shape;
`/explain` always fills `contributions`:

```json
{ "features": { "URLLength": 41, "IsHTTPS": 1 }, "explain": true,
  "model_version": null }
→ { "label": "phishing", "probability_phishing": 0.91,
    "contributions": [ { "feature": "URLLength", "value": 41, "shap": 0.12 } ],
    "missing_features": [], "status": "ok",
    "model": { "name": "phiusiil-xgboost", "version": "1.0.0",
               "feature_contract_version": "2", "label_map": { "0": "phishing", "1": "legitimate" } } }
```

- `status`: `ok | partial | unknown`.
  - `ok` — every contract feature was supplied.
  - `partial` — up to 25% were missing; training medians were used and every
    imputed name is listed in `missing_features`.
  - `unknown` — more than 25% missing; `label` is `"unknown"`. The probability
    is still returned because the field is required, but it is not a verdict.
- Contributions are SHAP values in the model margin space and are ordered by
  absolute value. They explain the score; they are not a probability
  decomposition and not causal.
- `503 upstream_unavailable` means the artifact set is absent or unreadable. The
  service never fabricates a probability.

`FEATURE_SCHEMA_VERSION` and `CONTRACT_VERSION` are exported by
`packages/contracts` and reported by `/health` and `/version`.

## Transport engines (M6)

`/internal/analyze` runs the M3 URL engine, the M6 `tls` and `http` engines, and
the M5B `intel` engine. The scanner is called once per scan; TLS and HTTP
assessment consume its evidence and never fetch the target again.

- `tls` evidence includes `verified`, `protocol`, `cipher`, certificate subject,
  issuer, validity dates and SAN count. Findings cover untrusted, expired,
  not-yet-valid, expiring, weak-protocol and weak-cipher certificates.
- `http` evidence includes present/missing security headers, HTTP status, HTTPS
  use and cookie-flag counts. Cookie values and response bodies are never
  included.
- Certificate Transparency is off by default (`CT_ENABLED=false`) and is only
  queried when the request sets `options.include_ct=true`. A requested CT
  lookup that is disabled, rate-limited, times out or fails makes the `tls`
  engine `partial`; it never removes the TLS findings.
- `unknown`, `skipped`, `partial` and `error` are never safe verdicts. M7
  consumes their evidence and reduces coverage; it never turns missing evidence
  into a low-risk result.

## Threat-intelligence engine (M5B)

`/internal/analyze` also runs the M5B `intel` engine. M7 turns provider
`match`, `no_match`, `unavailable` and `error` states into distinct factors.
A no-match or provider failure is never converted into a safe verdict.

Each provider is reported separately in `engines.intel.evidence.providers`:

```json
{
  "google_safe_browsing": {
    "status": "match | no_match | unavailable | error",
    "reason": null,
    "error": null,
    "looked_up_at": "2026-11-08T12:00:00Z",
    "expires_at": "2026-11-08T13:00:00Z",
    "cached": false,
    "findings": [
      {
        "provider": "google_safe_browsing",
        "status": "match",
        "queried_url": "https://example.com/login",
        "provider_reference": null,
        "category": "social_engineering",
        "severity": "high",
        "metadata": { "threat_type": "SOCIAL_ENGINEERING" },
        "looked_up_at": "2026-11-08T12:00:00Z",
        "expires_at": "2026-11-08T13:00:00Z",
        "source": "google_safe_browsing",
        "error": null
      }
    ]
  }
}
```

- `match` is the only state that produces a contract `Finding`.
- `no_match` is not a safe verdict; it only means this provider did not report a
  match.
- `unavailable` covers missing credentials, timeouts, outages, auth failures and
  quota/rate limits. `error` covers malformed or unexpected responses. Neither
  may be rendered or scored as safe.
- `engines.intel.status` is `ok | partial | skipped | unknown | error` and
  follows the aggregate rules in `docs/threat-intelligence.md`.
- Provider metadata is preserved, but raw HTTP bodies and credentials are not
  returned or logged.

## Community reports

`CreateReportRequest`: `url`, `category` (`phishing|malware|scam|credential_theft|
impersonation|other`), `description` 10–2000 chars, optional `evidence` object.
`Report` adds `id`, `status` (`pending|verified|rejected`), `created_at`,
`reporter_id`, `vote_count`.

## Compatibility rules

1. Adding an optional field is non-breaking.
2. Renaming/removing a field, or changing a required field, bumps
   `CONTRACT_VERSION` and requires updating Python **and** TypeScript in one PR.
3. Fixtures in `packages/contracts/fixtures/` are canonical examples; add one for
   every new shape.
