# API contracts

**Version: `2026-11-08.1`** · source of truth: `packages/contracts/schemas/*.schema.json`
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
| `POST` | `/internal/analyze` | analysis | `X-Service-Token` | M1: validates, returns 501 |
| `GET` | `/internal/config` | both | `X-Service-Token` | implemented |
| `POST` | `/predict` | ml | `X-Service-Token` | M1: validates, returns 503 |
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

## Risk block

Three separate outputs, never collapsed:

```json
{
  "score": 78,
  "band": "high",
  "likelihood": { "score": 0.82, "band": "high",
                  "contributions": [ { "engine": "ml", "weight": 0.45, "value": 0.91 } ] },
  "posture":    { "score": 42, "grade": "D",
                  "penalties": [ { "id": "hsts-missing", "points": 8 } ] },
  "confidence": { "score": 0.86, "engines_ok": 5, "engines_total": 6, "notes": [] }
}
```

- `band`: `low | suspicious | high | critical | insufficient_evidence`.
- `score` is `null` when confidence is too low to publish one.
- Weights must sum to 1.0; no single engine may contribute more than 40%.

## Explanation

```json
{ "top_factors": [ { "feature": "TLDLegitimateProb", "value": 0.11,
                     "contribution": 0.18, "direction": "increases_risk",
                     "source": "ml" } ],
  "summary": "Model probability 0.91 with credential-harvesting keywords." }
```

`source` distinguishes model-driven factors from deterministic findings.

## Errors

```json
{ "error": { "code": "blocked_target",
             "message": "Target resolves to a private address.",
             "request_id": "req_01HZX8K4T9" } }
```

Codes: `invalid_url`, `blocked_target`, `rate_limited`, `not_found`,
`unauthorized`, `payload_too_large`, `upstream_unavailable`, `timeout`, `internal`.

`request_id` is echoed in the `X-Request-ID` response header.

## ML contracts

`POST /predict`:

```json
{ "features": { "URLLength": 41 }, "explain": true, "model_version": null }
→ { "label": "phishing", "probability_phishing": 0.91,
    "contributions": [ { "feature": "URLLength", "value": 41, "shap": 0.12 } ],
    "missing_features": [], "status": "ok", "model": { "name": "...", "version": "1.0.0",
    "feature_contract_version": "1" } }
```

`status` is `ok | partial | unknown`. `partial` means some features were
unavailable and confidence is reduced. `unknown` means no usable prediction.

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
