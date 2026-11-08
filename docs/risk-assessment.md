# Risk assessment (M7)

Status: **M7 implemented and tested locally.** `services/analysis/risk_assessment.py`
is a pure, deterministic aggregation layer over the URL, intel, TLS, HTTP and
redirect evidence. It performs no network I/O and calls no model.

Policy version: **`m7-2026-11-09.2`**. The weights and bands are provisional,
uncalibrated heuristics. They are not probabilities and must not be presented as
calibrated confidence.

## Outputs

M7 keeps four concepts separate:

| Output | Meaning | Source |
|---|---|---|
| `risk.score` / `risk.band` | Aggregate heuristic risk | weighted deterministic factors |
| `risk.likelihood` | Threat likelihood from intel, URL, brand and redirect evidence | intel, URL, redirect, optional brand |
| `risk.posture` | Website security posture | TLS and HTTP configuration |
| `risk.confidence` | Evidence coverage, not safety certainty | engine status and covered weight |

The ML phishing probability is reported separately as `risk.model_probability`
with `used_in_risk_score: false`. It never enters `risk.score`, `likelihood` or
`posture`.

## Weights and bands

| Category | Weight |
|---|---:|
| Threat intelligence | 35 |
| URL analysis | 15 |
| Brand impersonation | 15 |
| Redirects | 10 |
| TLS | 15 |
| HTTP security | 10 |

| Band | Range |
|---|---|
| `low` | 0–19 |
| `guarded` | 20–39 |
| `suspicious` | 40–69 |
| `high` | 70–100 |
| `insufficient_evidence` | `score = null` |

`critical` remains in the contract enum for compatibility but M7 does not emit
it.

## Scoring

Each available category is scored on its own 0–max scale, capped at its weight:

```text
raw = sum(category_points)
covered_weight = sum(weight of categories with usable evidence)
coverage = covered_weight / 100
```

`raw` is published as `risk.score` only when coverage is sufficient. Otherwise
`score = null` and `band = insufficient_evidence`.

Thresholds:

- `min_coverage_for_score = 0.50`
- `min_coverage_for_low = 0.75`

A low band requires both `raw <= 19` and coverage `>= 0.75`. A strong positive
signal (an intel match, a confirmed brand match, or any critical-severity
factor) can publish a score below the normal coverage threshold; missing
evidence still reduces confidence.

## Factors

`risk.factors` is the complete, ordered explanation. Each factor carries:

- `reason_code` — stable identifier for UI, tests and analytics
- `category` — `intel`, `url`, `brand`, `redirect`, `tls`, `http`, `ml`
- `source` — engine that produced the evidence
- `observed` — sanitized value or short description
- `contribution` / `max_contribution`
- `direction` — `increases_risk`, `decreases_risk` or `informational`
- `severity`
- `explanation`
- `evidence_ref` when a specific engine finding applies
- `status` — `applied`, `evaluated`, `unavailable`, `error` or `skipped`

`risk.reason_codes` is the ordered list of factor codes. `explanation.top_factors`
is the ordered display subset and does not replace the full factor list.

Missing, unavailable or errored evidence is explicit. It contributes zero points
and reduces coverage; it is never interpreted as benign.

## Category rules

### Intel

- `match` contributes up to 35 points and is a strong positive signal.
- `no_match` contributes zero and does not prove safety.
- `unavailable` / `error` contribute zero and reduce coverage.

### URL

URL findings map by severity: critical 15, high 10, medium 5, low 2. The URL
category is capped at 15.

### Brand

The brand category is present in the policy but **unavailable in M7** because no
brand engine exists. The factor is reported as unavailable, so maximum coverage
is below 100%.

### Redirects

Redirect evidence comes from the sanitized `transport.redirect_chain`:

- 5 or more hops: 10 points
- 3–4 hops: 5 points
- 1–2 hops: 4 points
- registered-domain change: 4 points
- host change: 2 points (only when the chain is otherwise low)
- any HTTP hop: 4 points
- redirect loop detected: 10 points

All redirect candidates share the 10-point redirect cap.

HTTP `http_not_https` and `http_insecure_redirect` are skipped in the HTTP
category because transport evidence already covers them. TLS `tls_not_used` is
scored in the TLS category at the full TLS weight. This avoids double-counting
correlated signals.

### TLS

TLS findings map by severity: critical 15, high 10, medium 6, low 3. The category
is capped at 15.

### HTTP

HTTP findings map by severity: critical 10, high 8, medium 5, low 2. A clean HTTP
report contributes zero. The category is capped at 10.

## Posture and confidence

`risk.posture` is computed only from TLS and HTTP:

```text
posture_risk = posture_points / covered_posture_weight * 100
posture_score = 100 - posture_risk
```

Grades: `A >= 90`, `B >= 80`, `C >= 70`, `D >= 60`, `F < 60`. If neither
category has usable evidence, `posture.score = null`. `posture.status` is `ok`,
`partial` or `unknown`.

`risk.confidence` reports `score = coverage`, `engines_ok`, `engines_total`,
`covered_weight`, `total_weight`, `incomplete` and `missing_evidence`.

## Scan status

`/internal/analyze` returns:

- `complete` only when every engine is `ok`
- `partial` when any engine is not `ok`

In M7 the brand engine is absent, so the normal live path is `partial` even when
all implemented engines succeed. A partial scan still includes a contract-valid
`risk` object and `explanation`.

## Determinism and tests

The engine is pure and deterministic: same inputs produce the same score, band,
factor order and reason codes. Tests assert exact contributions, band boundaries,
coverage behavior, strong-positive handling, redirect single-sourcing, ML
separation and repeatability. No test calls a live target, intel provider,
crt.sh or ML endpoint.
