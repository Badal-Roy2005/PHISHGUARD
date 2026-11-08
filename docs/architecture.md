# Architecture

Status: **M0/M1 implemented**. Only bootstrap, configuration, health endpoints and
wire contracts exist. Engines, scanner, scoring, database and UI are planned.

## Units

```
 Chrome MV3 extension ─┐
                       ├─► apps/web (Next.js 16)  ── dashboard, auth session, thin proxy
 browser dashboard ────┘        │  X-Service-Token (server-only)
                                ▼
                   services/analysis  (FastAPI :8000)
                   orchestration · deterministic engines · risk aggregation
                      │                    │
                      │                    └─► scanner (only outbound code)
                      │
                      ├─► services/ml (FastAPI :8001)   stateless inference + SHAP
                      └─► Supabase (hosted)             scans, reports, intel cache
```

## Boundaries that must not be crossed

| Rule | Reason |
|---|---|
| `apps/web` never fetches target URLs | keeps SSRF surface off the public handler and out of Vercel's egress |
| `services/ml` performs no network I/O and holds no DB credentials | independent, stateless, replaceable |
| `services/ml` and `services/analysis` share only `packages/contracts` | they must be deployable and testable independently |
| all outbound traffic goes through `services/analysis/scanner` | single choke point for SSRF/DNS-rebinding controls |
| the browser only ever sees the Supabase anon key | service-role key stays server-side |

## Current components

| Path | Status |
|---|---|
| `packages/contracts` | JSON Schemas, Pydantic models, TS types and validators, fixtures |
| `services/analysis` | app factory, env validation, `/health`, `/version`, `/internal/config`, contract-validated `/internal/analyze` (returns 501) |
| `services/ml` | app factory, env validation, `/health`, `/version`, `/internal/config`, contract-validated `/predict` (returns 503) |
| `apps/web` | minimal App Router shell that imports contracts; no scan UI yet |

Both services return an explicit "not implemented" response instead of a fabricated
verdict. That is deliberate: §"unavailable is never safe" applies to development too.

## Scan lifecycle

`queued → running → complete | partial | failed`

`partial` means at least one engine did not produce a usable verdict (`unknown`,
`skipped`, `error`). Confidence drops and the band may become
`insufficient_evidence`; it never becomes `low`.

## Why the web tier proxies instead of calling engines

Vercel serverless functions cannot host an 8 s multi-hop scan plus five engines.
`apps/web` validates, enqueues and polls; `services/analysis` owns execution.

## Known architectural open questions

1. Job queue: in-process `asyncio` queue for the hackathon; external queue (Redis)
   is out of scope before the deadline.
2. Two Python hosts double cold-start latency; keep instances warm for the demo.
3. Certificate Transparency (`crt.sh`) is flag-gated and off by default.
