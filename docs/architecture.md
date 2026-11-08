# Architecture

Status: **M2-M7 implemented**. The ML service, deterministic URL engine, isolated
scanner, TLS/HTTP assessment, threat-intelligence adapters and risk aggregation
exist. Database and UI are still planned.

## Units

```
 Chrome MV3 extension ─┐
                       ├─► apps/web (Next.js 16)  ── dashboard, auth session, thin proxy
 browser dashboard ────┘        │  X-Service-Token (server-only)
                                ▼
                   services/analysis  (FastAPI :8000)
                   orchestration · deterministic engines · intel · M7 risk assessment
                      │                    │
                      │                    ├─► scanner (target fetches only)
                      │                    └─► threat-intel providers (fixed endpoints)
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
| all target-URL fetches go through `services/analysis/scanner` | single choke point for SSRF/DNS-rebinding controls |
| threat-intel lookups use fixed provider endpoints in `threat_intel.py` | no user-controlled host; bounded timeouts, retries and response caps |
| the browser only ever sees the Supabase anon key | service-role key stays server-side |

## Current components

| Path | Status |
|---|---|
| `packages/contracts` | JSON Schemas, Pydantic models, TS types and validators, fixtures |
| `services/analysis` | app factory, env validation, `/health`, `/version`, `/internal/config`, M3 URL engine, M4 scanner, M5B intel adapters, M6 TLS/HTTP/CT assessment, M7 deterministic risk assessment; `/internal/analyze` runs url + transport + intel and returns a policy-versioned risk assessment |
| `services/ml` | app factory, env validation, `/health`, `/version`, `/internal/config`, M2 model metadata and contract-validated `/predict` |
| `apps/web` | minimal App Router shell that imports contracts; no scan UI yet |

Both services return an explicit "not implemented" response instead of a fabricated
verdict. That is deliberate: §"unavailable is never safe" applies to development too.

## Scan lifecycle

`queued → running → complete | partial | failed`

`partial` means at least one engine did not produce a usable verdict (`unknown`,
`skipped`, `error`). M7 lowers evidence coverage and may publish
`band = insufficient_evidence` with `score = null`; missing evidence never
becomes `low`.

## Why the web tier proxies instead of calling engines

Vercel serverless functions cannot host an 8 s multi-hop scan plus five engines.
`apps/web` validates, enqueues and polls; `services/analysis` owns execution.

## Known architectural open questions

1. Job queue: in-process `asyncio` queue for the hackathon; external queue (Redis)
   is out of scope before the deadline.
2. Two Python hosts double cold-start latency; keep instances warm for the demo.
3. Certificate Transparency (`crt.sh`) is flag-gated and off by default; it is
   bounded by timeout, response size and record count, with no shared cache yet.
