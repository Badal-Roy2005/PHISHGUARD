# PHISHGUARD

Multi-layer phishing detection with explainable, policy-versioned risk scoring.

PHISHGUARD runs six independent engines — URL structural analysis, live fetch inspection
(SSRF-protected), threat intelligence (Google Safe Browsing + URLhaus), TLS/HTTP security
assessment, Certificate Transparency, and M7 deterministic risk aggregation — then combines
them into a coverage-aware risk assessment with full factor-level explanations.

Instead of one opaque score, PHISHGUARD produces **three separate outputs**:
- **Threat likelihood** (intel, URL, brand, redirect evidence)
- **Security posture** (TLS and HTTP configuration)
- **Evidence confidence** (coverage, engine status, missing evidence)

Missing or failed evidence is never treated as safe — it is reported explicitly and reduces
coverage.

## What's implemented (M0–M7)

| Component | Status |
|---|---|
| `packages/contracts` | JSON Schemas, Pydantic models, TS types/validators, fixtures |
| `services/analysis` | FastAPI orchestration; URL engine, scanner, threat-intel, TLS/HTTP/CT, M7 risk aggregation; `/internal/analyze` |
| `services/ml` | FastAPI `/predict` inference; XGBoost model artifacts |
| `apps/web` | Next.js 16 dashboard; scan form, results, history, auth, Supabase persistence |
| `apps/extension` | Chrome Manifest V3 extension for active-tab assessment |

## Architecture

```
Chrome MV3 extension ─┐
browser dashboard ────┼─► apps/web (Next.js 16)  ── dashboard, auth, thin proxy
                      │    X-Service-Token (server-only)
                      ▼
             services/analysis (FastAPI :8000)
             orchestration · engines · intel · M7 risk assessment
                       │                    │
                       │                    ├─► scanner (target fetches only)
                       │                    └─► threat-intel providers (fixed endpoints)
                       │
                       ├─► services/ml (FastAPI :8001)   stateless inference + SHAP
                       └─► Supabase (hosted)             scans, reports, intel cache
```

**Security boundaries:**
- `apps/web` never fetches target URLs (SSRF surface stays off the public handler)
- `services/ml` performs no network I/O and holds no DB credentials
- All target-URL fetches go through `services/analysis/scanner` with DNS pinning, private-IP rejection, redirect revalidation, bounded timeouts and response caps
- Service-role keys stay server-side only; browser sees only the Supabase anon key

## Quick start

### Prerequisites
- Node 26.x (`.nvmrc`), pnpm 11, uv

### Install
```bash
pnpm install
```

### Run verification (typecheck → lint → test → build)
```bash
bash scripts/verify.sh
```

### Run services locally

Terminal 1 — Analysis API (port 8000):
```bash
cd services/analysis && uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Create `services/analysis/.env` (use `PERSISTENCE=memory` for local without Supabase).

Terminal 2 — Web dev server:
```bash
pnpm dev
```

Visit `http://localhost:3000/` — the scan form is on the homepage. Submit any URL to get a full M7 risk assessment.

## Hackathon submission

- **Project:** PHISHGUARD
- **Problem:** Phishing detection needs explainable, multi-signal verdicts — not black-box scores
- **Solution:** Six independent engines aggregated into a policy-versioned risk assessment with per-factor explanations
- **Demo:** `POST /api/scan` with any URL → JSON result with `risk.score`, `risk.band`, `risk.likelihood`, `risk.posture`, `risk.confidence`, and per-engine findings
- **Milestones:** M0–M7 complete; M8+ (Supabase migrations, dashboard features, extension polish) in progress

## Documentation

- `docs/architecture.md` — system design and security boundaries
- `docs/risk-assessment.md` — M7 scoring weights, bands, and factor rules
- `docs/threat-intelligence.md` — provider states and safe-verdict rules
- `docs/transport-security.md` — scanner SSRF invariants and TLS/HTTP assessment
- `docs/api-contracts.md` — wire format and contract parity
- `docs/LOCAL_SETUP_AND_TESTING.md` — full local setup instructions

## License

Private — hackathon submission.
