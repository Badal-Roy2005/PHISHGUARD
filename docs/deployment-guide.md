# Deployment guide

Status: **not deployed.** No git remote, no Supabase project, no Vercel/Render
project, no API keys. Nothing below has been executed.

## Hard constraint

This machine has **no Docker and no Podman**. Any flow that requires building a
container locally cannot be tested before deployment. Therefore:

- no `Dockerfile` is the critical path for the hackathon;
- hosts must build from a Git repository;
- Supabase local emulation (`supabase start`) is unavailable.

## Target topology

| Unit | Host | Build |
|---|---|---|
| `apps/web` | Vercel | pnpm workspace, Node from `.nvmrc` |
| `services/analysis` | Render (Git-based) | `uv sync --frozen` + `uvicorn` |
| `services/ml` | Render (Git-based) | `uv sync --frozen` + `uvicorn` |
| database | Supabase (hosted) | `supabase db push` |
| extension | load unpacked | none |

Render is chosen for Git-based builds, not for preference: a Docker-based host
cannot be validated locally before submission.

## Environment matrix

`apps/web` (browser-visible, safe to expose):

```
NEXT_PUBLIC_SUPABASE_URL
NEXT_PUBLIC_SUPABASE_ANON_KEY
NEXT_PUBLIC_API_BASE_URL
```

`apps/web` (server-only):

```
ANALYSIS_API_URL
ANALYSIS_SERVICE_TOKEN
```

`services/analysis`:

```
ENV=production
PERSISTENCE=supabase
SUPABASE_URL
SUPABASE_SERVICE_ROLE_KEY
ML_SERVICE_URL
ML_SERVICE_TOKEN
INTERNAL_SERVICE_TOKEN
ALLOWED_ORIGINS=https://<vercel-domain>
GOOGLE_SAFE_BROWSING_API_KEY
URLHAUS_API_KEY
INTEL_HTTP_TIMEOUT_SECONDS=5
INTEL_MAX_RESPONSE_BYTES=256000
INTEL_MAX_RETRIES=1
INTEL_CACHE_ENABLED=true
INTEL_SAFE_BROWSING_CACHE_TTL_SECONDS=3600
INTEL_URLHAUS_CACHE_TTL_SECONDS=21600
CT_ENABLED=false
CT_TIMEOUT_SECONDS=5
CT_MAX_RESPONSE_BYTES=1000000
CT_MAX_RECORDS=1000
MAX_CONCURRENT_SCANS=8
```

See `docs/threat-intelligence.md` for provider setup, quota semantics and the
`match`/`no_match`/`unavailable`/`error` model. See
`docs/transport-security.md` for TLS, HTTP-header and CT semantics. Missing
provider keys or a disabled CT flag are not startup failures; they produce
`skipped`/`unavailable`, never `safe`.

`services/ml`:

```
ENV=production
ML_SERVICE_TOKEN
MODEL_PATH=artifacts/model.joblib
FEATURE_CONTRACT_PATH=artifacts/feature_contract.json
```

Startup fails fast if a production token is missing, weak, or if
`SCANNER_ALLOW_LOOPBACK_FOR_TESTS` is set.

## Deploy order

1. **Supabase** — create project, `supabase link`, `supabase db push`, verify RLS
   with the anon key.
2. **services/ml** — deploy, check `GET /health` (`checks.model`).
3. **services/analysis** — deploy, check `GET /health`, then `GET /version`.
4. **apps/web** — deploy with `ANALYSIS_API_URL` pointing at the analysis host.
5. **Extension** — point at the web origin, load unpacked.

Health checks gate each step; do not continue on a non-200.

## Build commands

```bash
# web (Vercel)
pnpm install --frozen-lockfile && pnpm --filter @phishguard/web build

# python services (Render, root = repo root)
cd services/analysis && uv sync --frozen && uv run uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
cd services/ml       && uv sync --frozen && uv run uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
```

Python projects depend on `packages/contracts` by relative path, so the build
context must be the **repository root**, not the service directory.

## Rollback

- Vercel: promote the previous deployment.
- Render: redeploy the previous commit.
- Migrations: forward-only. Ship a compensating migration; never edit or reset an
  applied one.

## Known deployment risks

| Risk | Impact | Mitigation |
|---|---|---|
| Two Python hosts cold-start | 10–20 s first scan | keep instances warm for the demo |
| Vercel → analysis latency | slow first paint | polling UI shows "warming" state |
| CORS misconfiguration | scans fail silently in the browser | explicit allowlist; test from the deployed origin |
| No RLS test before deploy | data exposure | run the anon-key suite immediately after `db push` |
| No CI/CD autodeploy | manual step missed | deploy order documented above |

## Not deployed for this submission

Custom domains, TLS hardening, autoscaling, observability/alerting, and Chrome Web
Store publishing are out of scope before 10 November 2026.
