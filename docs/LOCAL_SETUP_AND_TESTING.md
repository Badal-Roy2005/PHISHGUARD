# PHISHGUARD — Local Setup and Testing Guide

## Overview

PHISHGUARD is a multi-layer phishing defense platform with explainable risk scoring.
It consists of several independent services that work together:

- **`services/analysis/`** — Python FastAPI service (`http://localhost:8000`) that performs
  deterministic URL analysis, TLS/HTTP assessment, and threat-intelligence lookup. Returns
  a policy-versioned risk assessment (`M7`). This is the primary backend for URL scans.

- **`services/ml/`** — Python FastAPI service (`http://localhost:8001`) that serves the
  XGBoost model trained on the PhiUSIIL dataset (`M2`). Provides `/predict`, `/model/info`,
  and `/explain` endpoints. *Optional* — the URL scan can function without the ML service.

- **`apps/web/`** — Next.js 16 web application (`http://localhost:3000` default) that
  provides a user interface for URL submission, scan history, and Supabase-backed
  authenticated scan persistence. Exposes `POST /api/scan` (anonymous, no Supabase session
  required) and `GET /api/scan/{id}` for result retrieval.

- **`packages/contracts/`** — Single source of truth for wire contracts (JSON Schemas +
  Pydantic models + TypeScript types). All services import from this package.

- **`apps/extension/`** — Manifest V3 Chrome extension for on-demand phishing risk
  assessment of the active tab. Calls `POST {PHISHGUARD_API_ORIGIN}/api/scan` anonymously.
  No content scripts, no page monitoring, no polling.

- **Supabase** — Optional backend for scan persistence and authenticated sessions.
  Anonymous scans are not persisted; a verified Supabase session sets an owner.

---

## 1. Project Architecture

```mermaid
graph TD
    subgraph Client
        direction LR
        Browser -->|URL scan| Next.js Web App[apps/web: http://localhost:3000]
        Browser -->|Active tab| Chrome Extension[apps/extension]
    end

    subgraph Backend
        direction TB
        Next.js Web App -->|POST /api/scan| Analysis Service[services/analysis: http://localhost:8000]
        Next.js Web App -->|ML inference| ML Service[services/ml: http://localhost:8001]
        Analysis Service -->|Supabase| Persistence[Supabase]
    end

    style Analysis Service fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style ML Service fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style Web App fill:#fff3e0,rgba(255,152,0,0.5),stroke-orange:2px
    style Extension fill:#e3f2fd,rgba(33,150,243,0.5),stroke:#1976d2:2px
```

### Flow Diagrams

#### URL Scan (anonymous, no Supabase)

```mermaid
sequenceDiagram
    participant Browser
    participant Extension[Chrome MV3 Extension]
    participant Web[Next.js Web App]
    participant Analysis[services/analysis: http://localhost:8000]
    
    Browser->>Extension: Click toolbar icon
    Extension->>Web: read active tab URL
    Web->>Analysis: POST /api/scan (anonymous)
    Analysis->>Analysis: run engines (url, tls, http, intel)
    Analysis-->>Web: ScanResult (200)
    Web-->>Extension: assessment data
    Extension->>Popup: render risk state
    Popup-->>Browser: display verdict
```

#### URL Scan (authenticated, with Supabase)

```mermaid
sequenceDiagram
    participant Browser
    participant User[Supabase-authenticated user]
    participant Extension[Chrome MV3 Extension]
    participant Web[Next.js Web App]
    participant Analysis[services/analysis: http://localhost:8000]
    
    Browser->>Extension: Click toolbar icon
    Extension->>Web: read active tab URL
    Web->>Analysis: POST /api/scan (with userId)
    Analysis-->>Web: ScanResult (persisted)
    Web-->>Extension: assessment data (cached)
    Extension->>Popup: render risk state
    Popup-->>Browser: display verdict
```

### ML Service Flow (optional)

```mermaid
sequenceDiagram
    participant Browser
    participant User
    participant Extension[Chrome MV3 Extension]
    participant ML[services/ml: http://localhost:8001]
    
    Browser->>Extension: Click toolbar icon
    Extension->>Web: read active tab URL
    Web->>ML: GET /model.info / POST /predict
    ML-->>Web: model info / prediction label
    Web-->>Extension: ML result
    Extension->>Popup: display probability
    Popup-->>Browser: show probability
```

---

## 2. Prerequisites

| Dependency | Tested Version | Mandatory / Optional | Installation |
|---|---|---|---|
| **Node.js** | 26 (`.nvmrc`) | Mandatory | `nvm install 26 || nvm use 26` |
| **pnpm** | 11.25.0 | Mandatory | `corepack enable && pnpm install` |
| **Python** | 3.14 | Mandatory | `apt-get install -y python3 python3-venv || brew install python` |
| **Google Chrome** | Stable 102+ | Mandatory (for extension) | `apt-get install -y google-chrome-stable || brew install --cask google-chrome` |
| **Python packages** | (see below) | Mandatory | `pip install --break-system-packages -e packages/contracts` then `pip install --break-system-packages -r services/ml/requirements.txt` or use `uv sync` in `services/ml/` |
| **system packages** | (none required) | Optional | none needed |

### Python packages (mandatory)

These are installed automatically when you run the setup commands below:

- `fastapi>=0.115,<1` — web framework for analysis and ML services
- `uvicorn>=0.30,<1` — ASGI server
- `pydantic>=2.8,<3` — data validation
- `phishguard-contracts` — shared contracts (installed from `packages/contracts`)
- `joblib>=1.4,<2` — ML model serialization
- `numpy>=1.26,<3` — numerical computing
- `scikit-learn>=1.5,<2` — ML utilities
- `xgboost>=2.1,<4` — trained model
- `shap>=0.46,<1` — SHAP explanations
- `tldextract>=5,<6` — URL hostname parsing
- `httpx>=0.27,<1` — HTTP client (analysis service)

---

## 3. Clone and Install

From a fresh clone of the repository:

```bash
# 1. Clone the repository
git clone https://github.com/phishguard/phishguard.git
cd phishguard

# 2. Install Node dependencies (workspace-wide)
pnpm install

# 3. Install Python contracts package
pip install --break-system-packages -e packages/contracts

# 4. Install ML service dependencies
pip install --break-system-packages -e services/ml 2>&1 | tail -5

# 5. Install remaining Python deps (tldextract etc.)
pip install --break-system-packages tldextract tld 2>&1 | tail -3
```

> **Note**: The `services/ml` package uses `uv` for isolation. You can also run
> `uv sync --frozen` inside `services/ml/` if `uv` is available.

---

## 4. Environment Configuration

Copy the environment template and adjust values for your local setup:

```bash
cp .env.example .env
```

### Required Environment Variables

| Variable | Used By | Required | Example | Description |
|---|---|---|---|---|
| `ENV` | All | No | `development` | Environment name |
| `LOG_LEVEL` | All | No | `INFO` | Log verbosity |
| `ANALYSIS_API_URL` | Next.js web app, Chrome extension | Yes | `http://localhost:8000` | Base URL of the analysis service |
| `ANALYSIS_SERVICE_TOKEN` | Next.js web app (`/api/scan` route) | Yes | `dev-only-change-me-please` | Token for `/internal/analyze` endpoint |
| `NEXT_PUBLIC_SUPABASE_URL` | Next.js web app (optional) | No | `` | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | Next.js web app (optional) | No | `` | Supabase anonymous key |
| `ML_SERVICE_URL` | Next.js web app (optional) | Yes | `http://localhost:8001` | Base URL of the ML service |
| `ML_SERVICE_TOKEN` | Next.js web app (`/api/scan` route) | Yes | `dev-only-change-me-please` | Token for ML service `/predict` |
| `ALLOWED_ORIGINS` | Chrome extension | Yes | `http://localhost:3000` | Comma-separated list of allowed origins |
| `PHISHGUARD_API_ORIGIN` | Chrome extension build | Yes | `http://localhost:3000` | Injected at build time; must be HTTP for loopback dev |

> **Important**: Never commit real secrets. The `.env` file is gitignored.

### Optional — Supabase (for authenticated scan persistence)

If you want scan persistence (scans owned by a user):

1. Create a Supabase project at <https://supabase.com>
2. Fill in:
   - `NEXT_PUBLIC_SUPABASE_URL=<your-project-url>`
   - `NEXT_PUBLIC_SUPABASE_ANON_KEY=<your-anon-key>`
3. The analysis service also needs a service-role key (not exposed to the client):

```bash
SUPABASE_SERVICE_ROLE_KEY=<your-service-role-key>
```

Anonymous scans (no Supabase session) work without configuration — they simply are not
persisted.

---

## 5. Start the Backend Services

### Step 1: Start the Analysis Service (`http://localhost:8000`)

```bash
cd /home/badal/Desktop/projects/PHISHGUARD
PYTHONPATH=services/analysis nohup uvicorn services.analysis.app.main:app \
    --host 0.0.0.0 --port 8000 --no-access-log > /tmp/analysis_service.log 2>&1 &
ANALYSIS_PID=$!
echo "Analysis service PID: $ANALYSIS_PID"
```

Verify it is running:

```bash
curl -s http://localhost:8000/health
# Expected: {"status":"ok","service":"analysis",...}

curl -s http://localhost:8000/version
# Expected: {"service":"analysis","version":"0.1.0",...}
```

### Step 2: Start the ML Service (`http://localhost:8001`)

```bash
cd /home/badal/Desktop/projects/PHISHGUARD
PYTHONPATH=services/ml nohup uvicorn services.ml.app.main:app \
    --host 0.0.0.0 --port 8001 --no-access-log > /tmp/ml_service.log 2>&1 &
ML_PID=$!
echo "ML service PID: $ML_PID"
```

Verify it is running:

```bash
curl -s http://localhost:8001/health
# Expected: {"status":"ok","service":"ml",...}

curl -s http://localhost:8001/model/info
# Expected: model name, version, metrics, feature contract
```

### Step 3: Start the Next.js Web Application (`http://localhost:3000`)

```bash
cd /home/badal/Desktop/projects/PHISHGUARD/apps/web
pnpm dev
```

The web app should be reachable at `http://localhost:3000`.

Verify it is running by visiting `http://localhost:3000` in a browser.

---

## 6. Test Web Scanning

### Anonymous Scan (no Supabase)

1. Visit `http://localhost:3000` in your browser.
2. Enter a URL (e.g., `https://example.com/login`) in the input field.
3. Click **Scan**.
4. Wait for the assessment result.
5. The result will show the risk band, score, verdict, and observed factors.

For `https://example.com/login`, you should see `insufficient_evidence` band with a
message like "Incomplete assessment — no high-risk indicators found."

### Authenticated Scan (with Supabase)

If you have configured Supabase environment variables:

1. Sign in to your Supabase account through the web app.
2. Submit a URL for scanning.
3. The scan will be persisted with your user ID.
4. You can view your scan history and details.

### ML-Powered Prediction (optional)

If the ML service is running (`http://localhost:8001`):

1. The web app may display a "Threat probability" pill alongside the risk band.
2. This comes from `ML_SERVICE_URL` + `/predict`.
3. If the ML service is not running, the pill will not appear (graceful degradation).

---

## 7. Build the Chrome Extension

### Configure the API origin

The extension builds with a fixed backend origin. For local development:

```bash
PHISHGUARD_API_ORIGIN=http://localhost:8000 \
  pnpm --filter @phishguard/extension build
```

> **Important**: 
> - `http://localhost:8000` is accepted for loopback development only.
> - Remote plaintext HTTP origins are rejected by the build script.
> - For production, use `https://your-deployed-origin.com`.

### Build output

The build script (`build.ts`) performs these steps:

1. Validates `PHISHGUARD_API_ORIGIN` (must be http/https, no wildcards, no credentials)
2. Runs `tsc -p tsconfig.build.json` — emits ES modules from `.ts` sources
3. Copies `popup.html`, `popup.css` to `dist/`
4. Generates `dist/manifest.json` with:
   - `host_permissions: ["http://localhost:8000/*"]`
   - `connect-src http://localhost:8000` (CSP)
   - `activeTab` permission only

```bash
ls dist/
# Expected:
#   manifest.json  popup.html  popup.css  popup.js  service-worker.js
#   lib/url.js  lib/backend.js  lib/assessment.js  lib/messages.js
#   lib/cache.js  lib/request-gate.js  lib/view.js  lib/api-origin.js
```

### Load the extension in Chrome

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select `apps/extension/dist`.
4. The extension should appear; click the **Pin** icon to pin it to the toolbar.
5. Open a new tab and visit any HTTPS website (e.g., `https://example.com`).

### Trigger an assessment

1. Click the PHISHGUARD extension icon.
2. The popup will read the active tab's URL and send it to the backend.
3. After a few seconds, the assessment result will appear:
   - **Risk band** (high/critical/suspicious/guarded/low/insufficient_evidence)
   - **Score** (0–100, or "No score")
   - **Verdict** (e.g., "High-risk evidence", "Insufficient assessment")
   - **Reasons** (observed factors contributing to the risk)
   - **Coverage** (how much of the assessment was complete)
   - **Likelihood** (heuristic percentage)
   - **Posture** (grade A–F)

### Recheck and Cache

- **Recheck**: Click the **Recheck** button to force a fresh assessment (ignores cache).
- **Clear cached result**: Click **Clear cached result** to remove the in-memory cache
  entry and then re-assess.

---

## 8. Manual Testing Checklist

### URL Assessment Tests

| Test Case | Expected Input | Expected Band | Notes |
|---|---|---|---|
| Safe HTTPS URL | `https://example.com/` | `low` / `Low observed risk` | No high-risk indicators |
| Keyword-rich URL | `http://localhost:3000/login?token=secret#section` | `high` / `High-risk evidence` | Credentials stripped, token removed |
| Suspicious characteristics | `http://example.com/~user/scripts/` | `suspicious` / `Suspicious characteristics` | Obfuscated path, single-label host |
| Insufficient evidence | `https://example.com/clean-page` | `incomplete` / `Incomplete assessment` | No engines triggered, normal coverage |
| Backend unavailable | Stop analysis service | `unavailable` | Extension shows error notice |
| Unsupported scheme | `ftp://example.com/file` | `unsupported_url` | Rejected before network call |
| URL with credentials | `https://user:pass@example.com/` | credentials removed, shown in popup | `token`, `session`, `password` etc. stripped |
| Sensitive query params | `https://example.com/page?token=abc&session=xyz` | params removed, count shown | `token`, `session`, `password`, `otp`, `jwt` etc. |
| Recheck (force refresh) | Click Recheck | Fresh assessment, cache bypassed | Sequence gate prevents stale response |
| Cache behavior | Assess same URL twice | Second call returns `cached: true` | 5-minute TTL, 32-entry cap |

### Tab Switching

1. Assess URL on Tab A.
2. Switch to Tab B (different URL) while assessment is in-flight.
3. The in-flight request for Tab A should be cancelled/deduplicated; Tab B gets a new request.

### Anonymous Scan Persistence

1. Assess a URL anonymously.
2. Verify the scan is NOT stored in Supabase (check Supabase dashboard if configured).
3. The extension should show the assessment without a persistence indicator.

### Authenticated Scan Persistence

1. Configure Supabase env vars.
2. Sign in to Supabase through the web app.
3. Assess a URL.
4. Verify the scan is persisted with your user ID.
5. View scan history in the web app.

---

## 8. Automated Tests

### Run the full verification suite

```bash
pnpm verify
```

This runs: dependency sync → typecheck → lint → test → build.

### Extension tests only

```bash
pnpm --filter @phishguard/extension test
# 65 tests across: URL sanitization, assessment parsing, backend client,
# cache/single-flight/epoch, request gate, contract parity, manifest privacy, build
```

### TypeScript and lint checks

```bash
pnpm --filter @phishguard/extension typecheck
pnpm lint
# root: pnpm typecheck  (includes all workspace packages)
```

### Python tests

```bash
cd services/analysis && uv run pytest 2>&1 | tail -10
# or
bash scripts/test-python.sh
```

### Build verification

```bash
pnpm --filter @phishguard/extension build
# Must succeed and emit valid manifest.json
```

---

## 9. Troubleshooting

| Problem | Likely Cause | Diagnostic Command |
|---|---|---|
| `pnpm install` fails | Lockfile corruption, Node version mismatch | `node --version` (must be >=22), `pnpm --version` (must be 11.x) |
| Analysis service won't start | `phishguard_contracts` not installed | `pip show phishguard-contracts`; reinstall with `pip install --break-system-packages -e packages/contracts` |
| `ModuleNotFoundError: No module named 'tldextract'` | Missing system package | `pip install --break-system-packages tldextract` |
| Extension won't load | Manifest error in Chrome console | Open `chrome://extensions`, check "Details" for error summary |
| Extension popup shows "unavailable" | Backend not running at `PHISHGUARD_API_ORIGIN` | `curl -s $PHISHGUARD_API_ORIGIN/health`; ensure analysis service is running |
| `401 Missing or invalid service token` | Wrong `ANALYSIS_SERVICE_TOKEN` | Check `.env` matches `services/analysis/app/main.py` setup |
| `connect-src` error in CSP | Extension calling wrong origin | Verify `PHISHGUARD_API_ORIGIN` in build matches analysis service URL |
| Web scan returns `rate_limited` | Too many rapid requests | Throttle requests; no retry loop in extension |
| `insufficient_evidence` band on clean URL | Normal for live assessment (coverage ~75–85%) | This is expected — missing evidence is never "safe" |
| Chrome blocks "Load unpacked" | Corrupted extension, bad manifest | Run `pnpm --filter @phishguard/extension build` again; verify `dist/manifest.json` |

---

## 10. Current Limitations

| Limitation | Status | Workaround |
|---|---|---|
| **Production HTTPS backend not deployed** | True | Use `PHISHGUARD_API_ORIGIN=http://localhost:8000` for local development only |
| **Chrome popup live integration not yet verified** | True (in this environment) | Manual testing possible with running backend services; see testing checklist |
| **Chrome Web Store publication** | Not completed | Extension can be loaded unpacked; signed packaging requires production cert |
| **pgTAP verification** | Pending (no Docker/Podman/Postgres locally) | `bash scripts/test-rls.sh` cannot run locally |
| **Rate limiting** | Not implemented yet (M9 audit item D4) | Extension sends one request per user action; no retries/polling |
| **CT (Certificate Transparency) enabled** | Off by default (`CT_ENABLED=false`) | CT failures are reported as `partial/unavailable`, never `safe` |
| **ML service dependency** | Optional | URL scan works without ML service; ML probability is reported separately |

---

## 11. Commands Summary

| Action | Command |
|---|---|
| Install all dependencies | `pnpm install` |
| Install Python contracts | `pip install --break-system-packages -e packages/contracts` |
| Start analysis service | `PYTHONPATH=services/analysis nohup uvicorn services.analysis.app.main:app --host 0.0.0.0 --port 8000 --no-access-log &` |
| Start ML service | `PYTHONPATH=services/ml nohup uvicorn services.ml.app.main:app --host 0.0.0.0 --port 8001 --no-access-log &` |
| Start web app | `cd apps/web && pnpm dev` |
| Build Chrome extension | `PHISHGUARD_API_ORIGIN=http://localhost:8000 pnpm --filter @phishguard/extension build` |
| Load extension in Chrome | `chrome://extensions` → Developer mode → Load unpacked → `apps/extension/dist` |
| Run extension tests | `pnpm --filter @phishguard/extension test` |
| Run full verification | `pnpm verify` |
| Python analysis tests | `cd services/analysis && uv run pytest` |
| Run lint | `pnpm lint` |
| Run typecheck | `pnpm typecheck` |

---

## 11. FAQ

### Q: Why does the extension show `incomplete` / `insufficient_evidence` on normal URLs?

**A**: This is expected behavior. The live assessment normally has ~75–85% coverage because
brand-impersonation evidence is unavailable in M7, and not all engines are configured.
The `incomplete` band explicitly states that missing evidence is **not** safe — it is a
coverage warning, not a risk verdict.

### Q: Why can't I use `https://remote-host:8000` as the API origin?

**A**: The build script rejects plaintext HTTP origins that are not loopback (localhost/127.0.0.1/[::1]).
Remote deployments must use HTTPS.

### Q: Why does the ML service `/predict` return `unauthorized`?

**A**: The `/predict` endpoint requires the `ML_SERVICE_TOKEN` header. Set
`ML_SERVICE_TOKEN=dev-only-change-me-please` in your `.env` and ensure the Next.js app
passes it (configured in `apps/web/lib/api/scan.ts`).

### Q: Can I run the extension without the analysis service?

**A**: The extension will show an "unavailable" notice if the backend is unreachable. The
extension has a 20-second timeout and a 5-minute in-memory cache; a cache hit can serve
a previous assessment even if the backend is temporarily down.

### Q: Do I need Supabase to use the extension?

**A**: No. The extension works anonymously — it calls `POST /api/scan` without a Supabase
session. Supabase is only needed if you want scan persistence (scans owned by a user).

### Q: Why does the web app show a different risk band than the extension?

**A**: The web app and extension use the same `/api/scan` endpoint and backend. Any
difference would be due to different `PHISHGUARD_API_ORIGIN` values or cached results.

---

## 12. git status and modified files (after setup)

```bash
git status --short
# M docs/architecture.md       (updated architecture description)
# M docs/implementation-roadmap.md  (M8/M9/M10 status updates)
# M pnpm-lock.yaml           (workspace dependency changes)
# ?? apps/extension/          (new M10 extension package)
# ?? docs/chrome-extension.md (new M10 documentation)
# ?? apps/web/AGENTS.md       (pre-existing, not modified)
# ?? docs/audits/M0-M8-comprehensive-audit.md  (pre-existing audit)
```

---

## 13. Finalization

After following this guide:

1. All services should be running and healthy.
2. The web app should be accessible at `http://localhost:3000`.
3. The analysis service should respond at `http://localhost:8000`.
4. The ML service should respond at `http://localhost:8001`.
5. The Chrome extension should build and load successfully.
6. Anonymous URL assessments should produce a risk band (low/suspicious/guarded/high/incomplete).
7. All 65 extension tests should pass.
8. `pnpm verify` should exit 0.

If anything fails, consult the troubleshooting table above or check the respective service logs
(`/tmp/analysis_service.log`, `/tmp/ml_service.log`).

**Do not commit, push, or deploy.** This guide is for local development and testing only.