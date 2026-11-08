# AGENTS.md

## Repository status (read first)

Milestones **M0 through M7 are implemented**; M8+ are not. What exists today:

- `packages/contracts` — JSON Schemas, Pydantic models, TS types/validators, fixtures
- `services/analysis` — FastAPI app factory, env validation, health/version,
  M3 deterministic URL engine, M4 isolated scanner, M5B Google Safe Browsing and
  URLhaus adapters, M6 TLS/HTTP/CT assessment, M7 deterministic risk
  assessment; `/internal/analyze` runs url + tls + http + intel and returns a
  policy-versioned risk assessment with explicit incomplete coverage
- `services/ml` — M2 model training artifacts and `/predict` inference
- `apps/web` — minimal Next.js 16 shell that imports the contracts package
- `docs/` — architecture, roadmap, contracts, DB design, security, ML contract,
  threat intelligence, transport security, risk assessment, testing, deployment

Do not assume Supabase migrations (M8), the extension (M10) or the dashboard
exist. Only
`packages/contracts` describes the wire format; treat `docs/api-contracts.md` and
the schemas as authoritative over prose elsewhere.

## Commands (verified)

```bash
bash scripts/verify.sh        # dependency sync -> typecheck -> lint -> test -> build
pnpm install                  # Node workspace (pnpm 11)
pnpm typecheck                # tsc --noEmit, web + contracts
pnpm lint                     # eslint (root flat config)
pnpm test                     # node --test (Node 26 runs .ts natively)
pnpm build                    # next build (Turbopack)
cd packages/contracts && uv run pytest    # contract parity suite
cd services/analysis  && uv run pytest
cd services/ml        && uv run pytest
cd services/analysis  && uv run ruff check .
```

Python uses **uv per project** (`packages/contracts`, `services/analysis`,
`services/ml` each have their own `pyproject.toml` + `uv.lock` + `.venv`). Never
`pip install` into the system interpreter; it is PEP 668 managed.

Run a single Python test:
`cd services/analysis && uv run pytest tests/test_health.py::test_health_reports_ok_and_versions`

## Non-obvious repo facts

- Node is **26.x** (`.nvmrc`); Next.js runs on Turbopack and compiles the contracts
  package from TypeScript source via `transpilePackages`. Contracts imports use
  explicit `.ts` extensions (required by Node's native TS type-stripping) and every
  tsconfig sets `allowImportingTsExtensions`.
- `packages/contracts` is the single source of truth. The parity test validates each
  fixture against **both** the JSON Schema and the Pydantic model. If you change a
  shape, update schema + Pydantic + TS + fixture + `docs/api-contracts.md` together;
  bump `CONTRACT_VERSION` on breaking changes.
- `apps/web` must never fetch a target URL, and `services/ml` must never do network
  I/O or hold DB credentials. All target-URL fetches belong to
  `services/analysis/scanner` (M4). Threat-intel lookups use fixed provider
  endpoints in `services/analysis/threat_intel.py` (M5B).
- There is **no Docker, no Podman, no local Postgres**. `supabase start` cannot run.
  Migrations can only be applied to a hosted Supabase project (M8).
- M2 model artifacts exist and `/predict` serves the selected `live` XGBoost model.
  Report only metrics recorded in `services/ml/artifacts/metrics.json`; do not
  fabricate or round them up.
- M5B provider state is `match | no_match | unavailable | error`. A no-match or a
  provider failure is never a safe verdict. See `docs/threat-intelligence.md`.
- M6 calls the scanner exactly once per scan; TLS and HTTP assessment consume its
  evidence. CT is off by default (`CT_ENABLED=false`), uses the fixed crt.sh
  endpoint, and a requested CT failure makes the `tls` engine `partial`. See
  `docs/transport-security.md`.
- M7 scoring is deterministic and policy-versioned (`m7-2026-11-09.2`). Its
  weights and bands are provisional, uncalibrated heuristics, not probabilities.
  Brand-impersonation evidence is unavailable in M7. ML probability is reported
  separately and never enters the heuristic score. Missing evidence reduces
  coverage and can yield `score = null`; it is never treated as benign. See
  `docs/risk-assessment.md`.
- The PhiUSIIL CSV sits at the repo root and is gitignored. Verified shape:
  235,795 rows × 56 columns (`FILENAME`, `URL`, 53 features, `label`).
  **`0 = phishing`, `1 = legitimate`.** About 29 of the 53 features are page-content
  features that cannot be computed from the URL alone — see
  `docs/ml-feature-contract.md` before training.


## What PHISHGUARD is

An end-to-end phishing-defense platform: phishing detection, malicious-URL intelligence,
TLS certificate inspection, website security assessment, collaborative threat reporting,
and a Chrome extension. It is a multi-engine system, not a single classifier.

Intended stack (only the M0-M5B parts are installed so far):

- Next.js 16 + TypeScript + Tailwind CSS 4 + shadcn/ui; backend via Route Handlers
- Python/FastAPI ML service: pandas, NumPy, scikit-learn, XGBoost, SHAP
- Supabase Postgres + Supabase Auth; Node.js TLS for certificate inspection
- Google Safe Browsing, URLhaus, Certificate Transparency as external intel
- Chrome Manifest V3 extension; deploy to Vercel + Supabase + a Python host

Inspect the repo before changing versions; do not upgrade majors as a side effect of a feature.

## Domain rules an agent will get wrong

- **PhiUSIIL label mapping is inverted from intuition: `0 = Phishing`, `1 = Legitimate`.**
  Any flip here silently inverts the whole model and its metrics.
- Audit the dataset for duplicate rows and related-domain leakage **before** splitting;
  duplicates across train/test invalidate reported scores.
- Keep a held-out test set untouched. Use reproducible, stratified evaluation.
  Report accuracy, precision, recall, F1, ROC-AUC, and PR-AUC.
- Maintain an explicit **feature compatibility contract** between the ML service and the
  URL-analysis path. Never synthesize or backfill unavailable live features.
- Version model artifacts and preprocessing together; a model without its preprocessing
  version is not reproducible.
- **Keep ML inference separate from deterministic URL analysis.** Do not route deterministic
  checks (TLS, DNS, redirects, blocklists) through the model, or vice versa.

## Risk output semantics

Produce **three separate outputs**: threat likelihood, security posture, and evidence
confidence. Never collapse them into one score.

Every engine reports: `status`, `findings`, `evidence`, `source`, `duration`.

- **An unavailable or failed check is never "safe."** Propagate `unknown`/`error` distinctly;
  a timeout must not read as a clean result.
- Document the scoring formula. Do not double-count correlated signals (e.g. a blocklist hit
  and the same indicator-derived feature).

## URL scanner security invariants

The scanner fetches attacker-controlled URLs. Treat SSRF/DNS-rebinding/redirect abuse as the
primary threat:

- Only `http` and `https`; restrict ports.
- Reject `localhost`, private, reserved, link-local, and internal addresses — resolve DNS and
  validate the **resolved** IP, not just the hostname.
- **Revalidate every redirect destination** against the same rules.
- Enforce connection and total timeouts and a maximum response size.
- Never execute downloaded site code.
- Rate-limit scan endpoints.
- Test with controlled fixtures. **Never visit live malicious sites for a demo.**

## Data and secrets

- Schema changes go through migrations. Enable and test RLS; enforce user ownership.
- Service-role keys stay server-side only. Never commit secrets or real user data.
- Avoid persisting sensitive URL query parameters.

## Verification standard

A milestone is: inspect → state intended changes → implement one bounded feature →
add unit + integration tests → run lint/typecheck/build → fix regressions →
inspect the final diff → update docs → report **actual** output.

Do not claim success from code generation alone. Always label work as exactly one of
**Implemented / Tested / Integrated / Deployed / Verified in production**.
Do not start the next milestone while the current one has unresolved critical failures.

## Git safety

Never run destructively without explicit approval: `git reset --hard`, `git clean -fd`,
`git push --force`, destructive branch deletion. Never reset or push migrations against a
production database. Don't overwrite or revert user changes; inspect the diff first.

## Completion definition

Implementation, tests, integration, and observable behavior must all be verified before a
feature is called complete.
