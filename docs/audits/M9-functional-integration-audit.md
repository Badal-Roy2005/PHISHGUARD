# M9 Functional Integration Audit Report (Corrected)

**Date:** 2026-11-09
**Commit under audit:** `d952c98 feat: implement M9 scan dashboard and results UI`
**Method:** Runtime HTTP tests against a live analysis service, a live Next.js
(dev and production `next start`) server, and the hosted Supabase project;
plus source inspection. No browser automation was available.
**Overall status:** ⚠️ **NOT PASSED** — one blocking integration defect
(authenticated scans are never persisted by the web route).

This report supersedes the earlier version of this file, which contained
claims that were not supported by runtime evidence. Section 0 records each
correction.

> **Update — M9.1 (2026-11-09):** defect **D1 is FIXED and verified against the
> hosted Supabase project**. Authenticated web scans now persist exactly one row
> owned by the verified session user; anonymous scans persist nothing; a forged
> body id or identity header cannot impersonate another user. See
> [`M9.1-authenticated-persistence-fix.md`](./M9.1-authenticated-persistence-fix.md)
> for the implementation, tests, and database evidence, and for the updated
> verdicts. Sections below record the state **as audited at `d952c98`**, before
> the fix; statements about `/api/scan` being proxy-protected and about
> authenticated scans not persisting are historical.

---

## Status legend

| Status | Meaning |
| --- | --- |
| **VERIFIED** | Directly exercised at runtime; command and observed result are recorded here. |
| **IMPLEMENTED** | Code exists and was read; runtime behavior not proven in this pass. |
| **NOT TESTED** | A required test was not performed. |
| **BLOCKED** | An external dependency/config prevents the test. |
| **NOT IMPLEMENTED** | The capability does not exist in the code. |

---

## 0. Corrections to the previous report

| Previous claim | Actual finding | Evidence |
| --- | --- | --- |
| "✅ PASSED — Ready for M9 Integration" / "ready for production integration" | **Not passed.** Authenticated web scans return 200 but persist **zero** rows. | §5.1, §6.1 |
| "Authenticated scan would persist; code path implemented correctly" | **False.** `app/api/scan/route.ts` passes `userId = ""`, so no `X-Authenticated-User-Id` header is sent and the analysis service persists nothing. | §5.1, §13 D1 |
| `apps/web/lib/supabase/proxy.ts` was modified to remove `/api/scan` from protected paths ("public endpoint") | That edit was made **during the previous audit run** to enable anonymous testing and is **not** part of `HEAD`. It was reverted with `git checkout -- apps/web/lib/supabase/proxy.ts`. At `HEAD`, `/api/scan` **is** protected. | `git diff` clean; §7 |
| "Rate-limited state handled" | **Not implemented.** 12 concurrent scans produced 12×200 and 0×429. `RATE_LIMIT_*` settings are defined but unused. | §8, D4 |
| "Desktop layout / Mobile responsiveness / Browser console errors: ✅" | No browser, Playwright, or Chromium was installed. These were **not** browser-tested; only HTTP responses and source were inspected. | §14 |
| "SSRF/DNS rebinding protection ✅ Working" (implying rebinding was exercised) | Separate the claims: private/link-local/loopback rejection is **VERIFIED**; code-level DNS pinning is **IMPLEMENTED**; an actual rebinding attack was **NOT TESTED**. | §9 |
| "ML Probability: `null` / `unavailable`" | The stored value is `null`, but `MLProbabilityCard` returns `null` (renders nothing). It does **not** display "unavailable". Only the engine table shows `ml = unknown` with an error string. | §10, D2 |
| "Nine components" in the changed-file list | There are **12** component files: 2 top-level + 10 under `components/scan/`. | §16 Appendix |
| Anonymous `POST /api/scan` validation/SSRF rows | With `HEAD` code, anonymous `POST /api/scan` is **401**, so those web-layer results are not reproducible anonymously; the SSRF results were obtained by calling `/internal/analyze` directly. | §5.3, §9 |

---

## 1. Scope

M9 is the scan dashboard and results UI. This audit covers:

- the web scan submission route and scan page,
- the scan detail page and results components,
- authentication/authorization at the proxy and route-handler boundary,
- persistence of scans (M8) and RLS enforced by Supabase,
- rate limiting,
- SSRF/DNS controls as surfaced through the analysis service,
- ML unavailability display semantics,
- build, typecheck, lint, and test suites,
- client-bundle secret exposure.

Out of scope: Supabase migrations themselves (authoring), the Chrome extension
(M10), community reporting, and browser visual/responsive QA (see §14).

---

## 2. Verification environment

| Component | Detail |
| --- | --- |
| Node | 26.x |
| Next.js | 16.4.5 (Turbopack); also ran production `next start` |
| Analysis service | `uv run uvicorn app.main:app --port 8000`, `PERSISTENCE=supabase` |
| ML service | `uv run uvicorn app.main:app --port 8001` |
| Supabase | hosted project `cghilkrgdvppqjykcbis.supabase.co` |
| Database baseline | `scans` empty; one pre-existing profile before and after testing |

The analysis service reads `os.environ` only (it does not load `.env.local`);
`PERSISTENCE` defaults to `memory`. It was started with the environment exported
from `apps/web/.env.local` plus `PERSISTENCE=supabase` and
`INTERNAL_SERVICE_TOKEN=$ANALYSIS_SERVICE_TOKEN`.

Two disposable Supabase users (A and B) were created via the Admin API, used for
the tests, then deleted along with every test scan row. Post-cleanup state:
`scans: []`, exactly the original profile remaining (§15).

---

## 3. Static quality gates

| Command | Result |
| --- | --- |
| `pnpm test` | **9 passed**, exit 0 (only `packages/contracts/tests/contracts.test.ts`) |
| `bash scripts/test-python.sh` | **232 passed** (contracts 18, analysis 153, ml 61), exit 0 |
| `pnpm typecheck` | exit 0 |
| `pnpm lint` | exit 0 |
| `bash scripts/lint-python.sh` | exit 0 |
| `pnpm build` | **exit 0**; routes `/`, `/scan`, `/scan/[id]`, `/account`, `/login`, `/api/scan`, `/api/scans`, `/api/scans/[id]` compiled |

All gates above are **VERIFIED**.

---

## 4. Service readiness

| Service | Check | Result | Status |
| --- | --- | --- | --- |
| Analysis | `GET /health` | `status=ok`, `checks.persistence=supabase` | VERIFIED |
| ML | `GET /health` | `model=ready`, `feature_contract=present` | VERIFIED |
| Web (dev) | `GET /scan` | 200 | VERIFIED |
| Web (production `next start`) | `GET /`, `/scan`, `/login` | 200, 200, 200 | VERIFIED |
| Web (production) | `GET /account` unauthenticated | 307 → login | VERIFIED |
| Web (production) | `GET /api/scans` unauthenticated | 401 | VERIFIED |

Note: the web tier does **not** call the ML service during a scan. ML inference
is explicitly "not wired into scan orchestration yet"; the `ml` engine is
reported as `unknown`.

---

## 5. Functional scan flow

### 5.1 Authenticated web scan — **FAIL (blocking)**

Signed in as User A (SSR cookie from `@supabase/ssr` `signInWithPassword`).

| Step | Observed |
| --- | --- |
| `GET /api/scans` as A (before) | 200, 0 scans |
| `POST /api/scan` as A, body `{url:"https://example.com", options:{...}}` | **200**, `status=partial`, `scan_id` returned |
| rows in `scans` after the web scan | **0 (delta 0)** |
| `GET /api/scans` as A (after) | 200, **0 scans** |

So the web scan returns a result but does **not** persist it. Root cause: the
route handler passes an empty user id.

`apps/web/app/api/scan/route.ts:48-54`:

```ts
const requestId = request.headers.get("X-Request-ID") ?? crypto.randomUUID();

const result = await callAnalysis(
  body,
  "",          // <-- user id is always empty
  requestId,
);
```

`apps/web/lib/analysis.ts` omits `X-Authenticated-User-Id` when `userId` is
falsy, and `services/analysis/app/main.py` persists only when that header is
present. Therefore authenticated scans are never persisted by the web path.

There is existing, **unused** code that does this correctly:
`apps/web/lib/api/scan.ts` `createScanResponse()` calls `getUser()` and passes
`user.id`. It is not imported anywhere (verified by search).

**Status: VERIFIED (defect).** — **Resolved in M9.1**; see
[`M9.1-authenticated-persistence-fix.md`](./M9.1-authenticated-persistence-fix.md).

### 5.2 Direct analysis call with a user header — **PASS**

```
POST http://localhost:8000/internal/analyze
  X-Service-Token: <valid>
  X-Authenticated-User-Id: <User A id>
  body: {"url":"https://example.com", ...}
```

- Response: **200**, `status=partial`, `scan_id` returned.
- `scans` delta: **+1**, `user_id = A`, `user_id = null` count 0.

**Status: VERIFIED.**

### 5.3 Anonymous direct analysis — **PASS (not persisted)**

Same call without `X-Authenticated-User-Id`:

- Response **200**, `scan_id` returned.
- `scans` delta: **0** (by design, no owner).

Anonymous **web** scans are not reachable at `HEAD`: `POST /api/scan` and
`GET /api/scans` both return **401** (`{"code":"unauthorized"}`), because the
proxy protects them. (**Superseded in M9.1:** `/api/scan` is now public so
anonymous scans are reachable and still never persist; `/api/scans*` remains
protected.)

**Status: VERIFIED.**

---

## 6. Persistence and RLS (M8)

### 6.1 Schema presence

Queried through the Supabase REST API with the server-only service key (key
value never printed):

| Object | Result |
| --- | --- |
| `profiles` | 200, table present |
| `scans` | 200, table present |
| `scan_reports` | 404 `PGRST205` — table does **not** exist (not part of M8 schema) |

**Status: VERIFIED.**

### 6.2 Row-level security with real roles

Exercised through PostgREST using real user JWTs (password grant) and the anon
key — not mocks.

| Acted as | Operation | Result | Expected |
| --- | --- | --- | --- |
| anon | `GET /scans` | **401** `42501 permission denied` | denied |
| A | `GET /scans` | 200, own row only | own only |
| B | `GET /scans` | 200, `[]` | no data |
| B | `GET /scans?id=eq.<A row>` | 200, `[]` | no data |
| A | `POST /scans` (forged row) | **403** `42501` | denied |
| anon | `GET /profiles` | **401** `42501` | denied |
| A | `GET /profiles` | 200, own row only | own only |
| A | `PATCH /profiles` display_name | 200 | allowed |
| A | `PATCH /profiles` role=admin | **403** `42501` | denied |

RLS therefore enforces ownership and least privilege for scans and profiles at
the database layer, independently of the app bug in §5.1.

**Status: VERIFIED.**

### 6.3 pgTAP suite

- `bash scripts/test-rls.sh` → "RLS_TEST_DB_URL is not set; skipping…", exit 0.
- `psql` is not installed.

The repository pgTAP suite (`supabase/tests/m8_rls.sql`, `plan(14)`) was **not**
executed. The real-role REST tests in §6.2 are the substitute evidence.

**Status: BLOCKED** (no `RLS_TEST_DB_URL`, no `psql`).

---

## 7. Authentication and authorization

| Check | Result | Status |
| --- | --- | --- |
| `POST /api/scan` unauthenticated (HEAD) | 401 `unauthorized` | VERIFIED (superseded: public in M9.1, still no persistence) |
| `GET /api/scans` unauthenticated (HEAD) | 401 `unauthorized` | VERIFIED |
| `GET /api/scans/<A>` as A | 200 `{scan:{...}}` | VERIFIED |
| `GET /api/scans/<A>` as B | 404 `{code:"not_found"}` | VERIFIED |
| `GET /scan/<A>` (detail page) as A | 200, 62,497 bytes, contains "Engine Reports" and "Heuristic Risk Score" | VERIFIED |
| `GET /scan/<A>` as B | 404 | VERIFIED |
| `/account` unauthenticated | 307 → `/login` | VERIFIED |

`apps/web/lib/supabase/proxy.ts` at `HEAD` protects `/account`,
`pathname === "/api/scan"`, and `/api/scans*`. The previous audit's deletion of
the `/api/scan` line was reverted and must not be reintroduced.
(Historical — **M9.1 intentionally makes `/api/scan` public** so anonymous
scanning is reachable; identity is still verified in the route via
`supabase.auth.getUser()`, and `/account` + `/api/scans*` stay protected.)

**Status: VERIFIED.**

---

## 8. Rate limiting — **NOT IMPLEMENTED**

`RATE_LIMIT_ANON_PER_MIN` and `RATE_LIMIT_USER_PER_MIN` are defined in
`services/analysis/app/settings.py` but no code reads them for enforcement.

Test: 12 concurrent `POST /internal/analyze` (`RATE_LIMIT_ANON_PER_MIN=10`).

```
rate-limit burst (12 concurrent): {"200":12}
elapsed_ms: 59
```

No `429` and no throttling. The web `/api/scan` route has no rate limit either.

**Status: NOT IMPLEMENTED** (runtime confirmed).

---

## 9. SSRF / DNS controls (three separate claims)

### 9.1 Prohibited-address rejection — **VERIFIED**

Direct `POST /internal/analyze` for each URL, `include_intel=false`:

| URL | HTTP engine result |
| --- | --- |
| `http://127.0.0.1/` | `unknown` — "DNS validation blocked: All DNS answers rejected… `['127.0.0.1',…]`" |
| `http://169.254.169.254/latest/meta-data/` | `unknown` — blocked `['169.254.169.254',…]` |
| `http://localtest.me/` (resolves to loopback) | `unknown` — blocked `['::1',…,'127.0.0.1',…]` |
| `http://[::1]/` | `unknown` — blocked `['::1',…]` |
| `http://192.168.1.1/` | `unknown` — blocked `['192.168.1.1',…]` |

In every case `risk.band = insufficient_evidence`; the blocked fetch is not
reported as safe.

### 9.2 DNS-resolution validation + IP pinning — **IMPLEMENTED**

Source inspection of `services/analysis/scanner.py`:

- `PinnedDNSResolver.resolve_and_validate()` resolves once via
  `socket.getaddrinfo`, rejects the resolution if any address is prohibited
  (`validate_dns_answers` fails on mixed public/private answers), and stores the
  validated IPs.
- `PinnedHTTPTransport` connects with
  `socket.create_connection((pinned_ip, port_int))`, i.e. it connects to the
  validated IP rather than re-resolving the hostname.

This is a sound design against rebinding, but it was verified only by reading
the code and by the unit test `test_validate_dns_answers_mixed`.

### 9.3 Actual DNS-rebinding attack simulation — **NOT TESTED**

No test drives a hostname whose DNS answer changes between the validation and
connection steps. Only static mixed-answer validation is covered.

**Status:** 9.1 VERIFIED, 9.2 IMPLEMENTED, 9.3 NOT TESTED.

---

## 10. ML unavailability semantics

Stored scan result observed for the transient test scan:

- `risk.model_probability` → `null`
- `engines.ml` → `{status:"unknown", source:"not-implemented", error:"ML inference is not wired into scan orchestration yet; probability is separate.", findings:[], duration_ms:0}`

UI behavior:

- `apps/web/components/scan/MLProbabilityCard.tsx:6` — `if (!risk.model_probability) return null;`
  The ML probability card renders **nothing** when the value is absent. It does
  **not** say "unavailable".
- `apps/web/components/scan/EngineReportsSection.tsx` — the engine table does
  render `ml` with status `Unknown` and the error text, so the absence is
  visible somewhere on the page.

The deterministic heuristic risk score and band are computed independently and
are not affected by the missing ML probability. `model_probability` is never
merged into the heuristic score.

**Status:** data separation VERIFIED; explicit "unavailable" presentation
**NOT IMPLEMENTED** (defect D2).

---

## 11. Results rendering and navigation

| Check | Result | Status |
| --- | --- | --- |
| Detail page renders risk score/band, engine reports, explanation, evidence for owner | 200, 62,497 bytes, expected headings present | VERIFIED |
| Non-owner detail page | 404 | VERIFIED |
| Inline result after a web scan | Rendered by `ScanResultInline` | IMPLEMENTED (not browser-verified) |
| Link from `/account` history to `/scan/[id]` | **None** — list items are plain `<li>`/`<span>`, not links | NOT IMPLEMENTED (defect D3) |
| Link from inline result to `/scan/[id]` | **None**; only the `status === "queued"` branch calls `router.push('/scan/<id>')` | NOT IMPLEMENTED (D3) |

Because authenticated web scans were not persisted at `HEAD` (D1, since fixed —
see M9.1) and the analysis service returns `partial` (not `queued`), the queued
redirect is not exercised in practice, and there is no other path from a result
to its detail page. D3 is therefore still open: the detail page is reachable by
URL now, but not by a link.

---

## 12. Secret exposure

| Check | Result |
| --- | --- |
| `process.env` referenced in any `"use client"` file | **none** |
| `SUPABASE_SERVICE_ROLE_KEY` referenced anywhere in `apps/web` | **none** |
| Server-only token used by web | only `apps/web/lib/analysis.ts` (`ANALYSIS_SERVICE_TOKEN`) |
| `SUPABASE_SERVICE_ROLE_KEY` value in `apps/web/.next/static` | **0 files** |
| `ANALYSIS_SERVICE_TOKEN`, `ML_SERVICE_TOKEN` values in `.next/static` | **0 files** |

Secret-value scans used `grep -rlF` and printed only file counts, never values.

**Status: VERIFIED.**

---

## 13. Confirmed defects (not fixed in this audit)

No application code was changed. Proposed fixes are recorded for a follow-up
change.

### D1 — Authenticated scans are never persisted (blocking) — **RESOLVED in M9.1**

- **Where:** `apps/web/app/api/scan/route.ts:48-54`
- **What:** `callAnalysis(body, "", requestId)` — user id is hard-coded empty.
- **Effect:** every authenticated web scan returns 200 but writes 0 rows;
  scan history and the detail page stay empty. The scan→persist→view loop for
  M9 is broken.
- **Proposed fix:** call `createClient()` and `supabase.auth.getUser()`, pass
  `user.id`; or wire the existing `createScanResponse()` from
  `apps/web/lib/api/scan.ts` (already does `getUser()` + `validateScanRequest`).
  Add a regression test asserting a row is written for an authenticated scan.
- **Severity:** Critical.
- **Resolution (M9.1):** `apps/web/app/api/scan/route.ts` now calls
  `createScanResponse()` with a `getVerifiedUser()` built on the server Supabase
  client; anonymous callers pass `null` and are not persisted. Verified against
  hosted Supabase: A → 1 row owned by A, anonymous → 0, forged body id → 400,
  forged header → row still owned by verified A. See
  [`M9.1-authenticated-persistence-fix.md`](./M9.1-authenticated-persistence-fix.md).

### D2 — ML probability is hidden rather than shown as unavailable

- **Where:** `apps/web/components/scan/MLProbabilityCard.tsx:6`
- **What:** `if (!risk.model_probability) return null;`
- **Effect:** the required "ML unavailable / not wired" state is invisible in
  the summary area. It appears only in the engine table.
- **Proposed fix:** render a card with "ML probability: unavailable" and the
  `engines.ml.error`, clearly separated from the heuristic score.
- **Severity:** Medium.

### D3 — No navigation to scan detail

- **Where:** `apps/web/app/account/page.tsx:80-94`;
  `apps/web/app/scan/page.tsx:97-98`
- **What:** history list items and inline results are not links to
  `/scan/[id]`.
- **Effect:** users cannot open a persisted scan's detail page from the UI.
- **Proposed fix:** wrap the history row and add a "View full report" link to
  `/scan/<id>` when the scan is persisted.
- **Severity:** Medium.

### D4 — No rate limiting on scan endpoints

- **Where:** `services/analysis/app/settings.py` (settings only);
  `apps/web/app/api/scan/route.ts`
- **Effect:** unbounded scan submission; 12/12 concurrent requests accepted.
- **Proposed fix:** enforce per-user/per-IP limits before calling the scanner
  (token bucket at the web route and/or the analysis service), return `429`.
- **Severity:** High for public deployment.

### D5 — Unchecked JSON cast in the scan page

- **Where:** `apps/web/app/scan/page.tsx:37-40`
- **What:** `JSON.parse(text) as ScanResponse` with no runtime validation.
- **Effect:** a malformed upstream body is trusted as a `ScanResponse`; the
  subsequent `isScanResult` check only tests for `"risk" in data`.
- **Proposed fix:** validate against `@phishguard/contracts` before use.
- **Severity:** Low/Medium.

---

## 14. Not tested / blocked

| Item | Reason | Status |
| --- | --- | --- |
| Browser visual, responsive, and console checks | No Playwright/Chromium/system Chrome installed | BLOCKED |
| pgTAP `supabase/tests/m8_rls.sql` | `RLS_TEST_DB_URL` unset; `psql` absent | BLOCKED |
| Actual DNS-rebinding attack | No dynamic-DNS test harness | NOT TESTED |
| End-to-end web persistence | Was prevented by D1; **retested and PASSED in M9.1** (`M9.1-authenticated-persistence-fix.md` §5) | VERIFIED (M9.1) |
| `scan_reports` / community reporting | Table and feature do not exist | NOT IMPLEMENTED |
| Threat-intel live verdicts | No provider keys in this environment; treated as `skipped`/`unavailable` | NOT TESTED |

---

## 15. Test-data cleanup

Two disposable users were created via the Supabase Admin API and signed in with
`@supabase/ssr`. After testing:

- test scan rows for A and B deleted (`204`),
- users A and B deleted (`200`),
- final state: `scans: []`, `profiles: [<original profile>]`.

Audit artifacts (temporary `.env.local` copies in the Python services, session
scripts, cookie jars, user JSON) were removed. The only remaining untracked
files are `apps/web/AGENTS.md` (auto-generated by `next dev`) and `docs/audits/`.

---

## 16. Verdicts

> **M9.1 update:** D1 is fixed and verified, so §16.2 and §16.3 change. The
> authoritative post-fix verdicts are in
> [`M9.1-authenticated-persistence-fix.md`](./M9.1-authenticated-persistence-fix.md)
> §8: M9 functional acceptance **PASSED for the scan→persist→detail loop**;
> frontend readiness **implemented, not complete** (D2/D3); public deployment
> **NOT READY** (D4). The text below is the pre-fix audit.

### 16.1 Frontend implementation readiness — **IMPLEMENTED, NOT COMPLETE**

The pages, components, contracts integration, and build are in place and the
production build serves `/`, `/scan`, `/login` at 200. But the frontend cannot
be called ready while D1 breaks the scan→history→detail loop, D2 hides the
required ML-unavailable state, and D3 leaves no route to the detail page. No
browser-level visual/responsive verification exists.

### 16.2 M9 functional acceptance — **NOT PASSED** (pre-fix; now passed, see M9.1)

The core authenticated flow fails: `POST /api/scan` returns 200 but persists
zero rows, so history and detail rendering cannot be reached from a web scan.
The direct-service persistence path works; the web integration does not.

### 16.3 M8 persistence readiness — **PARTIALLY VERIFIED** (pre-fix; web path now verified, see M9.1)

Schema exists on the hosted project; scan persistence works when a user id is
supplied; RLS enforces ownership and least privilege for scans and profiles
with real roles (VERIFIED). Remaining gaps: the web route never supplies the
user id (D1), and the pgTAP suite is BLOCKED.

### 16.4 Public deployment readiness — **NOT READY**

Blocking/high-severity items remain: authenticated scans are not persisted (D1),
rate limiting is absent (D4), and browser/visual QA and the pgTAP suite are
unrun. Client bundles show no server-secret leakage, which is a positive, but
it does not offset the functional and abuse-resistance gaps.

**M9.1 update:** D1 no longer applies. Rate limiting (D4) is now the primary
blocker because `/api/scan` is public, and browser QA + pgTAP remain unrun.

---

## Appendix A — Representative commands

```bash
# Static gates
pnpm test                                  # 9 passed, exit 0
bash scripts/test-python.sh                # 232 passed, exit 0
pnpm typecheck                             # exit 0
pnpm lint                                  # exit 0
bash scripts/lint-python.sh                # exit 0
pnpm build                                 # exit 0

# Services
cd services/analysis && PERSISTENCE=supabase uv run uvicorn app.main:app --port 8000
cd services/ml      && uv run uvicorn app.main:app --port 8001
cd apps/web         && pnpm start          # production server

# Health
curl -s http://localhost:8000/health       # persistence=supabase
curl -s http://localhost:8001/health       # model=ready

# RLS suite (skipped)
bash scripts/test-rls.sh                   # RLS_TEST_DB_URL is not set; skipping

# Rate-limit probe (summary)
# 12 concurrent POST /internal/analyze -> {"200":12}
```

**M9.1 (post-fix)** full-gate command and results:

```bash
bash scripts/verify.sh                     # VERIFY_EXIT=0
pnpm --filter @phishguard/web test         # 7 passed, 1 skipped (live test gated by M9_INTEGRATION=1)
cd apps/web && M9_INTEGRATION=1 node --test tests/persistence.integration.test.ts   # 1 passed
```

## Appendix B — Files inspected

- `apps/web/app/api/scan/route.ts` (D1)
- `apps/web/app/api/scans/route.ts`
- `apps/web/app/api/scans/[id]/route.ts`
- `apps/web/app/scan/page.tsx` (D5, D3)
- `apps/web/app/scan/[id]/page.tsx`
- `apps/web/app/account/page.tsx` (D3)
- `apps/web/app/login/actions.ts`
- `apps/web/components/ScanResultDetail.tsx`
- `apps/web/components/ScanResultInline.tsx`
- `apps/web/components/scan/*.tsx` (12 component files total)
- `apps/web/components/scan/MLProbabilityCard.tsx` (D2)
- `apps/web/components/scan/EngineReportsSection.tsx`
- `apps/web/lib/analysis.ts`
- `apps/web/lib/api/scan.ts` (unused correct path)
- `apps/web/lib/supabase/proxy.ts` (reverted to HEAD)
- `apps/web/lib/supabase/server.ts`
- `services/analysis/app/main.py`
- `services/analysis/app/settings.py` (D4)
- `services/analysis/persistence.py`
- `services/analysis/scanner.py`
- `supabase/migrations/20261109000100_m8_schema.sql`
- `supabase/migrations/20261109000200_m8_functions.sql`
- `supabase/migrations/20261109000300_m8_rls.sql`
- `supabase/tests/m8_rls.sql`
- `scripts/test-rls.sh`, `scripts/test-python.sh`, `scripts/verify.sh`
