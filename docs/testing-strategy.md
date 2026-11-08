# Testing strategy

## Current state (M0-M7)

| Suite | Tool | Files | Status |
|---|---|---|---|
| Contract parity | pytest + jsonschema | `packages/contracts/tests/test_parity.py` | 18 passing |
| TS validators | `node --test` (built in, no dependency) | `packages/contracts/tests/contracts.test.ts` | 9 passing |
| Analysis service | pytest + TestClient | `services/analysis/tests/` | 143 passing (M7) |
| ML service | pytest + TestClient | `services/ml/tests/` | 61 passing |

No test contacts a live target, a live malicious site, a live threat-intelligence provider or crt.sh.

## Layers

| Layer | Tool | Scope |
|---|---|---|
| Contract | pytest + jsonschema | fixture ↔ JSON Schema ↔ Pydantic |
| Unit (py) | pytest | engines, guard, risk scoring, features |
| Unit (ts) | `node --test` | validators, band logic, formatters |
| Integration | pytest + loopback fixture server | analysis ↔ ml over HTTP |
| Security | pytest | SSRF matrix, size/timeout, provider failure states, RLS with anon key |
| E2E | Playwright (P2) | scan → verdict render |
| Manual | checklist | extension, real browsers |

## Commands

```bash
bash scripts/verify.sh      # everything, in order
pnpm typecheck              # tsc --noEmit (web + contracts)
pnpm lint                   # eslint
pnpm test                   # node --test
bash scripts/lint-python.sh # ruff
bash scripts/test-python.sh # pytest per project
pnpm build                  # next build
```

Run a single Python test:

```bash
cd services/analysis && uv run pytest tests/test_health.py::test_health_reports_ok_and_versions
```

Run a single TS test file:

```bash
cd packages/contracts && node --test tests/contracts.test.ts
```

## Rules

1. **Fixtures are canonical.** Every new wire shape gets a fixture in
   `packages/contracts/fixtures/` and a case in `tests/test_parity.py`.
2. **Parity is mandatory.** A model/schema mismatch fails CI. This already caught
   a real divergence (`Finding.detail` was nullable in Python, not in schema).
3. **No network in unit tests.** Upstream APIs and crt.sh are stubbed with
   `httpx.MockTransport`; scanner behaviour is injected or monkeypatched. M7
   risk tests use synthetic engine reports only.
4. **Risk tests are deterministic.** Assert exact factor contributions, reason
   codes, band boundaries, coverage thresholds and ML separation; do not assert
   calibrated probabilities.
5. **Loopback is test-only.** The scanner may reach `127.0.0.1` only when
   `SCANNER_ALLOW_LOOPBACK_FOR_TESTS=1`, and settings refuse that value in
   production.
5. **Never assert on flaky live services.** If a test needs an API key, it is
   skipped with an explicit reason.
6. A bug fix adds a regression test.

## Verification discipline

- `scripts/verify.sh` is the only definition of "green".
- Report exact command output; do not paraphrase.
- Order matters: dependency sync → typecheck → lint → tests → build.
- If a step fails, stop and fix; never continue to declare success.

## Gaps until later milestones

- No exhaustive SSRF matrix yet; the M4/M6 scanner has targeted SSRF, port,
  credential, TLS-failure and redirect tests.
- No RLS tests (M8; blocked on a hosted Supabase project).
- No browser/extension E2E (M10/M11).
- Coverage measurement is not configured; correctness is enforced by parity and
  behaviour tests instead.
