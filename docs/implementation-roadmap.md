# Implementation roadmap

Deadline: **10 November 2026**. M0 and M1 are complete.

## Milestones

| M | Scope | Depends on | State |
|---|---|---|---|
| M0 | Repository and environment foundation | — | done |
| M1 | Shared types and API contracts | M0 | done |
| M2 | ML training and inference | M1, dataset | next |
| M3 | URL analysis engine | M1 | queued |
| M4 | Isolated scanner + SSRF protection | M3 | queued |
| M5 | Threat intelligence | M4 | queued |
| M6 | TLS, CT, HTTP assessment | M4 | queued |
| M7 | Risk assessment and explainability | M2, M3, M5, M6 | queued |
| M8 | Supabase persistence and auth | M1 | queued (needs hosted project) |
| M9 | Next.js frontend | M7, M8 | queued |
| M10 | Chrome extension | M9 | queued |
| M11 | End-to-end testing | M2–M10 | queued |
| M12 | Deployment and release | M11 | queued |

## Parallelism

```
M0 → M1 ─┬─► M2 ──────────────────┐
         ├─► M3 → M4 ─┬─► M5 ─────┤
         │            └─► M6 ─────┤
         ├─► M8 (migrations) ─────┤
         └──────────► M9 shell ───┴─► M7 → M9 finish → M10 → M11 → M12
```

Must stay sequential:

- M0 → M1 (nothing can be built against an unfrozen contract).
- M3 → M4 (guard exists before any fetch).
- M4 → M5/M6 (all egress uses the guard).
- M2 + M3 + M5 + M6 → M7 (scoring needs engines).
- M7 → M9 finish (UI renders a real assessment).
- everything → M11 → M12.

Parallelizable: M2 ∥ M3 after M1; M5 ∥ M6 after M4; M8 migration authoring ∥ M2–M7;
M9 layout shell ∥ backend work.

## Per-milestone template

Each milestone must record: objective, dependencies, files created, files modified,
implementation details, API contracts touched, database changes, required tests,
acceptance criteria, rollback.

Rollback is always `git revert <sha>` or deleting the branch. Destructive git is
forbidden (see `AGENTS.md`).

## M2 notes (next)

- Confirm 235,795 rows × 53 features + `label`; class counts 100,945 / 134,850.
- Leakage audit before splitting: exact duplicates, normalized-URL duplicates,
  cross-class registrable-domain overlap.
- Stratified 70/15/15, fixed seed. LogReg baseline + XGBoost; RF only if time.
- Persist `model.joblib`, `preprocessor.joblib`, `feature_contract.json`,
  `metrics.json`, `MODEL_CARD.md`, checksums.
- Do not copy the deck's metrics. Report measured values.

## Cannot realistically ship by 10 Nov 2026

- Full leakage audit depth (near-duplicate clustering, temporal checks).
- Three-model comparison with calibration.
- Certificate Transparency with caching and rate-limit handling.
- Verified RLS suite (no Docker/Podman/Postgres locally; needs a hosted project).
- Community moderation UI.
- Chrome Web Store packaging.
- Observability, autoscaling, CI/CD autodeploy.
- Continuous monitoring, brand impersonation, SIEM/email (deck "future scope").
