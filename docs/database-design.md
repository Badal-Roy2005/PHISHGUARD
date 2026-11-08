# Database design

Status: **design only — no migrations exist yet.** M8 creates
`supabase/migrations/`. Nothing here has been applied anywhere.

Verified constraint: this machine has **no Docker, no Podman and no local
Postgres**, so `supabase start` cannot run. Migrations can only be applied and
tested against a **hosted Supabase project**.

## Tables

### `profiles`
1:1 with `auth.users`.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | references `auth.users(id)` on delete cascade |
| `email` | text | |
| `role` | text | `user` / `moderator` / `admin`, default `user`, **immutable by the user** |
| `created_at` | timestamptz | default `now()` |

### `scans`

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | |
| `user_id` | uuid null | null = anonymous scan |
| `url` | text | raw submitted URL |
| `normalized_url` | text | from `normalize_url()` |
| `url_hash` | text | SHA-256 of normalized URL, for dedupe/intel cache |
| `status` | text | `queued|running|complete|partial|failed` |
| `risk_score` | int null | 0–100 |
| `risk_band` | text | includes `insufficient_evidence` |
| `confidence` | numeric | 0–1 |
| `result` | jsonb | full `ScanResult` (contract-validated before write) |
| `created_at` / `expires_at` | timestamptz | retention policy applied by a job |

### `threat_reports`

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | |
| `reporter_id` | uuid | `auth.users(id)` |
| `url`, `url_hash` | text | |
| `category` | text | mirrors `ReportCategory` |
| `description` | text | 10–2000 chars, stored as data |
| `status` | text | `pending|verified|rejected` |
| `evidence` | jsonb null | user-supplied, never rendered as HTML |
| `created_at` | timestamptz | |

Unique `(reporter_id, url_hash)` to stop duplicate spam from one account.

### `report_votes`

`id`, `report_id`, `user_id`, `vote` (`-1|1`), unique `(report_id, user_id)`.

### `intel_cache`

Server-only. PK `(url_hash, source)`; `verdict`, `raw jsonb`, `fetched_at`,
`expires_at`. Never exposed to clients.

## Indexes

- `scans(user_id, created_at desc)`
- `scans(url_hash)`
- `threat_reports(status, created_at desc)`
- `threat_reports(url_hash)`
- `intel_cache(expires_at)`

## Row Level Security

All tables: `ENABLE ROW LEVEL SECURITY` **and** `FORCE ROW LEVEL SECURITY`
for client roles.

| Table | anon | authenticated |
|---|---|---|
| `profiles` | none | select/update **own row only**; `role` cannot change |
| `scans` | none | select own (`user_id = auth.uid()`) |
| `threat_reports` | select `status = 'verified'` | select all; insert own; update own while `pending`; moderators update `status` |
| `report_votes` | none | insert/select own |
| `intel_cache` | none | none |

**No client insert policy exists for `scans`.** Only the service role writes scan
records. This is intentional: a client must never be able to forge a verdict.

## Functions and triggers

- `handle_new_user()` — `security definer`; creates the `profiles` row.
- `set_updated_at()` — maintained `updated_at` where applicable.
- `report_vote_count` — aggregate used by the public report list.

## Migration plan

```
supabase/migrations/0001_schema.sql     tables, enums, indexes
supabase/migrations/0002_rls.sql        policies
supabase/migrations/0003_functions.sql  triggers, aggregations
```

Forward-only. Production corrections ship as `0004_*.sql`; never edit an applied
migration. Never `supabase db reset` against a hosted project.

## Verification requirements (M8)

1. Anon key cannot read another user's `scans` (expect 0 rows).
2. Authenticated user cannot escalate `profiles.role`.
3. Non-owner cannot update a `threat_reports` row.
4. Service role bypasses RLS (expected, documented).
5. `intel_cache` is unreachable with the anon key.
