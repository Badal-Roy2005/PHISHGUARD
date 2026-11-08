-- PHISHGUARD M8: persistence schema.
-- Forward-only migration. Never edit after it has been applied.

create extension if not exists pgcrypto with schema extensions;

create type public.app_role as enum ('user', 'moderator', 'admin');
create type public.scan_status as enum ('queued', 'running', 'complete', 'partial', 'failed');
create type public.risk_band as enum (
  'low',
  'guarded',
  'suspicious',
  'high',
  'critical',
  'insufficient_evidence'
);

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  display_name text,
  role public.app_role not null default 'user',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint profiles_email_length check (
    email is null or char_length(email) between 3 and 320
  ),
  constraint profiles_display_name_length check (
    display_name is null or char_length(display_name) between 1 and 80
  )
);

create unique index profiles_email_key
  on public.profiles (lower(email))
  where email is not null;

comment on table public.profiles is
  'Application profile, 1:1 with auth.users. role is server-managed.';
comment on column public.profiles.role is
  'Least-privilege role. Clients cannot update this column.';

create table public.scans (
  id uuid primary key default extensions.gen_random_uuid(),
  user_id uuid references public.profiles (id) on delete cascade,
  url text not null,
  normalized_url text not null,
  url_hash text not null,
  status public.scan_status not null,
  risk_score integer,
  risk_band public.risk_band,
  confidence numeric(5, 4),
  policy_version text,
  result jsonb,
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  expires_at timestamptz,
  inserted_at timestamptz not null default now(),
  constraint scans_url_length check (char_length(url) between 8 and 2048),
  constraint scans_normalized_url_length check (
    char_length(normalized_url) between 8 and 2048
  ),
  constraint scans_url_hash_format check (url_hash ~ '^[0-9a-f]{64}$'),
  constraint scans_risk_score_range check (
    risk_score is null or risk_score between 0 and 100
  ),
  constraint scans_confidence_range check (
    confidence is null or confidence between 0 and 1
  ),
  constraint scans_policy_version_length check (
    policy_version is null or char_length(policy_version) between 1 and 64
  ),
  constraint scans_result_required check (
    status in ('queued', 'running') or result is not null
  ),
  constraint scans_terminal_risk check (
    status not in ('complete', 'partial')
    or (risk_band is not null and policy_version is not null)
  ),
  constraint scans_timestamp_order check (
    (completed_at is null or completed_at >= created_at)
    and (expires_at is null or expires_at >= created_at)
  )
);

comment on table public.scans is
  'Immutable scan/assessment records. Only the service role writes rows.';
comment on column public.scans.result is
  'Contract-validated ScanResult. Evidence is already sanitized upstream.';
comment on column public.scans.url_hash is
  'SHA-256 of normalized_url, lowercase hex. Used for dedupe/lookup only.';
comment on column public.scans.expires_at is
  'Retention boundary for a future service-role cleanup job.';

create index scans_user_id_created_at_idx
  on public.scans (user_id, created_at desc);

create index scans_url_hash_idx
  on public.scans (url_hash);

create index scans_expires_at_idx
  on public.scans (expires_at)
  where expires_at is not null;

-- Backfill profiles for users that existed before this migration.
insert into public.profiles (id, email)
select id, email
from auth.users
on conflict (id) do nothing;
