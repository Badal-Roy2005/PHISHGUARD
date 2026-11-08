-- PHISHGUARD M8: least-privilege grants and row-level security.
--
-- Clients may only read their own profile and scans. Only the service role may
-- insert/update/delete scans, so a browser can never forge a verdict or owner.

alter table public.profiles enable row level security;
-- FORCE is intentionally omitted on profiles: the auth.users trigger runs as
-- the table owner (security definer) and must be able to create the profile.
-- Client roles are still fully constrained by RLS and column grants below.

alter table public.scans enable row level security;
alter table public.scans force row level security;

revoke all on table public.profiles from anon, authenticated;
revoke all on table public.scans from anon, authenticated;

grant select on table public.profiles to authenticated;
grant update (display_name) on table public.profiles to authenticated;
grant select on table public.scans to authenticated;

create policy profiles_select_own
  on public.profiles
  for select
  to authenticated
  using (id = (select auth.uid()));

create policy profiles_update_own
  on public.profiles
  for update
  to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

create policy scans_select_own
  on public.scans
  for select
  to authenticated
  using (user_id = (select auth.uid()));

-- No insert/update/delete policy exists for profiles or scans. The service role
-- bypasses RLS and is the only writer for assessment data.
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    execute 'grant all privileges on table public.profiles, public.scans to service_role';
  end if;
end;
$$;
