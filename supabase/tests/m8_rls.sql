-- M8 RLS tests. Run only against a disposable local/test Supabase database:
--   bash scripts/test-rls.sh
-- The transaction is rolled back, but this is still not a production script.

begin;
set search_path = public, extensions;
select plan(14);

insert into auth.users (
  instance_id,
  id,
  aud,
  role,
  email,
  encrypted_password,
  email_confirmed_at,
  raw_app_meta_data,
  raw_user_meta_data,
  created_at,
  updated_at
)
values
  (
    '00000000-0000-0000-0000-000000000000',
    '11111111-1111-4111-8111-111111111111',
    'authenticated',
    'authenticated',
    'user1@example.test',
    'test-only',
    now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    '{"display_name":"User One"}'::jsonb,
    now(),
    now()
  ),
  (
    '00000000-0000-0000-0000-000000000000',
    '22222222-2222-4222-8222-222222222222',
    'authenticated',
    'authenticated',
    'user2@example.test',
    'test-only',
    now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    '{"display_name":"User Two"}'::jsonb,
    now(),
    now()
  );

select is(
  (select count(*) from public.profiles),
  2::bigint,
  'auth trigger creates one profile per user'
);

insert into public.scans (
  id, user_id, url, normalized_url, url_hash, status,
  risk_score, risk_band, confidence, policy_version, result,
  created_at, completed_at
)
values
  (
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    '11111111-1111-4111-8111-111111111111',
    'https://example.com/one',
    'https://example.com/one',
    repeat('a', 64),
    'complete',
    10,
    'low',
    0.9000,
    'm7-2026-11-09.2',
    '{}'::jsonb,
    now(),
    now()
  ),
  (
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    '22222222-2222-4222-8222-222222222222',
    'https://example.com/two',
    'https://example.com/two',
    repeat('b', 64),
    'complete',
    70,
    'high',
    0.8000,
    'm7-2026-11-09.2',
    '{}'::jsonb,
    now(),
    now()
  );

set local role anon;

select throws_ok(
  $sql$ select count(*) from public.profiles $sql$,
  '42501',
  null,
  'anon cannot read profiles'
);
select throws_ok(
  $sql$ select count(*) from public.scans $sql$,
  '42501',
  null,
  'anon cannot read scans'
);

reset role;
set local role authenticated;
select set_config(
  'request.jwt.claims',
  '{"sub":"11111111-1111-4111-8111-111111111111","role":"authenticated"}',
  true
);
select set_config(
  'request.jwt.claim.sub',
  '11111111-1111-4111-8111-111111111111',
  true
);

select is(
  (select count(*) from public.scans),
  1::bigint,
  'user1 sees only their own scan'
);
select is(
  (select count(*) from public.profiles),
  1::bigint,
  'user1 sees only their own profile'
);
select is(
  (
    select count(*)
    from public.scans
    where user_id = '22222222-2222-4222-8222-222222222222'
  ),
  0::bigint,
  'user1 cannot see user2 scans'
);
select is(
  (
    select count(*)
    from public.profiles
    where id = '22222222-2222-4222-8222-222222222222'
  ),
  0::bigint,
  'user1 cannot see user2 profile'
);

select throws_ok(
  $sql$
    insert into public.scans (
      id, user_id, url, normalized_url, url_hash, status, result
    ) values (
      'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      '11111111-1111-4111-8111-111111111111',
      'https://example.com/forged',
      'https://example.com/forged',
      repeat('c', 64),
      'complete',
      '{}'::jsonb
    )
  $sql$,
  '42501',
  null,
  'user1 cannot insert a forged scan'
);

select throws_ok(
  $sql$
    update public.scans
    set risk_score = 99
    where id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  $sql$,
  '42501',
  null,
  'user1 cannot update assessment data'
);

select throws_ok(
  $sql$
    delete from public.scans
    where id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  $sql$,
  '42501',
  null,
  'user1 cannot delete scans'
);

select lives_ok(
  $sql$
    update public.profiles
    set display_name = 'User One Updated'
    where id = '11111111-1111-4111-8111-111111111111'
  $sql$,
  'user1 can update their own display name'
);

with changed as (
  update public.profiles
  set display_name = 'hacked'
  where id = '22222222-2222-4222-8222-222222222222'
  returning 1
)
select is(
  (select count(*) from changed),
  0::bigint,
  'user1 cannot update another profile'
);

select throws_ok(
  $sql$
    update public.profiles
    set role = 'admin'
    where id = '11111111-1111-4111-8111-111111111111'
  $sql$,
  '42501',
  null,
  'user1 cannot escalate role'
);

reset role;
set local role service_role;

insert into public.scans (
  id, user_id, url, normalized_url, url_hash, status,
  risk_score, risk_band, confidence, policy_version, result,
  created_at, completed_at
)
values (
  'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  '22222222-2222-4222-8222-222222222222',
  'https://example.com/three',
  'https://example.com/three',
  repeat('d', 64),
  'complete',
  40,
  'suspicious',
  0.7000,
  'm7-2026-11-09.2',
  '{}'::jsonb,
  now(),
  now()
);

select is(
  (select count(*) from public.scans),
  3::bigint,
  'service role can insert scans and bypasses RLS'
);

reset role;
select * from finish();
rollback;
