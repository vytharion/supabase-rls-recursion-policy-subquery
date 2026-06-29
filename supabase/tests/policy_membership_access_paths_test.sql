-- Step 6 — pgTAP regression suite for memberships_select_same_team.
--
-- Locks in the three access paths the article calls out so a future
-- edit to the policy cannot silently widen or narrow visibility:
--   1. owner    (alice owns Acme)             — sees both Acme rows.
--   2. member   (bob is admin in Acme)        — sees the Acme rows via
--                                                JWT app_metadata + own row.
--   3. outsider (carol owns Globex, not Acme) — sees zero Acme rows,
--                                                still sees own Globex row.
--
-- Each access path runs inside a SAVEPOINT so a failed assertion in one
-- session cannot leak GUCs (role, request.jwt.claims) into the next.
-- The whole file is wrapped in a transaction that rolls back so the
-- suite is repeatable against a long-lived dev database.

begin;

create extension if not exists pgtap;

select plan(9);

-- ---------------------------------------------------------------------
-- Fixtures: pinned in the test file so the suite is self-contained even
-- when supabase/seed.sql is not loaded. on conflict do nothing keeps it
-- idempotent against the seeded development database.
-- ---------------------------------------------------------------------
insert into auth.users (id, email) values
    ('11111111-1111-1111-1111-111111111111', 'alice@example.test'),
    ('22222222-2222-2222-2222-222222222222', 'bob@example.test'),
    ('33333333-3333-3333-3333-333333333333', 'carol@example.test')
on conflict (id) do nothing;

insert into public.teams (id, name, owner_id) values
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Acme',
     '11111111-1111-1111-1111-111111111111'),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Globex',
     '33333333-3333-3333-3333-333333333333')
on conflict (id) do nothing;

insert into public.memberships (team_id, user_id, role) values
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
     '11111111-1111-1111-1111-111111111111', 'owner'),
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
     '22222222-2222-2222-2222-222222222222', 'admin'),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
     '33333333-3333-3333-3333-333333333333', 'owner')
on conflict (team_id, user_id) do nothing;

-- ---------------------------------------------------------------------
-- Access path 1 — owner: alice
-- ---------------------------------------------------------------------
savepoint owner_session;

set local role authenticated;
set local "request.jwt.claims" = '{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated","app_metadata":{"team_ids":["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]}}';

select results_eq(
    $$ select count(*)::bigint
         from public.memberships
        where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' $$,
    $$ values (2::bigint) $$,
    'owner alice sees both Acme membership rows'
);

select is_empty(
    $$ select 1
         from public.memberships
        where team_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' $$,
    'owner alice sees zero Globex membership rows'
);

select results_eq(
    $$ select user_id::text
         from public.memberships
        order by user_id $$,
    $$ values ('11111111-1111-1111-1111-111111111111'::text),
              ('22222222-2222-2222-2222-222222222222'::text) $$,
    'owner alice sees exactly the Acme members and no one else'
);

rollback to savepoint owner_session;

-- ---------------------------------------------------------------------
-- Access path 2 — member: bob (admin in Acme, but not its owner)
-- ---------------------------------------------------------------------
savepoint member_session;

set local role authenticated;
set local "request.jwt.claims" = '{"sub":"22222222-2222-2222-2222-222222222222","role":"authenticated","app_metadata":{"team_ids":["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]}}';

select results_eq(
    $$ select count(*)::bigint
         from public.memberships
        where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' $$,
    $$ values (2::bigint) $$,
    'member bob sees both Acme rows via app_metadata.team_ids claim'
);

select is_empty(
    $$ select 1
         from public.memberships
        where team_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' $$,
    'member bob sees zero Globex rows — not in their claim'
);

select results_eq(
    $$ select count(*)::bigint
         from public.memberships
        where user_id = auth.uid() $$,
    $$ values (1::bigint) $$,
    'member bob always sees their own membership row via auth.uid() branch'
);

rollback to savepoint member_session;

-- ---------------------------------------------------------------------
-- Access path 3 — outsider: carol vs Acme
-- ---------------------------------------------------------------------
savepoint outsider_session;

set local role authenticated;
set local "request.jwt.claims" = '{"sub":"33333333-3333-3333-3333-333333333333","role":"authenticated","app_metadata":{"team_ids":["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]}}';

select is_empty(
    $$ select 1
         from public.memberships
        where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' $$,
    'outsider carol sees zero Acme membership rows'
);

select results_eq(
    $$ select count(*)::bigint
         from public.memberships
        where team_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' $$,
    $$ values (1::bigint) $$,
    'outsider carol still sees their own Globex membership'
);

select isnt_empty(
    $$ select 1
         from public.memberships
        where user_id = auth.uid() $$,
    'outsider carol always sees their own membership row'
);

rollback to savepoint outsider_session;

select * from finish();
rollback;
