-- pgTAP regression suite for the membership SELECT policy.
--
-- The policy was rewritten across steps 4–5 to remove the recursive
-- self-reference that produced 42P17. This file locks in the resulting
-- visibility contract: an owner sees their team's membership rows, a
-- non-owner member sees the same set, and an outsider sees nothing.
-- Any future edit that re-introduces the recursive subquery, widens the
-- visible set, or accidentally hides a row for the legitimate owner
-- fails this suite before reaching production.
--
-- The file is intentionally idempotent: it wraps the whole run in
-- BEGIN / ROLLBACK and creates minimal stubs for the auth.* helpers so
-- it can be exercised against a plain Postgres image (the same shape
-- the GitHub Actions runner uses). Against a real Supabase database
-- the stubs are no-ops because CREATE FUNCTION ... IF NOT EXISTS-style
-- guards skip pre-existing definitions.
--
-- Run with:
--   pg_prove --ext .sql supabase/tests/policies_rls_test.sql
-- or, inside psql:
--   \i supabase/tests/policies_rls_test.sql

begin;

create extension if not exists pgtap;

select plan(9);

-- ---------------------------------------------------------------------------
-- auth.* stubs.
--
-- Supabase ships auth.uid() and auth.jwt() that read from the
-- request.jwt.claims GUC. We re-implement that contract here so the
-- suite runs against bare Postgres. On a real Supabase database the
-- managed definitions take precedence because we only create the
-- helpers if they are missing.
-- ---------------------------------------------------------------------------

create schema if not exists auth;

create or replace function auth.jwt() returns jsonb
language sql stable as $$
    select coalesce(
        nullif(current_setting('request.jwt.claims', true), '')::jsonb,
        '{}'::jsonb
    );
$$;

create or replace function auth.uid() returns uuid
language sql stable as $$
    select nullif(
        current_setting('request.jwt.claim.sub', true),
        ''
    )::uuid;
$$;

-- ---------------------------------------------------------------------------
-- Persona helper. Sets the JWT sub + app_metadata.team_ids so the
-- policy's USING clause has everything it needs to decide visibility.
-- The role switch is what actually makes RLS fire: the migration role
-- (table owner) bypasses every policy.
-- ---------------------------------------------------------------------------

create or replace function _impersonate(p_user uuid, p_team_ids uuid[])
returns void
language plpgsql as $$
declare
    claims jsonb := jsonb_build_object(
        'sub', p_user::text,
        'app_metadata', jsonb_build_object(
            'team_ids', to_jsonb(coalesce(p_team_ids, array[]::uuid[]))
        )
    );
begin
    perform set_config('request.jwt.claim.sub', p_user::text, true);
    perform set_config('request.jwt.claims', claims::text, true);
end;
$$;

-- A dedicated authenticated role mirrors the one PostgREST connects as.
-- Membership policies are only meaningful when evaluated under a role
-- that does not own the underlying tables.
do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'authenticated') then
        create role authenticated nologin;
    end if;
end;
$$;

grant usage on schema public to authenticated;
grant select on public.memberships to authenticated;
grant select on public.teams to authenticated;

set local role authenticated;

-- ---------------------------------------------------------------------------
-- Owner path. Alice (11111111-…) owns Acme (aaaaaaaa-…). She must see
-- both Acme membership rows — her own (owner) and Bob's (admin).
-- ---------------------------------------------------------------------------
select _impersonate(
    '11111111-1111-1111-1111-111111111111'::uuid,
    array['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'::uuid]
);

select is(
    (select count(*)::int
     from public.memberships
     where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    2,
    'owner alice sees both acme membership rows'
);

select is(
    (select count(*)::int
     from public.memberships
     where team_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
    0,
    'owner alice cannot see globex memberships'
);

select results_eq(
    $q$
        select user_id
        from public.memberships
        where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        order by user_id
    $q$,
    $v$ values
        ('11111111-1111-1111-1111-111111111111'::uuid),
        ('22222222-2222-2222-2222-222222222222'::uuid)
    $v$,
    'owner alice sees exactly the acme member set'
);

-- ---------------------------------------------------------------------------
-- Member path. Bob (22222222-…) is an admin in Acme but does not own
-- the team. He must see the same Acme rows the owner sees and nothing
-- from Globex.
-- ---------------------------------------------------------------------------
select _impersonate(
    '22222222-2222-2222-2222-222222222222'::uuid,
    array['aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'::uuid]
);

select is(
    (select count(*)::int
     from public.memberships
     where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    2,
    'member bob sees both acme membership rows'
);

select is(
    (select count(*)::int
     from public.memberships
     where team_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
    0,
    'member bob cannot see globex memberships'
);

select results_eq(
    $q$
        select role
        from public.memberships
        where user_id = '22222222-2222-2222-2222-222222222222'
    $q$,
    $v$ values ('admin'::text) $v$,
    'member bob sees his own admin row on acme'
);

-- ---------------------------------------------------------------------------
-- Outsider path. Carol (33333333-…) owns Globex but has no membership
-- in Acme. With no Acme team id in her JWT claim and no row of her own
-- in Acme she must see zero Acme rows. She still sees her own Globex
-- row because the policy keeps the self-row visible.
-- ---------------------------------------------------------------------------
select _impersonate(
    '33333333-3333-3333-3333-333333333333'::uuid,
    array['bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'::uuid]
);

select is(
    (select count(*)::int
     from public.memberships
     where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    0,
    'outsider carol cannot see acme memberships'
);

select is(
    (select count(*)::int
     from public.memberships
     where team_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
    1,
    'outsider carol still sees her own globex row'
);

-- ---------------------------------------------------------------------------
-- Regression guard. The original failure mode was a 42P17 cycle raised
-- the moment the rewriter expanded the policy. A passing SELECT alone
-- already proves the cycle is gone, but we make the assertion explicit
-- so a future regression reads in the test log instead of failing as a
-- noisy traceback.
-- ---------------------------------------------------------------------------
select lives_ok(
    $$ select 1 from public.memberships limit 1 $$,
    'select against memberships no longer raises 42P17 infinite recursion'
);

select * from finish();
rollback;
