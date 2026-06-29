-- pgTAP test suite locking the behaviour of the step-5 non-recursive
-- EXISTS policy on public.memberships (and the supporting policy on
-- public.teams). Exercises the three identity paths that matter for a
-- multi-tenant Supabase project:
--
--   * OWNER     — alice, who owns the Acme team
--   * MEMBER    — bob, an admin in Acme who does not own any team
--   * OUTSIDER  — carol, who owns Globex and has no relationship to Acme,
--                 plus an unauthenticated caller with no JWT claim
--
-- Run against a database that has applied migrations 0001-0004 and the
-- seed fixtures:
--
--   supabase db reset
--   psql "$DATABASE_URL" -f supabase/tests/rls_membership_access.sql
--
-- The whole suite runs inside a transaction and rolls back on finish,
-- so the seed data is not mutated. The auth.uid() and authenticated
-- role shims at the top make the file self-contained: on a managed
-- Supabase project they are no-ops because CREATE OR REPLACE keeps the
-- platform definitions intact, and on a vanilla Postgres they install
-- the minimum surface the policies need.

begin;

create extension if not exists pgtap;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'authenticated') then
        create role authenticated nologin;
    end if;
end
$$;

grant usage on schema public to authenticated;
grant select on public.teams to authenticated;
grant select on public.memberships to authenticated;

create schema if not exists auth;

create or replace function auth.uid() returns uuid
    language sql
    stable
    as $$
        select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid
    $$;

create or replace function public._as_user(p_user uuid) returns void
    language plpgsql
    as $$
    begin
        perform set_config('request.jwt.claim.sub', p_user::text, true);
        set local role authenticated;
    end;
    $$;

create or replace function public._as_anon() returns void
    language plpgsql
    as $$
    begin
        perform set_config('request.jwt.claim.sub', '', true);
        set local role authenticated;
    end;
    $$;

select plan(13);

-- ---------------------------------------------------------------------
-- OWNER path — alice owns Acme. She must see every membership row in
-- Acme (her own row via user_id, bob's row via the EXISTS branch) and
-- exactly one team (the one she owns).
-- ---------------------------------------------------------------------
select public._as_user('11111111-1111-1111-1111-111111111111');

select is(
    (select count(*)::int from public.memberships),
    2,
    'owner alice sees exactly 2 membership rows (her team has 2 members)'
);

select ok(
    exists (
        select 1
        from public.memberships
        where user_id = '11111111-1111-1111-1111-111111111111'::uuid
    ),
    'owner alice can see her own membership row'
);

select ok(
    exists (
        select 1
        from public.memberships
        where user_id = '22222222-2222-2222-2222-222222222222'::uuid
    ),
    'owner alice can see bob''s membership row via the EXISTS branch'
);

select is(
    (select count(*)::int from public.teams),
    1,
    'owner alice sees exactly 1 team (the one she owns)'
);

reset role;

-- ---------------------------------------------------------------------
-- MEMBER path — bob is an admin in Acme but owns no team. He must see
-- only his own membership row (no other members of Acme leak in) and
-- zero teams (teams_select_owned scopes to owner_id).
-- ---------------------------------------------------------------------
select public._as_user('22222222-2222-2222-2222-222222222222');

select is(
    (select count(*)::int from public.memberships),
    1,
    'member bob sees exactly 1 membership row (his own)'
);

select ok(
    not exists (
        select 1
        from public.memberships
        where user_id = '11111111-1111-1111-1111-111111111111'::uuid
    ),
    'member bob cannot see alice''s membership row (no co-tenant leak)'
);

select is(
    (select count(*)::int from public.teams),
    0,
    'member bob sees 0 teams because teams_select_owned filters to owners'
);

reset role;

-- ---------------------------------------------------------------------
-- OUTSIDER path #1 — carol owns Globex. From Acme's perspective she is
-- an outsider: she must NOT see any Acme membership row, only her own
-- inside Globex. Her self-row visibility proves the user_id branch
-- still works for non-Acme tenants.
-- ---------------------------------------------------------------------
select public._as_user('33333333-3333-3333-3333-333333333333');

select is(
    (select count(*)::int from public.memberships),
    1,
    'outsider carol sees exactly 1 membership row (her own in globex)'
);

select is(
    (select count(*)::int
     from public.memberships
     where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'::uuid),
    0,
    'outsider carol cannot read any acme membership row'
);

select is(
    (select count(*)::int from public.teams),
    1,
    'outsider carol sees exactly 1 team (globex, the one she owns)'
);

reset role;

-- ---------------------------------------------------------------------
-- OUTSIDER path #2 — an unauthenticated caller (no JWT sub claim) must
-- see zero rows. auth.uid() returns null, so the user_id branch is
-- never true and the EXISTS branch finds no team rows either.
-- ---------------------------------------------------------------------
select public._as_anon();

select is(
    (select count(*)::int from public.memberships),
    0,
    'anonymous outsider sees no membership rows'
);

select is(
    (select count(*)::int from public.teams),
    0,
    'anonymous outsider sees no team rows'
);

reset role;

-- ---------------------------------------------------------------------
-- Structural guard — pin the policy that produces the behaviour above.
-- If a future migration renames or drops it the suite fails loud
-- instead of silently passing zero behavioural checks.
-- ---------------------------------------------------------------------
select policies_are(
    'public',
    'memberships',
    array['memberships_select_same_team'],
    'public.memberships exposes exactly the step-5 SELECT policy'
);

select finish();

rollback;
