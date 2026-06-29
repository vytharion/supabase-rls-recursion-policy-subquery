-- pgTAP regression suite for the memberships SELECT policy.
--
-- The earlier steps fixed the 42P17 recursion error twice — once via a
-- SECURITY DEFINER helper (step 4), once via a non-recursive JWT-claim
-- predicate (step 5). The structural pytest modules that ride along
-- with those migrations only inspect the SQL text; they cannot prove
-- the policy actually filters rows the way the article claims. This
-- script does that proof end-to-end against a live Postgres instance.
--
-- The suite walks three personas that map onto the seed data in
-- supabase/seed.sql:
--
--   * Alice (11111111-…-1111) — owner of the Acme team. Her JWT also
--     lists Acme in app_metadata.team_ids so the claim-driven branch
--     of the policy fires for her requests.
--   * Bob (22222222-…-2222) — admin/member of Acme but NOT the owner.
--     We run him twice: once with an empty team_ids array (only the
--     self-row branch should match) and once with Acme in team_ids
--     (the JWT branch widens his visibility to the rest of the team).
--   * Carol (33333333-…-3333) — owner of Globex, an outsider to Acme.
--     Her JWT lists Globex only, so cross-tenant rows must stay hidden.
--
-- How to run against a local Supabase stack:
--   supabase db reset
--   pg_prove --ext .sql supabase/tests/
--
-- The matching pytest module tests/test_pgtap_policy_coverage.py pins
-- the structural shape of this file so a regression cannot silently
-- drop one of the three personas.

begin;

create extension if not exists pgtap;

select plan(11);

-- ---------------------------------------------------------------------
-- Owner access path — Alice / Acme.
-- ---------------------------------------------------------------------

set local role authenticated;
set local "request.jwt.claims" = '{
    "sub": "11111111-1111-1111-1111-111111111111",
    "app_metadata": {"team_ids": ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]}
}';

select is(
    (select count(*)::int
       from public.memberships
       where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    2,
    'owner: Alice sees both Acme membership rows'
);

select is(
    (select count(*)::int from public.memberships),
    2,
    'owner: Alice sees no rows outside Acme'
);

select bag_eq(
    $$ select user_id::text from public.memberships $$,
    $$ values
        ('11111111-1111-1111-1111-111111111111'),
        ('22222222-2222-2222-2222-222222222222') $$,
    'owner: Alice reads exactly Alice + Bob as the Acme member set'
);

reset role;
reset "request.jwt.claims";

-- ---------------------------------------------------------------------
-- Member access path — Bob with no team_ids claim (self-row branch).
-- ---------------------------------------------------------------------

set local role authenticated;
set local "request.jwt.claims" = '{
    "sub": "22222222-2222-2222-2222-222222222222",
    "app_metadata": {"team_ids": []}
}';

select is(
    (select count(*)::int from public.memberships),
    1,
    'member: Bob with empty team_ids sees exactly one row'
);

select is(
    (select user_id::text
       from public.memberships),
    '22222222-2222-2222-2222-222222222222',
    'member: Bob with empty team_ids only sees his own membership row'
);

select is(
    (select team_id::text
       from public.memberships),
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    'member: Bob with empty team_ids cannot peek into Globex'
);

reset role;
reset "request.jwt.claims";

-- ---------------------------------------------------------------------
-- Member access path — Bob with Acme in team_ids (JWT branch widens).
-- ---------------------------------------------------------------------

set local role authenticated;
set local "request.jwt.claims" = '{
    "sub": "22222222-2222-2222-2222-222222222222",
    "app_metadata": {"team_ids": ["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]}
}';

select is(
    (select count(*)::int from public.memberships),
    2,
    'member: Bob with Acme in team_ids sees the full Acme roster'
);

select bag_eq(
    $$ select user_id::text from public.memberships $$,
    $$ values
        ('11111111-1111-1111-1111-111111111111'),
        ('22222222-2222-2222-2222-222222222222') $$,
    'member: Bob with Acme in team_ids reads Alice + himself'
);

reset role;
reset "request.jwt.claims";

-- ---------------------------------------------------------------------
-- Outsider access path — Carol cannot see Acme even with a Globex JWT.
-- ---------------------------------------------------------------------

set local role authenticated;
set local "request.jwt.claims" = '{
    "sub": "33333333-3333-3333-3333-333333333333",
    "app_metadata": {"team_ids": ["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]}
}';

select is(
    (select count(*)::int
       from public.memberships
       where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    0,
    'outsider: Carol reads zero rows from the Acme team'
);

select is(
    (select count(*)::int
       from public.memberships
       where team_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
    1,
    'outsider: Carol still reads her own Globex membership row'
);

reset role;
reset "request.jwt.claims";

-- ---------------------------------------------------------------------
-- Outsider access path — Carol with an empty team_ids claim still
-- reaches her own row through the self-row branch. This pins that
-- the policy never collapses to "deny everything" when the JWT is
-- thin; an outsider always retains the ability to confirm their own
-- membership.
-- ---------------------------------------------------------------------

set local role authenticated;
set local "request.jwt.claims" = '{
    "sub": "33333333-3333-3333-3333-333333333333",
    "app_metadata": {"team_ids": []}
}';

select is(
    (select count(*)::int from public.memberships),
    1,
    'outsider: Carol with empty team_ids still sees her own Globex row'
);

select * from finish();
rollback;
