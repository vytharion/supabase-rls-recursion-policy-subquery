-- pgTAP suite locking the step-5 RLS rewrite of public.memberships.
--
-- Step 5 swapped the recursive subquery for a JWT-driven USING clause:
-- a row is visible when (1) the caller owns it (user_id = auth.uid())
-- OR (2) the row's team_id appears in auth.jwt() -> app_metadata ->
-- team_ids. The three archetypes below exercise both branches plus the
-- fallback path so a future refactor cannot silently regress any of
-- them.
--
-- Archetypes (matching supabase/seed.sql):
--   * owner    — alice (11111111-…) owns Acme; her JWT carries Acme.
--   * member   — bob   (22222222-…) is admin in Acme; same Acme claim.
--   * outsider — carol (33333333-…) owns Globex; her JWT carries Globex
--                only, so every Acme row must be filtered out.
--
-- How to run against a local Supabase database (pgTAP must be installed
-- in the target db: `create extension if not exists pgtap;`):
--
--   pg_prove -d postgres supabase/tests/rls_memberships.sql
--
-- The whole suite runs inside a single BEGIN/ROLLBACK so the GUC
-- changes (role, jwt claims) never leak into the surrounding session.

begin;

select plan(9);

-- Sanity probe: without the step-5 policy installed every assertion
-- below would silently pass under the table-owner's bypass. has_policy
-- + policies_are pin both the existence and the exclusivity of the
-- rewritten policy.
select has_policy(
    'public', 'memberships', 'memberships_select_same_team',
    'step-5 SELECT policy must be attached to public.memberships'
);

select policies_are(
    'public', 'memberships',
    ARRAY['memberships_select_same_team'],
    'memberships should carry exactly one SELECT policy after step 5'
);

-- ---------------------------------------------------------------------
-- owner — alice@acme
-- ---------------------------------------------------------------------
set local role authenticated;
set local "request.jwt.claim.sub" = '11111111-1111-1111-1111-111111111111';
set local "request.jwt.claims" = '{"sub":"11111111-1111-1111-1111-111111111111","app_metadata":{"team_ids":["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]}}';

select results_eq(
    $$ select count(*)::int from public.memberships
        where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' $$,
    $$ values (2) $$,
    'owner alice should see both Acme rows (her own + bob)'
);

select is_empty(
    $$ select 1 from public.memberships
        where team_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' $$,
    'owner alice must not see Globex rows — her JWT carries Acme only'
);

reset role;

-- ---------------------------------------------------------------------
-- member — bob@acme
-- ---------------------------------------------------------------------
set local role authenticated;
set local "request.jwt.claim.sub" = '22222222-2222-2222-2222-222222222222';
set local "request.jwt.claims" = '{"sub":"22222222-2222-2222-2222-222222222222","app_metadata":{"team_ids":["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"]}}';

select results_eq(
    $$ select count(*)::int from public.memberships
        where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' $$,
    $$ values (2) $$,
    'member bob should see both Acme rows alongside the owner'
);

select results_eq(
    $$ select user_id::text from public.memberships
        where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        order by user_id $$,
    $$ values ('11111111-1111-1111-1111-111111111111'),
             ('22222222-2222-2222-2222-222222222222') $$,
    'member bob should see exactly alice + bob, with no Globex bleed'
);

reset role;

-- ---------------------------------------------------------------------
-- outsider — carol@globex
-- ---------------------------------------------------------------------
set local role authenticated;
set local "request.jwt.claim.sub" = '33333333-3333-3333-3333-333333333333';
set local "request.jwt.claims" = '{"sub":"33333333-3333-3333-3333-333333333333","app_metadata":{"team_ids":["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"]}}';

select is_empty(
    $$ select 1 from public.memberships
        where team_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' $$,
    'outsider carol must not see any Acme rows'
);

select results_eq(
    $$ select count(*)::int from public.memberships
        where team_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' $$,
    $$ values (1) $$,
    'outsider carol should still see her own Globex membership'
);

reset role;

-- ---------------------------------------------------------------------
-- regression — empty app_metadata must collapse to "own rows only"
-- ---------------------------------------------------------------------
-- A caller whose JWT lacks team_ids must fall back to the OR branch's
-- left side (user_id = auth.uid()). The policy must NEVER let an empty
-- claim widen visibility — even with a valid auth.uid() Alice should
-- not see Globex rows here.
set local role authenticated;
set local "request.jwt.claim.sub" = '11111111-1111-1111-1111-111111111111';
set local "request.jwt.claims" = '{"sub":"11111111-1111-1111-1111-111111111111","app_metadata":{}}';

select is_empty(
    $$ select 1 from public.memberships
        where team_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' $$,
    'empty team_ids claim must not bleed Globex rows for a valid sub'
);

reset role;

select * from finish();

rollback;
