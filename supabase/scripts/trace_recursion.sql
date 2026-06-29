-- Capture the planner's rewrite trace for the failing SELECT against
-- public.memberships under the naive USING-clause subquery policy.
--
-- Run after `supabase db reset` so migrations 0001 + 0002 and the seed
-- are loaded:
--   psql "$DATABASE_URL" -f supabase/scripts/trace_recursion.sql
--
-- The diagnostic GUCs turn on the rewriter and planner debug output so
-- a reader can see fireRIRrules try to inline the USING subquery, then
-- bail out with SQLSTATE 42P17 the moment it would have to expand the
-- policy a second time. The expected error itself is identical to the
-- one captured in expected_recursion_error.txt; this script's value is
-- the rewrite trace the server emits *before* the error fires.

begin;

set local client_min_messages = debug1;
set local debug_print_rewritten = on;
set local debug_pretty_print = on;

-- Drop privileges to a non-superuser so RLS actually fires.
set local role authenticated;

-- Pretend Alice is the JWT subject so auth.uid() resolves inside the
-- policy's USING clause.
set local "request.jwt.claim.sub" = '11111111-1111-1111-1111-111111111111';

-- The SELECT below triggers fireRIRrules to expand the USING subquery,
-- which re-references public.memberships, which still has the same
-- SELECT policy attached, which would expand again. fireRIRrules
-- detects the cycle on the second expansion attempt and raises
-- ERROR 42P17 before the plan ever reaches the executor.
select id, team_id, user_id, role
from public.memberships;

rollback;
