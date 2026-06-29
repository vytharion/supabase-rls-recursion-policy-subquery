-- Diagnostic companion to reproduce_recursion.sql.
--
-- reproduce_recursion.sql shows the *symptom* (SQLSTATE 42P17). This
-- script collects the four artefacts an engineer normally reaches for
-- when tracing why the planner refuses the query:
--
--   1. The policy text Postgres actually stored (pg_policies).
--   2. The rewrite rule chain attached to memberships (pg_rewrite).
--   3. EXPLAIN on the failing query, which still fires the rewriter
--      and therefore reproduces the same 42P17 without executing a
--      single row.
--   4. A sanity probe (a select that does NOT touch memberships) to
--      prove the rest of the schema is healthy.
--
-- Run order, against a local Supabase stack:
--   supabase db reset
--   psql "$DATABASE_URL" -f supabase/scripts/recursion_trace.sql
--
-- Steps 1, 2, 4 are read-only catalog probes and complete normally.
-- Step 3 is the one that raises 42P17 — that is the point of the
-- trace, not a bug in the script.

begin;

-- --------------------------------------------------------------------
-- 1. Confirm the naive policy is the one Postgres is rewriting with.
-- --------------------------------------------------------------------
select
    schemaname,
    tablename,
    policyname,
    cmd,
    qual as using_clause
from pg_policies
where schemaname = 'public'
  and tablename  = 'memberships'
order by policyname;

-- --------------------------------------------------------------------
-- 2. Inspect the rewrite rule chain. Each RLS policy becomes a row in
--    pg_rewrite of ev_type 'SELECT'; ev_qual carries the USING clause
--    expression tree. The presence of a self-reference inside ev_qual
--    is what makes fireRIRrules() recurse without a fixed point.
-- --------------------------------------------------------------------
select
    r.rulename,
    r.ev_type,
    r.is_instead,
    pg_get_expr(r.ev_qual, r.ev_class) as ev_qual_text
from pg_rewrite r
join pg_class c on c.oid = r.ev_class
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relname  = 'memberships'
order by r.rulename;

-- --------------------------------------------------------------------
-- 3. Re-enter the policy from a non-superuser session and trigger
--    42P17 *during planning*. EXPLAIN runs the rewriter but skips
--    execution, which proves the error is raised before any tuples
--    are scanned — i.e. it is a planner-side issue, not a runtime
--    one.
-- --------------------------------------------------------------------
set local role authenticated;
set local "request.jwt.claim.sub" = '11111111-1111-1111-1111-111111111111';

explain (verbose, costs off)
select id, team_id, user_id, role
from public.memberships;

-- --------------------------------------------------------------------
-- 4. Control probe: teams has no policy attached yet (step 1 only
--    enabled RLS, step 2 only added a policy on memberships), so this
--    select returns zero rows under the authenticated role instead of
--    raising. That contrast isolates the bug to the memberships
--    policy.
-- --------------------------------------------------------------------
select count(*) as visible_teams from public.teams;

rollback;
