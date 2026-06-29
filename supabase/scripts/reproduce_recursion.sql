-- Reproduce the "infinite recursion detected in policy" error that the
-- naive memberships SELECT policy from migration 0002 introduces.
--
-- How to run against a local Supabase stack:
--   supabase db reset                  -- applies 0001, 0002 + seed
--   psql "$DATABASE_URL" -f supabase/scripts/reproduce_recursion.sql
--
-- The first three statements act as Alice; the SELECT is the line that
-- raises the recursion error. The expected transcript lives next to this
-- file as expected_recursion_error.txt so the article can paste the
-- exact server response without hand-editing.

begin;

-- Drop privileges to a non-superuser session so RLS actually fires.
-- Supabase's PostgREST connects as `authenticated`; locally we fall
-- back to a plain role that owns nothing.
set local role authenticated;

-- Pretend Alice (11111111-...-1111) is the JWT subject so auth.uid()
-- returns her id inside the policy's USING clause.
set local "request.jwt.claim.sub" = '11111111-1111-1111-1111-111111111111';

-- This is the query that triggers the failure. Postgres begins to
-- evaluate the SELECT policy on public.memberships, the USING clause
-- runs `select team_id from public.memberships ...`, that inner read
-- re-enters the same SELECT policy, and the planner aborts the
-- evaluation with SQLSTATE 42P17.
select id, team_id, user_id, role
from public.memberships;

rollback;
