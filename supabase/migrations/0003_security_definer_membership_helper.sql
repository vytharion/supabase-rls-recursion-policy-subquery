-- Step 4 — Fix attempt 1: break the policy recursion by delegating the
-- membership lookup to a SECURITY DEFINER SQL function.
--
-- Step 2 stored a SELECT policy on public.memberships whose USING clause
-- ran a subquery against public.memberships itself. The rewriter re-fired
-- the same policy on the subquery and step 3 captured the resulting
-- 42P17 infinite recursion error.
--
-- A SECURITY DEFINER function executes with the privileges of the role
-- that owns it (here, the migration role / table owner) rather than the
-- calling role. RLS is bypassed for the function owner when it queries
-- the table from inside the function body, so the rewriter has nothing
-- to re-attach and the recursion loop is severed.
--
-- The function is marked STABLE because for a fixed (target_team,
-- auth.uid()) pair it returns the same value within a statement. That
-- lets the planner cache the result across the rows being filtered and
-- avoids re-running the lookup once per row.
--
-- search_path is pinned explicitly so a hostile caller cannot shadow
-- the public.memberships reference by setting a session search_path
-- ahead of the SELECT — the function would otherwise resolve the name
-- in the caller's scope while running with elevated privileges.

drop policy if exists memberships_select_same_team on public.memberships;

create or replace function public.is_team_member(target_team uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
    select exists (
        select 1
        from public.memberships
        where team_id = target_team
          and user_id = auth.uid()
    );
$$;

revoke all on function public.is_team_member(uuid) from public;
grant execute on function public.is_team_member(uuid) to authenticated;

create policy memberships_select_same_team on public.memberships
    for select
    using (public.is_team_member(team_id));
