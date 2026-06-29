-- Step 5 — Fix attempt 2: rewrite the membership policy with a
-- non-recursive EXISTS subquery against the base table public.teams.
--
-- Step 4 broke the rewriter loop by hiding the membership lookup
-- behind a SECURITY DEFINER helper. That works, but it ships a
-- privilege-escalating function on the public path, and every reviewer
-- has to re-verify the hardening flags (STABLE, pinned search_path,
-- revoked default EXECUTE) before signing off. This step shows the
-- alternative: keep the lookup inline in the policy, but point the
-- subquery at a base table whose policy does NOT reference
-- public.memberships. The rewriter has no cycle to refuse, so the
-- 42P17 error never appears.
--
-- The "base table" here is public.teams. It has a one-row-per-team
-- shape and an owner_id column that maps directly to auth.uid() for
-- the team owner. The new memberships policy decides visibility from
-- two non-recursive checks:
--   1. user_id = auth.uid()    -> the caller can always see their own
--                                 membership rows
--   2. EXISTS (... teams ...)  -> the caller can see every membership
--                                 row inside a team they own
-- Outsiders satisfy neither check and read zero rows.
--
-- public.teams already has RLS enabled (step 1), so the EXISTS
-- subquery is only safe if teams itself has a policy that lets the
-- owner see their team. We attach that policy in the same migration
-- so the fix lands atomically — partial application would silently
-- collapse the EXISTS to false for everyone.

drop policy if exists memberships_select_same_team on public.memberships;
drop function if exists public.is_team_member(uuid);

create policy teams_select_owned on public.teams
    for select
    using (owner_id = auth.uid());

create policy memberships_select_same_team on public.memberships
    for select
    using (
        user_id = auth.uid()
        or exists (
            select 1
            from public.teams as t
            where t.id = memberships.team_id
              and t.owner_id = auth.uid()
        )
    );
