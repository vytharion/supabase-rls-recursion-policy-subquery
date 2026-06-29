-- Step 5 — Fix attempt 2: rewrite the membership policy as a plain
-- EXISTS subquery against a different base table, without leaning on a
-- SECURITY DEFINER helper.
--
-- Step 4's fix worked, but it bought safety with a definer-rights
-- function and four hardening flags that have to travel together
-- (STABLE, pinned search_path, revoke from PUBLIC, grant to
-- authenticated). This step explores the alternative: skip the helper
-- entirely and rewrite the USING clause so it never reads from the
-- protected table in the first place.
--
-- The key observation is that the rewriter only loops when the policy
-- on memberships re-reads memberships. An EXISTS subquery against
-- public.teams is a read of a *different* base table, so the rewriter
-- never has to re-enter the memberships policy to evaluate it. No
-- SECURITY DEFINER is required because no privilege escalation is
-- happening.
--
-- The trade-off is semantic, not structural. Step 4 reproduced the
-- original rule "every member of a team can see every other member of
-- the same team." This step ships a narrower rule: a caller can see a
-- membership row when (a) it is their own row, or (b) they own the
-- team the row belongs to. The article compares the two shapes head to
-- head — neither one is universally correct; the right choice depends
-- on whether peer-visibility is part of the product spec.
--
-- Because step 5 is an alternative to step 4 rather than an addition,
-- the migration drops the step-4 policy AND the helper. After this
-- migration the database state is "fix attempt 2 applied"; the
-- helper's source lives on in git history under 0003.

drop policy if exists memberships_select_same_team on public.memberships;

drop function if exists public.is_team_member(uuid);

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
