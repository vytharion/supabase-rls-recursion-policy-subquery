-- The naive "you can read a membership row if you are also a member of
-- the same team" policy. The subquery in USING reads from the same
-- table the policy is attached to, so Postgres re-enters this policy
-- to evaluate the subquery, which re-enters the policy to evaluate
-- *its* subquery, and so on. Step 3 captures the runtime error this
-- produces; later steps replace this policy with a non-recursive one.

create policy memberships_select_same_team on public.memberships
    for select
    using (
        team_id in (
            select m.team_id
            from public.memberships as m
            where m.user_id = auth.uid()
        )
    );
