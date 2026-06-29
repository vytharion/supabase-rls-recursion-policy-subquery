-- Step 5 — Fix attempt 2: rewrite the membership SELECT policy so its
-- USING clause is decided entirely from JWT claims, with no SELECT
-- subquery anywhere in the expression.
--
-- Step 4 broke the recursion by hiding the membership lookup behind a
-- SECURITY DEFINER helper. That works, but it pays two prices: the
-- helper runs with elevated privileges on every row check, and the
-- policy still costs a lookup against public.memberships from inside
-- the helper body. Step 5 takes the opposite tradeoff — push the
-- membership list OUT of the database and into the JWT, then let the
-- policy decide from the token alone.
--
-- Supabase reserves the JWT's app_metadata claim for server-controlled
-- attributes: the browser cannot mutate it from the client. The
-- expectation is that a membership-change hook keeps
-- app_metadata.team_ids in sync with public.memberships, shaped as a
-- JSON array of team UUIDs the caller belongs to. The policy reads
-- that array straight from the token via auth.jwt() and decides
-- visibility from a pure boolean expression: there is literally no
-- SELECT in the USING clause, so the rewriter has no subquery to
-- expand and the 42P17 cycle from step 3 cannot reappear.
--
-- The jsonb containment operator `?` returns true when the right-hand
-- text equals an element of the left-hand jsonb array. Casting
-- memberships.team_id to text per row is cheap, and auth.jwt() is
-- STABLE inside a statement so the planner evaluates the claim
-- extraction once and reuses it across the rows being filtered.
--
-- Trade-off notes recorded here so they travel with the migration:
--   * Visibility is driven by the token snapshot, not the live table.
--     A membership change is only reflected once the JWT is refreshed.
--   * The hook that maintains app_metadata.team_ids is the only writer
--     trusted to derive the array — the policy does not re-validate.
--   * If team_ids is absent from the claim the COALESCE falls back to
--     an empty array so the expression remains a well-formed boolean.

drop policy if exists memberships_select_same_team on public.memberships;
drop function if exists public.is_team_member(uuid);

create policy memberships_select_same_team on public.memberships
    for select
    using (
        memberships.user_id = auth.uid()
        or coalesce(
               auth.jwt() -> 'app_metadata' -> 'team_ids',
               '[]'::jsonb
           ) ? memberships.team_id::text
    );
