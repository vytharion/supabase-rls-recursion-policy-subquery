# Tracing the `42P17 infinite recursion detected in policy` error

This note is the human-readable companion to
`supabase/scripts/recursion_trace.sql`. The script collects raw
catalog data; this file walks through what that data *means* and why
Postgres surrenders during query rewriting instead of executing the
SELECT.

The reproduction lives in `reproduce_recursion.sql` and the verbatim
server response lives in `expected_recursion_error.txt`. Refer back to
both while reading.

## What the user typed

```sql
set local role authenticated;
set local "request.jwt.claim.sub" = '11111111-1111-1111-1111-111111111111';

select id, team_id, user_id, role
from public.memberships;
```

A normal three-column SELECT. Nothing in the query itself is
recursive. The recursion is entirely a property of the
`memberships_select_same_team` policy that migration 0002 attached to
the table.

## The policy under inspection

```sql
create policy memberships_select_same_team on public.memberships
    for select
    using (
        team_id in (
            select m.team_id
            from public.memberships as m
            where m.user_id = auth.uid()
        )
    );
```

The `USING` clause filters `memberships` by reading from
`memberships`. That self-reference is the whole story.

## Step-by-step trace of the rewriter

Postgres handles row-level security inside the *rewriter*, in the
`fireRIRrules()` function (`src/backend/rewrite/rewriteHandler.c`,
around line 2167 — the LOCATION line in the error transcript points
straight at it). The rewriter expands each RTE that has policies into
a subquery whose WHERE clause is the policy's USING expression. Trace
that expansion on our query:

1. **Input parse tree.** The planner receives:
   `SELECT id, team_id, user_id, role FROM public.memberships`.
   `pg_class.relrowsecurity` is true on `memberships`, so the
   rewriter is obligated to apply policies before it hands the tree
   to the planner.

2. **First expansion (depth 0 → 1).** The outer `memberships` RTE is
   rewritten into a subquery:

   ```sql
   SELECT id, team_id, user_id, role
   FROM (
       SELECT * FROM public.memberships
       WHERE team_id IN (
           SELECT m.team_id FROM public.memberships AS m
           WHERE m.user_id = auth.uid()
       )
   ) AS memberships;
   ```

   Two `memberships` RTEs now exist: the outer one (already
   security-wrapped) and the inner one inside the `IN (...)` subquery
   (still raw).

3. **Second expansion (depth 1 → 2).** `fireRIRrules` walks the tree
   again, finds the unprocessed inner `memberships` RTE in the
   USING-clause subquery, and applies the same policy:

   ```sql
   SELECT m.team_id
   FROM (
       SELECT * FROM public.memberships
       WHERE team_id IN (
           SELECT m2.team_id FROM public.memberships AS m2
           WHERE m2.user_id = auth.uid()
       )
   ) AS m
   WHERE m.user_id = auth.uid();
   ```

   A *new* unprocessed `memberships` RTE has just been introduced
   (`m2`). The rewriter has not converged — every pass produces
   another reference that itself needs the policy applied.

4. **Third expansion (depth 2 → 3).** Same shape. Wrap the new
   `m2` RTE, get an `m3` RTE inside it. Repeat.

5. **Bail-out.** Postgres detects that the rewrite is not reaching a
   fixed point and refuses to materialise the rule chain. It raises
   `ERROR: 42P17: infinite recursion detected in policy for relation
   "memberships"` and points at `fireRIRrules, rewriteHandler.c:2167`.

The number of textual expansions Postgres will tolerate before giving
up is small (it does not actually run thousands of passes); the
recursion detector watches the relation OID stack and trips as soon as
the same OID is about to be wrapped a second time inside its own
rewrite.

## Why this is a *planner-time* error, not a runtime one

`EXPLAIN (verbose, costs off) select ... from memberships` raises the
same 42P17. EXPLAIN never executes the plan — it stops after rewriting
and planning. The fact that EXPLAIN already fails proves the error
fires during rewriting, before any tuple is read. That is also why
adding indexes, narrowing the predicate, or shrinking the seed data
makes no difference: there are no tuples in the picture yet.

## Why the `authenticated` role matters

Superusers and the table owner bypass RLS, so running the same SELECT
as `postgres` succeeds and gives no hint of the bug. `reproduce_*.sql`
explicitly switches to `authenticated` (the role PostgREST uses) so
that `fireRIRrules` is forced to apply the policy. Without that role
switch the script would silently look fine and the recursion would
only surface in production once a real client request arrived.

## What the trace tells us about the fix

The recursion is structural: any USING clause that issues `SELECT ...
FROM memberships` against the same table re-enters the same policy.
There are two ways out, and the next two steps explore both:

- **SECURITY DEFINER helper** — move the membership lookup into a SQL
  function owned by the table owner. The function executes with the
  owner's privileges, RLS is skipped for that call, and the policy's
  USING clause only sees the function result, not another RLS-checked
  read.
- **EXISTS against a different relation** — rewrite the policy so the
  subquery hits a base table that does not have the same policy
  attached (for example, joining through `teams.owner_id` or a
  materialised view), eliminating the self-reference.

Both fixes work by making sure that, after one rewriter pass, no
unprocessed `memberships` RTE remains in the tree. That is the
property the naive policy lacks.

## Quick checklist for diagnosing similar policies

When you see `42P17`, ask in this order:

1. Which relation is named in the error? That is the policy's home.
2. Does any USING / WITH CHECK clause on that relation read from the
   same relation, directly or via a view that fans out to it?
3. Can the read be replaced by a SECURITY DEFINER function, a join
   through a different base table, or a denormalised column?
4. Does the new policy still pass `EXPLAIN` under a non-privileged
   role? If yes, the recursion is gone.
