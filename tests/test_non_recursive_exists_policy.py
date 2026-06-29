"""Structural tests for the step-5 non-recursive EXISTS policy migration.

Step 5 is the alternative to step 4's SECURITY DEFINER helper. Instead
of delegating the membership lookup to a definer-rights function, this
migration rewrites the USING clause so it reads from a different base
table (public.teams) and never re-enters the memberships policy.

These tests pin the shape of the migration so a later refactor cannot
quietly drop a clause and either re-introduce the step-2 recursion or
silently widen the policy's semantics. They also assert that the
step-4 helper is removed by this migration — step 5 is an alternative
fix, not a layer on top of step 4, and leaving the helper in place
would confuse the article's comparison.

The suite stays offline. Every assertion reads the migration text and
checks structural properties, the same approach used by every other
test module in this codebase.
"""
from __future__ import annotations

import re

from tests._sql import migration_path, normalized


def _fix_sql() -> str:
    return normalized(migration_path("0004").read_text())


def _policy_clause(sql: str) -> str:
    pattern = (
        r"create policy \w+ on (?:public\.)?memberships\s+"
        r"for select\s+using\s*\((.*)\)\s*;"
    )
    match = re.search(pattern, sql)
    if not match:
        raise AssertionError(
            "step 5 must create a SELECT policy on memberships with a USING clause"
        )
    return match.group(1)


def test_step5_migration_filename_signals_the_approach() -> None:
    # Migration filenames are part of the contract. A reviewer scanning
    # supabase/migrations should be able to tell at a glance that step
    # 5 took the "non-recursive EXISTS" route, distinct from step 4's
    # "security definer helper" route.
    path = migration_path("0004")
    assert path.name.endswith(".sql")
    assert "exists" in path.name or "non_recursive" in path.name


def test_step5_drops_the_step4_policy_first() -> None:
    sql = _fix_sql()
    # Step 4 already created memberships_select_same_team. Re-creating
    # it without dropping first would fail with "policy already exists",
    # so the migration has to be idempotent against the prior state.
    assert re.search(
        r"drop policy (?:if exists )?memberships_select_same_team "
        r"on (?:public\.)?memberships",
        sql,
    )


def test_step5_drops_the_step4_helper_function() -> None:
    sql = _fix_sql()
    # Step 5 is an alternative to step 4, not an addition. Leaving the
    # is_team_member helper in place would muddle the comparison the
    # article makes between the two approaches and leave a definer
    # function with no caller.
    assert re.search(
        r"drop function (?:if exists )?(?:public\.)?is_team_member"
        r"\s*\(\s*uuid\s*\)",
        sql,
    )


def test_step5_creates_replacement_policy_on_memberships() -> None:
    sql = _fix_sql()
    assert re.search(
        r"create policy \w+ on (?:public\.)?memberships\s+for select",
        sql,
    )


def test_step5_policy_uses_exists_against_a_different_base_table() -> None:
    clause = _policy_clause(_fix_sql())
    # The whole point of fix attempt 2: the EXISTS subquery reads from
    # public.teams, a base table that the rewriter can scan without
    # re-firing the memberships policy. That severs the loop step 3
    # captured.
    assert re.search(r"exists\s*\(", clause)
    assert re.search(r"from\s+(?:public\.)?teams", clause)


def test_step5_policy_correlates_teams_id_with_membership_team_id() -> None:
    clause = _policy_clause(_fix_sql())
    # The EXISTS has to bind the teams row to the candidate membership
    # row's team_id; otherwise it would degrade into "does the caller
    # own any team at all", which is not a per-row check.
    assert re.search(
        r"(?:t|teams)\.id\s*=\s*(?:memberships\.)?team_id",
        clause,
    )


def test_step5_policy_filters_teams_by_auth_uid() -> None:
    clause = _policy_clause(_fix_sql())
    # The teams scan has to be scoped to the calling user via auth.uid(),
    # otherwise every authenticated caller would see every membership.
    assert "auth.uid()" in clause
    assert re.search(
        r"(?:t|teams)\.owner_id\s*=\s*auth\.uid\(\)",
        clause,
    )


def test_step5_policy_allows_caller_to_see_their_own_row() -> None:
    clause = _policy_clause(_fix_sql())
    # The narrower semantic this step accepts is "you can see your own
    # membership row or membership rows of teams you own". The self-row
    # branch (user_id = auth.uid()) is what makes the policy useful for
    # non-owner members at all — without it a regular member could not
    # even see their own membership.
    assert re.search(r"user_id\s*=\s*auth\.uid\(\)", clause)


def test_step5_policy_combines_branches_with_or() -> None:
    clause = _policy_clause(_fix_sql())
    # The two branches (self-row + owner-of-team) have to be OR-ed.
    # AND-ing them would collapse the policy down to "you own the team
    # AND it's your row", which excludes co-owner relationships and is
    # almost certainly not what the product wants.
    assert re.search(r"\bor\b", clause)


def test_step5_policy_does_not_select_from_memberships() -> None:
    clause = _policy_clause(_fix_sql())
    # Re-introducing a `select ... from memberships` inside the USING
    # clause would resurrect the step-2 recursion the whole series is
    # about. Guard it explicitly.
    assert not re.search(
        r"select[^)]*from\s+(?:public\.)?memberships",
        clause,
    ), (
        "step 5's USING clause must not read from memberships — that "
        "would re-introduce the step-2 recursion"
    )


def test_step5_does_not_reintroduce_security_definer() -> None:
    sql = _fix_sql()
    # The alternative-fix narrative depends on this migration NOT
    # creating a definer-rights function. If a future edit smuggles
    # `security definer` back in, the article's comparison collapses.
    assert "security definer" not in sql


def test_step5_does_not_recreate_is_team_member() -> None:
    sql = _fix_sql()
    # Symmetric guard: step 5 drops the helper, it must not also
    # re-create it. A `drop ... create` pair would leave the database
    # in the same shape as step 4 and erase the point of this step.
    assert not re.search(
        r"create (?:or replace )?function (?:public\.)?is_team_member\s*\(",
        sql,
    )
