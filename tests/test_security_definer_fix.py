"""Structural tests for the step-4 SECURITY DEFINER fix migration.

Step 4 replaces the naive self-referencing policy from step 2 with a
non-recursive shape: a SECURITY DEFINER SQL function that performs the
membership lookup, and a rewritten USING clause that simply calls that
function. The function's owner-level privileges bypass RLS when the
body queries public.memberships, which severs the rewriter loop that
step 3 captured.

These tests stay offline — they assert the migration text encodes the
required shape so a later refactor cannot silently regress to the
recursive form or drop the hardening flags (STABLE, pinned
search_path, revoked public execute) that make SECURITY DEFINER safe
to ship.
"""
from __future__ import annotations

import re

from tests._sql import migration_path, normalized


def _fix_sql() -> str:
    return normalized(migration_path("0003").read_text())


def test_fix_migration_drops_the_naive_policy_first() -> None:
    sql = _fix_sql()
    # Without the drop, applying the migration twice (or on top of a db
    # that already has the step-2 policy) would error on the second
    # create. The fix has to be idempotent against the prior state.
    assert re.search(
        r"drop policy (?:if exists )?memberships_select_same_team "
        r"on (?:public\.)?memberships",
        sql,
    )


def test_fix_migration_creates_is_team_member_function() -> None:
    sql = _fix_sql()
    assert re.search(
        r"create (?:or replace )?function (?:public\.)?is_team_member\s*\(",
        sql,
    )


def test_is_team_member_takes_a_team_id_argument() -> None:
    sql = _fix_sql()
    # The policy must pass the candidate row's team_id into the helper.
    # A no-arg helper would force the helper to scan every team the
    # caller belongs to and would not compose with the USING expression.
    assert re.search(
        r"function (?:public\.)?is_team_member\s*\(\s*\w+\s+uuid\s*\)",
        sql,
    )


def test_is_team_member_returns_boolean() -> None:
    sql = _fix_sql()
    assert re.search(
        r"function (?:public\.)?is_team_member\s*\([^)]*\)\s*returns boolean",
        sql,
    )


def test_is_team_member_is_security_definer() -> None:
    sql = _fix_sql()
    # The whole point of the fix: definer-rights execution bypasses RLS
    # on public.memberships inside the function body, which is what
    # breaks the recursion the rewriter refused to expand in step 3.
    assert "security definer" in sql


def test_is_team_member_is_stable() -> None:
    sql = _fix_sql()
    # STABLE lets the planner cache the function result across the rows
    # being filtered. Without it, the helper would be re-evaluated per
    # row and the fix would re-introduce an O(N) cost on every SELECT.
    assert re.search(
        r"function (?:public\.)?is_team_member\s*\([^)]*\)[^$]*?\bstable\b",
        sql,
    )


def test_is_team_member_pins_search_path() -> None:
    sql = _fix_sql()
    # A SECURITY DEFINER function that does not pin search_path can be
    # hijacked: a caller could create a public.memberships shadow in a
    # schema earlier on the path and the function would query that
    # shadow with elevated privileges. Pinning the path is non-optional.
    assert re.search(
        r"set search_path\s*=\s*public", sql
    )


def test_is_team_member_body_queries_memberships_with_auth_uid() -> None:
    sql = _fix_sql()
    # The helper has to perform the same logical check the naive policy
    # tried to perform: is the current user a member of the target team?
    assert re.search(r"from\s+(?:public\.)?memberships", sql)
    assert "auth.uid()" in sql


def test_fix_migration_revokes_function_from_public() -> None:
    sql = _fix_sql()
    # Postgres grants EXECUTE on new functions to PUBLIC by default. A
    # SECURITY DEFINER helper inherits owner privileges, so leaving the
    # default grant in place would let any role bypass RLS by calling
    # the helper directly. Lock it down explicitly.
    assert re.search(
        r"revoke (?:all|execute)[^;]*on function (?:public\.)?is_team_member"
        r"\s*\([^)]*\)\s*from public",
        sql,
    )


def test_fix_migration_grants_execute_to_authenticated() -> None:
    sql = _fix_sql()
    # After revoking from PUBLIC we have to re-grant to the role
    # PostgREST connects as, or the policy that calls the helper would
    # fail with "permission denied for function is_team_member".
    assert re.search(
        r"grant execute on function (?:public\.)?is_team_member"
        r"\s*\([^)]*\)\s*to authenticated",
        sql,
    )


def test_fix_migration_creates_non_recursive_policy() -> None:
    sql = _fix_sql()
    match = re.search(
        r"create policy \w+ on (?:public\.)?memberships\s+"
        r"for select\s+using\s*\((.*?)\)\s*;",
        sql,
    )
    assert match, "step 4 must create a SELECT policy on memberships"
    clause = match.group(1)
    # The recursion source from step 2 was a subquery against the same
    # table inside the USING clause. The fix must NOT bring that back.
    assert not re.search(r"select[^)]*from\s+(?:public\.)?memberships", clause), (
        "the rewritten policy must not select from memberships in its USING "
        "clause — that would re-introduce the step-2 recursion"
    )


def test_fix_migration_policy_uses_the_helper_function() -> None:
    sql = _fix_sql()
    match = re.search(
        r"create policy \w+ on (?:public\.)?memberships\s+"
        r"for select\s+using\s*\((.*?)\)\s*;",
        sql,
    )
    assert match
    clause = match.group(1)
    assert re.search(
        r"(?:public\.)?is_team_member\s*\(\s*team_id\s*\)", clause
    ), "policy must call is_team_member(team_id) so the helper bypasses RLS"


def test_fix_migration_filename_signals_the_helper() -> None:
    # Migration filenames are part of the contract: a future reviewer
    # scanning supabase/migrations should be able to tell the helper
    # lives in step 4 without opening every file.
    path = migration_path("0003")
    assert "security_definer" in path.name
    assert path.name.endswith(".sql")
