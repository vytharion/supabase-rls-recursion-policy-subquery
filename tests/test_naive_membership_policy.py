"""Structural tests for the step-2 naive RLS policy migration.

Step 2 introduces a SELECT policy on public.memberships whose USING clause
runs a subquery against public.memberships itself. This is the classic
Supabase RLS recursion trap: evaluating the policy requires re-entering it.
We assert the migration encodes that shape so later steps have something
concrete to break, diagnose, and fix.
"""
from __future__ import annotations

import re

from tests._sql import migration_path, normalized


def _policy_sql() -> str:
    return normalized(migration_path("0002").read_text())


def _policy_clause(sql: str) -> str:
    pattern = (
        r"create policy \w+ on (?:public\.)?memberships\s+"
        r"for select\s+using\s*\((.*?)\)\s*;"
    )
    match = re.search(pattern, sql)
    if not match:
        raise AssertionError("expected a SELECT policy on memberships with a USING clause")
    return match.group(1)


def test_policy_migration_attaches_policy_to_memberships() -> None:
    sql = _policy_sql()
    assert re.search(r"create policy \w+ on (?:public\.)?memberships", sql)


def test_policy_is_for_select() -> None:
    sql = _policy_sql()
    assert re.search(
        r"create policy \w+ on (?:public\.)?memberships\s+for select", sql
    )


def test_policy_subquery_references_memberships_itself() -> None:
    clause = _policy_clause(_policy_sql())
    # The recursion comes from selecting from the same table the policy is
    # attached to; if a later commit accidentally points the subquery at
    # something else, this test catches it.
    assert re.search(r"from\s+(?:public\.)?memberships", clause)


def test_policy_subquery_filters_by_auth_uid() -> None:
    clause = _policy_clause(_policy_sql())
    assert "auth.uid()" in clause


def test_policy_compares_team_id_against_subquery() -> None:
    clause = _policy_clause(_policy_sql())
    assert re.search(r"team_id\s+in\s*\(", clause)


def test_bootstrap_migration_still_has_no_policies() -> None:
    # Step 1's migration must remain policy-free so the recursion is
    # attributable to step 2's commit. If a refactor later folds the
    # policy back into 0001 this test fails loudly.
    sql = normalized(migration_path("0001").read_text())
    assert "create policy" not in sql
