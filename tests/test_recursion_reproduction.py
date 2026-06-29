"""Structural tests for the step-2 recursion-reproduction artifacts.

Step 2 ships two side-car files next to the migration: a SQL script that
demonstrates how to trigger the recursion as a non-superuser session, and
a transcript capturing the exact server-side error message that script
produces. These tests pin the shape of both files so the article in
docs/02-*.mdx can quote them verbatim and stay in sync with the code.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "supabase" / "scripts"
REPRODUCE_PATH = SCRIPTS_DIR / "reproduce_recursion.sql"
EXPECTED_ERROR_PATH = SCRIPTS_DIR / "expected_recursion_error.txt"


def _reproduce_sql() -> str:
    return REPRODUCE_PATH.read_text().lower()


def _expected_error() -> str:
    return EXPECTED_ERROR_PATH.read_text()


def test_reproduce_script_exists() -> None:
    assert REPRODUCE_PATH.exists(), (
        "supabase/scripts/reproduce_recursion.sql must exist so the article "
        "can show how to trigger the error"
    )


def test_reproduce_script_runs_inside_a_transaction() -> None:
    sql = _reproduce_sql()
    assert "begin;" in sql and "rollback;" in sql, (
        "wrap the demonstration in BEGIN/ROLLBACK so re-running it leaves "
        "no side effects on the seed data"
    )


def test_reproduce_script_drops_to_a_non_superuser_role() -> None:
    sql = _reproduce_sql()
    # RLS is bypassed for superusers and table owners, so the reproduction
    # has to switch into a role that actually evaluates the policy.
    assert "set local role authenticated" in sql


def test_reproduce_script_sets_a_jwt_subject() -> None:
    sql = _reproduce_sql()
    # auth.uid() inside the policy reads request.jwt.claim.sub; without it
    # the USING clause would never resolve to a real user id.
    assert "request.jwt.claim.sub" in sql


def test_reproduce_script_selects_from_memberships() -> None:
    sql = _reproduce_sql()
    assert "from public.memberships" in sql or "from memberships" in sql


def test_expected_error_captures_recursion_message() -> None:
    transcript = _expected_error()
    assert (
        "infinite recursion detected in policy for relation \"memberships\""
        in transcript
    )


def test_expected_error_carries_postgres_sqlstate() -> None:
    transcript = _expected_error()
    # SQLSTATE 42P17 = invalid_object_definition, the canonical code the
    # planner raises when it gives up on rewriting a recursive policy.
    assert "42P17" in transcript
