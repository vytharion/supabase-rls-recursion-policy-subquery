"""Structural tests for the step-3 recursion reproduction + trace artifacts.

Step 3 has two deliverables that sit beside the step-2 migration:

* a *reproduction* pair — ``reproduce_recursion.sql`` plus the verbatim
  ``expected_recursion_error.txt`` server transcript — that proves the
  policy added in step 2 actually raises ``SQLSTATE 42P17`` against a
  live database, and
* a *trace* pair — ``recursion_trace.sql`` plus the human-readable
  ``recursion_trace_notes.md`` — that explains *why* the rewriter
  re-enters the same policy by probing ``pg_policies`` / ``pg_rewrite``
  and forcing the failure during ``EXPLAIN`` so a reader can see the
  error fires before any tuple is scanned.

These tests pin the shape of all four files so the article in
``docs/`` can quote them verbatim and never drift out of sync with the
code on disk.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "supabase" / "scripts"
REPRODUCE_PATH = SCRIPTS_DIR / "reproduce_recursion.sql"
EXPECTED_ERROR_PATH = SCRIPTS_DIR / "expected_recursion_error.txt"
TRACE_PATH = SCRIPTS_DIR / "recursion_trace.sql"
TRACE_NOTES_PATH = SCRIPTS_DIR / "recursion_trace_notes.md"


def _reproduce_sql() -> str:
    return REPRODUCE_PATH.read_text().lower()


def _expected_error() -> str:
    return EXPECTED_ERROR_PATH.read_text()


def _trace_sql() -> str:
    return TRACE_PATH.read_text().lower()


def _trace_notes() -> str:
    return TRACE_NOTES_PATH.read_text()


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


def test_trace_script_exists() -> None:
    assert TRACE_PATH.exists(), (
        "supabase/scripts/recursion_trace.sql must exist so the article "
        "can show how to inspect the catalog state behind the recursion"
    )


def test_trace_script_probes_pg_policies() -> None:
    sql = _trace_sql()
    # pg_policies confirms the naive policy is in fact what the rewriter
    # is expanding; if the trace skips this probe a reader cannot rule
    # out a stale migration as the culprit.
    assert "pg_policies" in sql


def test_trace_script_probes_pg_rewrite() -> None:
    sql = _trace_sql()
    # The self-reference lives in pg_rewrite.ev_qual; the trace must
    # show how to read it so the article can explain fireRIRrules in
    # concrete terms.
    assert "pg_rewrite" in sql


def test_trace_script_uses_explain_to_prove_planner_time_failure() -> None:
    sql = _trace_sql()
    # EXPLAIN runs the rewriter without executing the plan, which is the
    # cleanest evidence that 42P17 is raised before any tuple is scanned.
    assert "explain" in sql


def test_trace_script_runs_under_authenticated_role() -> None:
    sql = _trace_sql()
    # Catalog probes work as superuser, but the EXPLAIN that demonstrates
    # the planner-time failure only fires under a role that has to obey
    # RLS — so the script must drop privileges before that step.
    assert "set local role authenticated" in sql


def test_trace_notes_exist() -> None:
    assert TRACE_NOTES_PATH.exists(), (
        "supabase/scripts/recursion_trace_notes.md must exist as the "
        "human-readable companion to recursion_trace.sql"
    )


def test_trace_notes_name_the_postgres_function_that_raises() -> None:
    notes = _trace_notes()
    # fireRIRrules is the rewriter entry point the error LOCATION line
    # points at; calling it out by name anchors the explanation to a
    # specific piece of Postgres source so the trace cannot be hand-waved.
    assert "fireRIRrules" in notes


def test_trace_notes_reference_the_sqlstate() -> None:
    notes = _trace_notes()
    assert "42P17" in notes


def test_trace_notes_call_out_the_self_reference() -> None:
    notes = _trace_notes()
    lowered = notes.lower()
    # The whole point of the trace is that the USING clause reads from
    # the same table the policy protects; the notes must say so in
    # plain language, not just gesture at it.
    assert "self-reference" in lowered or "self reference" in lowered


def test_trace_notes_explain_planner_time_failure() -> None:
    notes = _trace_notes()
    # The notes must connect the trace's use of EXPLAIN to the claim
    # that the error fires during rewriting, not at execution time.
    lowered = notes.lower()
    assert "explain" in lowered
    assert "rewriter" in lowered or "rewriting" in lowered
