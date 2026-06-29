"""Structural tests for the step-3 recursion-trace artifacts.

Step 3 adds two files alongside the reproduction script:

* ``supabase/scripts/recursion_trace.sql`` — a diagnostic script that
  inspects ``pg_policies``, ``pg_rewrite``, and an ``EXPLAIN`` of the
  failing query so an engineer can see *why* Postgres refuses the
  SELECT.
* ``supabase/scripts/recursion_trace_notes.md`` — a written walkthrough
  of the rewriter's behaviour, naming the C function and source line
  that raises the error.

These tests pin both files so the matching article section
(``docs/03-*.mdx``) can quote them verbatim and stay in sync with the
code.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "supabase" / "scripts"
TRACE_SQL_PATH = SCRIPTS_DIR / "recursion_trace.sql"
TRACE_NOTES_PATH = SCRIPTS_DIR / "recursion_trace_notes.md"


def _trace_sql() -> str:
    return TRACE_SQL_PATH.read_text().lower()


def _trace_notes() -> str:
    return TRACE_NOTES_PATH.read_text()


# ---------------------------------------------------------------------------
# recursion_trace.sql
# ---------------------------------------------------------------------------


def test_trace_sql_exists() -> None:
    assert TRACE_SQL_PATH.exists(), (
        "supabase/scripts/recursion_trace.sql must exist so the article "
        "can show the diagnostic queries used to trace the recursion"
    )


def test_trace_sql_inspects_pg_policies() -> None:
    sql = _trace_sql()
    # pg_policies surfaces the stored USING clause; if a future refactor
    # drops this probe the trace loses its most direct evidence.
    assert "from pg_policies" in sql
    assert "memberships" in sql


def test_trace_sql_inspects_pg_rewrite() -> None:
    sql = _trace_sql()
    # pg_rewrite is the catalog fireRIRrules walks; its presence in the
    # trace is what ties the runtime error to the rewriter pass.
    assert "from pg_rewrite" in sql


def test_trace_sql_runs_explain_to_prove_planner_time_error() -> None:
    sql = _trace_sql()
    # EXPLAIN never executes, so seeing it raise 42P17 is the proof that
    # the recursion is detected during planning, not during scan.
    assert "explain" in sql
    assert "from public.memberships" in sql or "from memberships" in sql


def test_trace_sql_uses_authenticated_role() -> None:
    sql = _trace_sql()
    # RLS is skipped for the owner / superuser. The trace must drop to
    # the role PostgREST uses or the recursion will never fire.
    assert "set local role authenticated" in sql


def test_trace_sql_is_wrapped_in_a_transaction() -> None:
    sql = _trace_sql()
    assert "begin;" in sql and "rollback;" in sql


def test_trace_sql_includes_control_probe() -> None:
    sql = _trace_sql()
    # The contrast against a non-policied table (teams) is what proves
    # the bug is policy-specific rather than a wider RLS misconfig.
    assert "from public.teams" in sql or "from teams" in sql


# ---------------------------------------------------------------------------
# recursion_trace_notes.md
# ---------------------------------------------------------------------------


def test_trace_notes_exists() -> None:
    assert TRACE_NOTES_PATH.exists(), (
        "supabase/scripts/recursion_trace_notes.md must exist so the "
        "article can quote the rewriter walkthrough"
    )


def test_trace_notes_names_firerirrules() -> None:
    notes = _trace_notes()
    # The error transcript points at fireRIRrules; the notes must name
    # that function so a reader following the LOCATION line lands here.
    assert "fireRIRrules" in notes


def test_trace_notes_references_rewrite_handler_source() -> None:
    notes = _trace_notes()
    assert "rewriteHandler.c" in notes


def test_trace_notes_mentions_sqlstate() -> None:
    notes = _trace_notes()
    assert "42P17" in notes


def test_trace_notes_walks_at_least_three_expansion_levels() -> None:
    notes = _trace_notes()
    # The walkthrough explains why the rewriter never reaches a fixed
    # point — that requires showing at least three successive depth
    # levels (input, first wrap, second wrap).
    for marker in ("depth 0", "depth 1", "depth 2"):
        assert marker in notes, f"trace notes must show {marker!r}"


def test_trace_notes_explains_planner_time_failure() -> None:
    notes = _trace_notes()
    # EXPLAIN raising the same error is the proof point used by the
    # SQL script. The notes must call that out so the two artefacts
    # reinforce each other.
    assert "EXPLAIN" in notes


def test_trace_notes_previews_both_upcoming_fixes() -> None:
    notes = _trace_notes()
    # Step 4 uses SECURITY DEFINER, step 5 uses a non-recursive EXISTS
    # rewrite. The trace already points at both so the reader knows
    # where the series is heading.
    assert "SECURITY DEFINER" in notes
    assert "EXISTS" in notes


def test_trace_notes_mentions_authenticated_role_requirement() -> None:
    notes = _trace_notes()
    # Skipping the role switch is the most common reason engineers
    # think the policy "works" locally; the notes must warn about it.
    assert "authenticated" in notes
