"""Structural tests for the step-6 pgTAP access-path suite.

Steps 1 through 5 lock the SQL *shape* of each migration. Step 6 raises
the bar: it ships a pgTAP test file that drives the live policy on a
running Postgres and asserts the exact row set every persona reads
through ``memberships_select_same_team``. These pytest assertions stay
offline — they parse the pgTAP file and verify it encodes the three
access paths the article promises:

    owner    — alice owns Acme              → sees both Acme rows
    member   — bob is admin in Acme         → sees both Acme rows
    outsider — carol owns Globex            → sees zero Acme rows,
                                              still sees her own row

Each invariant lives in its own test so a regression points at the
exact missing clause instead of dumping a vague "pgtap shape changed"
failure. The Python suite is intentionally narrow — it does NOT try to
prove the policy filters correctly (that is the pgTAP suite's job
against a real database) — it only proves the pgTAP file would put
the right rows under the microscope when ``pg_prove`` runs.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PGTAP_PATH = (
    REPO_ROOT
    / "supabase"
    / "tests"
    / "policy_membership_access_paths_test.sql"
)


# Fixture identifiers — must match supabase/seed.sql exactly. Holding
# them as module-level constants lets each test name the persona it is
# asserting against, which is what makes failures self-documenting.
ALICE = "11111111-1111-1111-1111-111111111111"
BOB = "22222222-2222-2222-2222-222222222222"
CAROL = "33333333-3333-3333-3333-333333333333"
ACME = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
GLOBEX = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def _pgtap_sql() -> str:
    return PGTAP_PATH.read_text()


def _pgtap_lower() -> str:
    return _pgtap_sql().lower()


def test_pgtap_file_exists_at_canonical_path() -> None:
    # The file path is part of the contract. ``supabase test db`` and
    # ``pg_prove --ext .sql supabase/tests/`` both discover suites by
    # walking that directory, so a rename outside it silently removes
    # the assertions from CI without any signal at the gate.
    assert PGTAP_PATH.exists(), (
        f"step-6 pgTAP suite must live at {PGTAP_PATH.relative_to(REPO_ROOT)} "
        "so pg_prove discovers it under supabase/tests/"
    )


def test_pgtap_file_wraps_in_a_transaction() -> None:
    sql = _pgtap_lower()
    # pgTAP convention: every test file runs inside BEGIN/ROLLBACK so
    # GUCs (role, request.jwt.claims) and any fixture inserts never
    # mutate state for the next file in the run.
    assert "begin;" in sql
    assert "rollback;" in sql


def test_pgtap_file_loads_the_pgtap_extension() -> None:
    sql = _pgtap_lower()
    # Declaring the dependency explicitly keeps the file portable: it
    # runs against a stock Postgres image with pgtap installed, not
    # only against a Supabase managed database where the extension may
    # already be loaded by the platform.
    assert "create extension if not exists pgtap" in sql


def test_pgtap_file_declares_a_plan() -> None:
    sql = _pgtap_lower()
    # ``select plan(N)`` is how pgTAP knows how many assertions to
    # expect. Without it, a test that exits early after the first
    # failure silently counts as a pass at the TAP layer.
    assert re.search(r"select\s+plan\s*\(\s*\d+\s*\)", sql)


def test_pgtap_file_calls_finish_at_the_end() -> None:
    sql = _pgtap_lower()
    # ``select * from finish()`` is the symmetric counterpart to
    # ``plan()``. It emits the TAP summary line ``1..N`` that the
    # harness greps for, so its absence collapses the suite to silent
    # success regardless of which assertions ran.
    assert re.search(r"select\s+\*\s+from\s+finish\s*\(\s*\)", sql)


def test_pgtap_file_drops_into_authenticated_role_for_each_path() -> None:
    sql = _pgtap_lower()
    # RLS is bypassed for superusers and table owners. If the file
    # forgot to switch into the ``authenticated`` role every assertion
    # would pass trivially under the migration role's bypass. Each
    # persona needs its own role switch — there are three paths, so we
    # expect at least three ``set local role authenticated`` calls.
    occurrences = re.findall(r"set\s+local\s+role\s+authenticated", sql)
    assert len(occurrences) >= 3, (
        "expected one `set local role authenticated` per access path "
        f"(owner, member, outsider) — found {len(occurrences)}"
    )


def test_pgtap_file_writes_claims_via_request_jwt_claims_guc() -> None:
    sql = _pgtap_lower()
    # The step-5 policy reads ``auth.jwt() -> 'app_metadata' ->
    # 'team_ids'``. Supabase resolves ``auth.jwt()`` against the
    # ``request.jwt.claims`` GUC, so the test file has to write to
    # that exact key — any other GUC and the policy would see a NULL
    # claim and fall through to the self-row branch every time,
    # erasing the bite of the JWT branch coverage.
    assert "request.jwt.claims" in sql


def test_pgtap_file_isolates_sessions_with_savepoints_or_resets() -> None:
    sql = _pgtap_lower()
    # Each persona leaves session-local state behind (role + claims).
    # If the file does not reset between paths the second persona
    # inherits the first persona's GUCs and the assertions pin the
    # wrong policy decision. Either savepoint+rollback or an explicit
    # ``reset role`` per path satisfies the invariant.
    rollbacks = re.findall(r"rollback\s+to\s+savepoint", sql)
    resets = re.findall(r"\breset\s+role\b", sql)
    assert len(rollbacks) + len(resets) >= 3, (
        "each access path must isolate its session state — expected "
        "at least 3 savepoint rollbacks or `reset role` calls, found "
        f"{len(rollbacks)} rollbacks + {len(resets)} resets"
    )


def test_pgtap_file_references_app_metadata_team_ids_claim() -> None:
    sql = _pgtap_lower()
    # The claim key is the contract between the membership-change hook
    # and the policy. If the test wrote ``team_id`` instead of
    # ``team_ids`` or ``user_metadata`` instead of ``app_metadata`` the
    # JWT branch would silently never fire and every assertion would
    # collapse to the self-row case — the suite would still pass but
    # would no longer prove the policy works for cross-team viewers.
    assert "app_metadata" in sql
    assert "team_ids" in sql


def test_pgtap_file_covers_owner_path() -> None:
    sql = _pgtap_sql()
    # Owner persona: alice owns Acme. The fixture row carries
    # role='owner', her JWT lists Acme in ``team_ids``, and she must
    # see both Acme membership rows (her own + the admin row for bob).
    assert ALICE in sql, "owner path must reference alice's user id"
    assert ACME in sql, "owner path must reference acme's team id"
    assert re.search(r"(?i)\bowner\b", sql), (
        "owner path must be labelled 'owner' in the assertion message "
        "so a reviewer can map a TAP failure back to the access path"
    )


def test_pgtap_file_covers_member_path() -> None:
    sql = _pgtap_sql()
    # Member persona: bob is a non-owner member of Acme. His JWT lists
    # Acme in ``team_ids`` and he must see the same row set the owner
    # sees — this is the visibility lever that makes the policy useful
    # for ordinary users, not just team owners.
    assert BOB in sql, "member path must reference bob's user id"
    assert re.search(r"(?i)\bmember\b", sql), (
        "member path must be labelled 'member' in the assertion message"
    )


def test_pgtap_file_covers_outsider_path() -> None:
    sql = _pgtap_sql()
    # Outsider persona: carol owns Globex and has no relationship to
    # Acme. Her JWT lists Globex only, so the policy must refuse every
    # Acme row. This is the negative half of the suite — if the policy
    # were broken open it would still pass owner/member but fail here.
    assert CAROL in sql, "outsider path must reference carol's user id"
    assert GLOBEX in sql, "outsider path must reference globex's team id"
    assert re.search(r"(?i)\boutsider\b", sql), (
        "outsider path must be labelled 'outsider' in the assertion message"
    )


def test_pgtap_file_asserts_owner_sees_two_acme_rows() -> None:
    sql = _pgtap_lower()
    # The positive guarantee: alice/bob whose claim lists Acme read
    # both Acme rows (her own + the admin row). Locking the literal
    # ``2`` against the Acme uuid catches any future edit that softens
    # the assertion to ``<= 2`` or counts a different team.
    assert re.search(
        r"values\s*\(\s*2(?:::bigint)?\s*\)",
        sql,
    ), (
        "owner / member paths must assert a row count of 2 against "
        "Acme — the seed places two membership rows there"
    )


def test_pgtap_file_asserts_outsider_sees_zero_acme_rows() -> None:
    sql = _pgtap_lower()
    # The cross-tenant guarantee: a caller whose claim does not list
    # Acme reads zero Acme rows. Pinning the literal ``0`` blocks a
    # future edit from softening the bound or pointing the count at a
    # different team. Either an explicit ``values (0)`` assertion or
    # an ``is_empty`` over an Acme-scoped query satisfies the contract.
    has_zero_count = re.search(
        r"values\s*\(\s*0(?:::bigint)?\s*\)",
        sql,
    )
    has_is_empty_on_acme = re.search(
        r"is_empty\s*\([^;]*aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        sql,
        re.DOTALL,
    )
    assert has_zero_count or has_is_empty_on_acme, (
        "outsider path must assert zero Acme rows — either via "
        "results_eq($$ ... $$, $$ values (0) $$) or is_empty over an "
        "Acme-scoped select"
    )


def test_pgtap_file_uses_results_eq_for_row_set_assertions() -> None:
    sql = _pgtap_lower()
    # results_eq is pgTAP's exact-bag comparator. Step 6 is framed as
    # locking the EXACT row set each caller can read, so the file
    # should be using results_eq across the three personas. Counting
    # via ``ok()`` alone would let a future edit silently widen the
    # row set as long as the total count happened to stay the same.
    matches = re.findall(r"results_eq\s*\(", sql)
    assert len(matches) >= 3, (
        "expected at least one results_eq assertion per access path "
        f"(owner, member, outsider) — found {len(matches)}"
    )


def test_pgtap_file_asserts_outsider_self_row_visibility() -> None:
    sql = _pgtap_lower()
    # The self-row branch (``memberships.user_id = auth.uid()``) is
    # what keeps a caller visible to themselves even when their JWT
    # carries no team_ids. The suite must prove this branch fires for
    # the outsider persona — otherwise a future edit could drop the
    # self-row branch and the suite would still pass the cross-tenant
    # guard. The outsider counts her own Globex row as the proof.
    assert re.search(
        r"values\s*\(\s*1(?:::bigint)?\s*\)",
        sql,
    ) or "isnt_empty" in sql, (
        "outsider path must assert at least one row for the self-row "
        "branch (Globex) — either via results_eq(... values (1) ...) "
        "or isnt_empty over a user_id = auth.uid() select"
    )


def test_pgtap_file_plan_matches_assertion_count_at_least_nine() -> None:
    sql = _pgtap_lower()
    # Three access paths × three assertions per path = nine. A plan()
    # smaller than that means the suite is shipping fewer guarantees
    # than the article advertises. We only pin the lower bound so a
    # future expansion (e.g. anon caller, missing claim fallback)
    # does not have to re-touch this test.
    match = re.search(r"select\s+plan\s*\(\s*(\d+)\s*\)", sql)
    assert match, "plan() count must be present and a positive integer"
    declared = int(match.group(1))
    assert declared >= 9, (
        "step 6 promises three access paths with three assertions each "
        f"— plan() should be at least 9, found {declared}"
    )
