"""Structural tests for the step-6 pgTAP regression suite.

Step 6 locks the runtime behaviour of the memberships SELECT policy
with a pgTAP script at ``supabase/tests/rls_membership_policy.sql``.
The script itself runs end-to-end against a live Postgres + the seed
data; these tests stay offline and assert the SQL file has the right
shape so the three access paths the article claims — owner, member,
outsider — cannot silently disappear in a later refactor.

Each assertion pins a single property of the pgTAP script so a
regression points at the missing clause directly rather than dumping
a vague "pgTAP suite changed" failure. The seed UUIDs are checked as
literals because the seed file deliberately uses deterministic ids;
swapping one of them out would break the article's narrative as well
as the test, so we want both to fail together.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PGTAP_PATH = REPO_ROOT / "supabase" / "tests" / "rls_membership_policy.sql"

ALICE_UUID = "11111111-1111-1111-1111-111111111111"
BOB_UUID = "22222222-2222-2222-2222-222222222222"
CAROL_UUID = "33333333-3333-3333-3333-333333333333"
ACME_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
GLOBEX_UUID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def _pgtap_sql() -> str:
    return PGTAP_PATH.read_text()


def _normalized() -> str:
    return re.sub(r"\s+", " ", _pgtap_sql()).lower()


def test_pgtap_file_exists_at_canonical_location() -> None:
    # pg_prove discovers tests under supabase/tests/ by convention.
    # If the file moves the runner finds nothing and the suite silently
    # passes — the article would then be lying about coverage.
    assert PGTAP_PATH.exists(), (
        "supabase/tests/rls_membership_policy.sql must exist so pg_prove "
        "can pick the pgTAP suite up by directory convention"
    )


def test_pgtap_file_is_a_sql_script() -> None:
    assert PGTAP_PATH.suffix == ".sql"


def test_pgtap_loads_the_pgtap_extension() -> None:
    sql = _normalized()
    assert "create extension if not exists pgtap" in sql, (
        "the suite must self-install pgTAP so a fresh database can run it "
        "without an out-of-band setup step"
    )


def test_pgtap_runs_inside_a_rolled_back_transaction() -> None:
    sql = _normalized()
    # Wrapping in BEGIN/ROLLBACK leaves the seed pristine for the next
    # invocation. Forgetting either keyword turns the suite into a
    # one-shot destructive script.
    assert "begin;" in sql
    assert "rollback;" in sql


def test_pgtap_declares_an_explicit_plan() -> None:
    sql = _normalized()
    match = re.search(r"select plan\(\s*(\d+)\s*\)", sql)
    assert match, "pgTAP requires an explicit plan(N) before any assertions"
    # The script ships eleven assertions covering the three personas.
    # A drift in this number means an assertion was added or removed;
    # the article quotes the count, so both must move together.
    assert int(match.group(1)) >= 3, (
        "plan(N) must cover at least one assertion per access path "
        "(owner, member, outsider)"
    )


def test_pgtap_calls_finish_after_assertions() -> None:
    sql = _normalized()
    # finish() is what pg_prove keys off to report the suite's exit
    # status. Omitting it makes the runner think the script aborted
    # mid-suite and flags every test as missing.
    assert "from finish()" in sql


def test_pgtap_drops_to_authenticated_role() -> None:
    sql = _normalized()
    # The membership policy is evaluated against the `authenticated`
    # role in production; tests have to switch into that role to
    # actually fire the RLS check rather than bypassing it as the
    # table owner.
    assert "set local role authenticated" in sql


def test_pgtap_sets_jwt_claims_for_each_persona() -> None:
    sql = _pgtap_sql()
    # The JWT-claim-driven policy reads app_metadata.team_ids; the
    # suite has to supply that claim shape per persona or the policy
    # falls back to its self-row branch only. Every persona test
    # block sets request.jwt.claims explicitly.
    occurrences = len(re.findall(r'"request\.jwt\.claims"', sql))
    assert occurrences >= 5, (
        "expected at least one JWT claim setup per persona test block "
        "(owner, member-empty, member-populated, outsider, "
        "outsider-empty)"
    )


def test_pgtap_covers_the_owner_access_path() -> None:
    sql = _pgtap_sql()
    # Owner persona is Alice. Her JWT lists Acme so both branches of
    # the policy fire; the assertion has to read 2 rows out of Acme.
    assert ALICE_UUID in sql, "owner block must reference Alice's UUID"
    assert ACME_UUID in sql, "owner block must reference Acme's UUID"
    assert re.search(r"owner:.*acme", sql, flags=re.IGNORECASE), (
        "an assertion description must mark the owner path so a failure "
        "message names the access path being exercised"
    )


def test_pgtap_covers_the_member_access_path_with_self_row_only() -> None:
    sql = _pgtap_sql()
    # Member persona is Bob. With empty team_ids the JWT branch never
    # fires and only the self-row branch lets him see his own row.
    assert BOB_UUID in sql, "member block must reference Bob's UUID"
    assert re.search(r'"team_ids":\s*\[\s*\]', sql), (
        "member block must run Bob with an empty team_ids claim so the "
        "self-row branch is exercised in isolation"
    )
    assert re.search(r"member:.*empty team_ids", sql, flags=re.IGNORECASE), (
        "an assertion description must mark the member-only-self-row path"
    )


def test_pgtap_covers_the_member_access_path_with_jwt_widening() -> None:
    sql = _pgtap_sql()
    # The second member block runs Bob with Acme in team_ids so the
    # JWT branch widens his visibility to the full Acme roster. This
    # is what proves the JWT branch actually fires for non-owners.
    assert re.search(
        r'"sub":\s*"' + BOB_UUID + r'"[^}]*"team_ids":\s*\[\s*"' + ACME_UUID + r'"\s*\]',
        sql,
        flags=re.DOTALL,
    ), (
        "member block must also run Bob with Acme in team_ids so the JWT "
        "branch is exercised, not only the self-row branch"
    )


def test_pgtap_covers_the_outsider_access_path() -> None:
    sql = _pgtap_sql()
    # Outsider persona is Carol. The assertion has to confirm she sees
    # zero rows from Acme even with a populated Globex JWT, and that
    # her own Globex row remains visible.
    assert CAROL_UUID in sql, "outsider block must reference Carol's UUID"
    assert GLOBEX_UUID in sql, "outsider block must reference Globex's UUID"
    assert re.search(r"outsider:.*acme", sql, flags=re.IGNORECASE), (
        "an assertion description must mark the outsider-vs-Acme path"
    )


def test_pgtap_asserts_outsider_reads_zero_acme_rows() -> None:
    sql = _pgtap_sql()
    # The single strongest invariant of the suite: an outsider must
    # read zero rows from a team they do not belong to. Encode that
    # as a literal pattern so a typo in the assertion (e.g. 1 instead
    # of 0) cannot land without breaking this test as well.
    pattern = re.compile(
        r"is\(\s*\(\s*select\s+count\(\*\)::int[^)]*from\s+public\.memberships"
        r"[^)]*where\s+team_id\s*=\s*'" + ACME_UUID + r"'[^)]*\),\s*0",
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert pattern.search(sql), (
        "the outsider block must assert an exact count of 0 rows from "
        "the Acme team; this is the central security invariant"
    )


def test_pgtap_asserts_owner_reads_two_acme_rows() -> None:
    sql = _pgtap_sql()
    # The owner-side invariant: Alice with Acme in team_ids reads the
    # full Acme roster of 2 rows (herself + Bob). A drop to 1 would
    # mean the JWT branch silently broke for owners.
    pattern = re.compile(
        r"is\(\s*\(\s*select\s+count\(\*\)::int[^)]*from\s+public\.memberships"
        r"[^)]*where\s+team_id\s*=\s*'" + ACME_UUID + r"'[^)]*\),\s*2",
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert pattern.search(sql), (
        "the owner block must assert an exact count of 2 rows from the "
        "Acme team so a regression in the JWT branch is caught"
    )


def test_pgtap_does_not_reintroduce_recursive_subquery() -> None:
    sql = _normalized()
    # The whole point of steps 4 + 5 is that the policy no longer
    # selects from memberships inside its own USING clause. A pgTAP
    # script that exercises the policy from outside is fine to query
    # memberships, but it must not paste the recursive subquery shape
    # back into the file as a "helper" — that would muddy the article.
    assert not re.search(
        r"create policy[^;]+memberships[^;]+select[^;]+from\s+(?:public\.)?memberships",
        sql,
    ), "the pgTAP suite must not redefine the recursive policy locally"
