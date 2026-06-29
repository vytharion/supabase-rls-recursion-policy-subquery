"""Structural tests for the step-5 JWT-claims membership policy.

Step 5 is the alternative to step 4's SECURITY DEFINER helper. Instead
of routing the membership lookup through a definer-rights function,
this migration moves the membership list onto the JWT itself: the
policy reads app_metadata.team_ids directly via auth.jwt() and decides
visibility from a pure boolean expression. No SELECT runs inside the
USING clause, so the rewriter has no subquery to expand and the 42P17
cycle from step 3 cannot reappear.

These tests stay offline. Each assertion parses the migration text and
checks a structural property — the same regex-based approach every
other test module in this codebase uses. They double as the human
checklist a reviewer can run against any future "tidy" pass on the
file: drop a clause, the regex fails.
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


def test_step5_migration_filename_signals_jwt_app_metadata() -> None:
    # Migration filenames are part of the contract. A reviewer scanning
    # supabase/migrations should be able to tell at a glance that step
    # 5 took the JWT/app_metadata route, distinct from step 4's
    # security-definer-helper route.
    path = migration_path("0004")
    assert path.name.endswith(".sql")
    assert "jwt" in path.name
    assert "app_metadata" in path.name or "metadata" in path.name


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
    # Step 5 is an alternative to step 4, not a layer on top of it. The
    # SECURITY DEFINER helper becomes dead surface area the moment the
    # policy stops calling it — leaving it on disk would ship a
    # privilege-escalating function with no caller.
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


def test_step5_policy_reads_from_auth_jwt() -> None:
    clause = _policy_clause(_fix_sql())
    # The whole point of fix attempt 2: the policy decides from the
    # token, not from a database lookup. auth.jwt() is the documented
    # accessor for the request's verified claim set in Supabase.
    assert re.search(r"auth\.jwt\s*\(\s*\)", clause)


def test_step5_policy_references_app_metadata() -> None:
    clause = _policy_clause(_fix_sql())
    # app_metadata is the server-controlled half of the JWT — the
    # client cannot mutate it. user_metadata would be wrong here
    # because a malicious caller could rewrite it from the browser.
    assert "app_metadata" in clause


def test_step5_policy_references_team_ids_claim() -> None:
    clause = _policy_clause(_fix_sql())
    # team_ids is the array key the membership-change hook is expected
    # to keep in sync. Misnaming the claim would silently collapse the
    # policy to "you can only see your own row" for every caller.
    assert "team_ids" in clause


def test_step5_policy_uses_jsonb_containment_operator() -> None:
    clause = _policy_clause(_fix_sql())
    # `?` is the jsonb "contains element" operator. It evaluates as a
    # pure boolean — no subquery, no function call to a definer-rights
    # helper, no read against any table.
    assert re.search(r"\?\s*(?:public\.)?memberships\.team_id", clause) or re.search(
        r"\?\s*memberships\.team_id", clause
    ) or re.search(r"\?\s*team_id::text", clause)


def test_step5_policy_casts_team_id_to_text_for_containment() -> None:
    clause = _policy_clause(_fix_sql())
    # The `?` operator's right-hand side is text. memberships.team_id
    # is uuid, so it has to be cast. Without the cast Postgres raises
    # "operator does not exist: jsonb ? uuid" at policy evaluation.
    assert re.search(r"team_id::text", clause)


def test_step5_policy_allows_caller_to_see_their_own_row() -> None:
    clause = _policy_clause(_fix_sql())
    # The narrow semantic this step accepts is "you can see your own
    # membership row, or any membership row for a team listed in your
    # JWT's app_metadata.team_ids". Without the self-row branch a
    # caller would be invisible to themselves until their JWT
    # refreshed with the new team_ids array.
    assert re.search(r"user_id\s*=\s*auth\.uid\(\)", clause)


def test_step5_policy_combines_branches_with_or() -> None:
    clause = _policy_clause(_fix_sql())
    # The two branches (self-row, JWT-claimed team) have to be OR-ed.
    # AND-ing would collapse the policy to "your own row AND a team in
    # your claim", which silently locks every cross-team viewer out.
    assert re.search(r"\bor\b", clause)


def test_step5_policy_contains_no_subquery_at_all() -> None:
    clause = _policy_clause(_fix_sql())
    # The headline property of fix attempt 2: there is no SELECT inside
    # the USING clause. The rewriter has nothing to expand, so the
    # cycle that step 3 captured cannot reappear regardless of which
    # row is being checked. Guard the property explicitly so a future
    # edit cannot smuggle a subquery back in.
    assert not re.search(r"\bselect\b", clause), (
        "step 5's USING clause must not contain a SELECT — the whole "
        "point of the JWT-claims approach is to eliminate the subquery"
    )


def test_step5_policy_does_not_read_from_memberships() -> None:
    clause = _policy_clause(_fix_sql())
    # Symmetric guard against the step-2 recursion. The JWT-claims
    # policy must not read from memberships at all — even through a
    # join or a CTE.
    assert not re.search(
        r"from\s+(?:public\.)?memberships",
        clause,
    )


def test_step5_policy_does_not_read_from_teams() -> None:
    clause = _policy_clause(_fix_sql())
    # The alternative approach (EXISTS against public.teams) read from
    # teams. The JWT-claims approach is supposed to eliminate ALL
    # subqueries, so any reference to a base table from inside the
    # USING clause means the fix degraded back to a subquery form.
    assert not re.search(
        r"from\s+(?:public\.)?teams",
        clause,
    )


def test_step5_policy_has_fallback_for_missing_claim() -> None:
    clause = _policy_clause(_fix_sql())
    # If a caller's JWT does not carry app_metadata.team_ids the raw
    # extraction returns NULL, and `NULL ? text` yields NULL — which
    # Postgres treats as "not satisfying the policy" but also makes
    # the boolean expression brittle. COALESCE to an empty jsonb array
    # keeps the expression a well-formed boolean for every caller.
    assert "coalesce" in clause
    assert re.search(r"\[\]'?::jsonb", clause) or re.search(
        r"'\[\]'\s*::\s*jsonb", clause
    )


def test_step5_does_not_reintroduce_security_definer() -> None:
    sql = _fix_sql()
    # The alternative-fix narrative depends on this migration NOT
    # creating a definer-rights function. If a future edit smuggles
    # `security definer` back in the article's comparison collapses.
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


def test_step4_security_definer_migration_is_untouched() -> None:
    # Step 5 is a sibling fix, not a rewrite of step 4. The previous
    # migration must stay byte-stable so its commit history remains a
    # truthful "fix attempt 1" snapshot the article can compare against.
    prior = normalized(migration_path("0003").read_text())
    assert "create or replace function public.is_team_member" in prior
    assert "security definer" in prior
