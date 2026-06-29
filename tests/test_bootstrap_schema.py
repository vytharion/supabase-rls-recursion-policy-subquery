"""Structural tests for the step-1 bootstrap migration + seed.

These tests do not require Postgres. They verify that the SQL files describe
the schema later steps depend on: a stub auth.users, plus public.teams and
public.memberships with the right foreign keys and the role check constraint.
RLS must be enabled on both domain tables so step 2's policy attaches in the
right place.
"""
from __future__ import annotations

import re

from tests._sql import (
    SEED_PATH,
    count_inserts,
    create_table_body,
    latest_migration_path,
    normalized,
)


def _migration_sql() -> str:
    return normalized(latest_migration_path().read_text())


def _seed_sql() -> str:
    return normalized(SEED_PATH.read_text())


def test_migration_creates_auth_users_stub() -> None:
    sql = _migration_sql()
    assert "create schema if not exists auth" in sql
    body = create_table_body(sql, "auth.users")
    assert "id uuid primary key" in body
    assert "email text unique not null" in body


def test_migration_creates_teams_table() -> None:
    sql = _migration_sql()
    body = create_table_body(sql, "public.teams")
    assert "id uuid primary key" in body
    assert "name text not null" in body
    assert re.search(r"owner_id uuid not null references auth\.users\(id\)", body)
    assert "created_at timestamptz not null default now()" in body


def test_migration_creates_memberships_table() -> None:
    sql = _migration_sql()
    body = create_table_body(sql, "public.memberships")
    assert re.search(r"team_id uuid not null references (?:public\.)?teams\(id\)", body)
    assert re.search(r"user_id uuid not null references auth\.users\(id\)", body)
    assert "role text not null check (role in ('owner', 'admin', 'member'))" in body
    assert "unique (team_id, user_id)" in body


def test_migration_creates_membership_indexes() -> None:
    sql = _migration_sql()
    assert "create index if not exists memberships_user_id_idx" in sql
    assert "create index if not exists memberships_team_id_idx" in sql


def test_migration_enables_rls_on_domain_tables() -> None:
    sql = _migration_sql()
    assert "alter table public.teams enable row level security" in sql
    assert "alter table public.memberships enable row level security" in sql


def test_migration_does_not_attach_policies_yet() -> None:
    # Step 2 introduces the (broken) policy. Step 1 must stay policy-free
    # so the recursion failure is attributable to the next commit.
    sql = _migration_sql()
    assert "create policy" not in sql


def test_seed_creates_three_users() -> None:
    sql = _seed_sql()
    assert count_inserts(sql, "auth.users") == 3
    assert "alice@example.test" in sql
    assert "bob@example.test" in sql
    assert "carol@example.test" in sql


def test_seed_creates_two_teams() -> None:
    sql = _seed_sql()
    assert count_inserts(sql, "public.teams") == 2
    assert "'acme'" in sql
    assert "'globex'" in sql


def test_seed_creates_three_memberships() -> None:
    sql = _seed_sql()
    assert count_inserts(sql, "public.memberships") == 3
