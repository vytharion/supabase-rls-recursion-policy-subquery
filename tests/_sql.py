"""Small helpers for asserting structural properties of SQL migrations.

We do not run a Postgres instance in tests. Instead we normalize the migration
text (strip comments, collapse whitespace, lowercase) and use regex matches to
check that the bootstrap migration creates the expected objects.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS_DIR = REPO_ROOT / "supabase" / "migrations"
SEED_PATH = REPO_ROOT / "supabase" / "seed.sql"
PGTAP_TESTS_DIR = REPO_ROOT / "supabase" / "tests"


def pgtap_test_path(stem: str) -> Path:
    matches = sorted(PGTAP_TESTS_DIR.glob(f"{stem}*.sql"))
    if not matches:
        raise AssertionError(
            f"no pgTAP test starting with {stem!r} in {PGTAP_TESTS_DIR}"
        )
    return matches[0]


def latest_migration_path() -> Path:
    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not files:
        raise AssertionError(f"no migration files found in {MIGRATIONS_DIR}")
    return files[-1]


def migration_path(prefix: str) -> Path:
    matches = sorted(MIGRATIONS_DIR.glob(f"{prefix}*.sql"))
    if not matches:
        raise AssertionError(f"no migration starting with {prefix!r} in {MIGRATIONS_DIR}")
    return matches[0]


def _strip_comments(sql: str) -> str:
    sql = re.sub(r"--[^\n]*", "", sql)
    sql = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    return sql


def normalized(sql: str) -> str:
    return re.sub(r"\s+", " ", _strip_comments(sql)).strip().lower()


def _name_pattern(table: str) -> str:
    if "." in table:
        schema, name = table.split(".", 1)
        return rf"(?:{re.escape(schema)}\.)?{re.escape(name)}"
    return rf"(?:\w+\.)?{re.escape(table)}"


def create_table_body(sql_norm: str, table: str) -> str:
    pattern = (
        rf"create table (?:if not exists )?{_name_pattern(table)}\s*\((.*?)\)\s*;"
    )
    match = re.search(pattern, sql_norm)
    if not match:
        raise AssertionError(f"create table {table} not found in migration")
    return match.group(1)


def count_inserts(sql_norm: str, table: str) -> int:
    pattern = (
        rf"insert into {_name_pattern(table)}[^;]*?values\s*(.*?)\s*on conflict"
    )
    match = re.search(pattern, sql_norm)
    if not match:
        raise AssertionError(f"insert into {table} not found in seed")
    values_block = match.group(1)
    return values_block.count("(")
