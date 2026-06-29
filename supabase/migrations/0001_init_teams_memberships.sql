-- Bootstrap schema for the RLS recursion tutorial.
-- Two domain tables that mirror a classic multi-tenant Supabase setup:
--   teams       : one row per workspace / organisation
--   memberships : join row linking auth.users to teams with a role
-- A stub auth.users table stands in for the real Supabase auth schema so
-- the seed + later policies can reference it without depending on the
-- managed auth.users table being present in a plain Postgres database.
-- RLS is enabled on both domain tables but no policies are attached
-- here. Step 2 adds the naive policy that triggers the recursion.

create extension if not exists pgcrypto;

create schema if not exists auth;

create table if not exists auth.users (
    id uuid primary key default gen_random_uuid(),
    email text unique not null
);

create table if not exists public.teams (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    owner_id uuid not null references auth.users(id) on delete cascade,
    created_at timestamptz not null default now()
);

create table if not exists public.memberships (
    id uuid primary key default gen_random_uuid(),
    team_id uuid not null references public.teams(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    role text not null check (role in ('owner', 'admin', 'member')),
    created_at timestamptz not null default now(),
    unique (team_id, user_id)
);

create index if not exists memberships_user_id_idx
    on public.memberships (user_id);

create index if not exists memberships_team_id_idx
    on public.memberships (team_id);

alter table public.teams enable row level security;
alter table public.memberships enable row level security;
