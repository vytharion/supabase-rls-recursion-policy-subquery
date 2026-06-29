-- Deterministic fixtures so the tutorial can show identical query
-- output across reruns. Three users, two teams, three memberships:
--   alice owns acme
--   bob is an admin in acme + outsider to globex
--   carol owns globex
-- The outsider relationships are what later steps query to prove
-- the RLS policy refuses cross-tenant reads.

insert into auth.users (id, email) values
    ('11111111-1111-1111-1111-111111111111', 'alice@example.test'),
    ('22222222-2222-2222-2222-222222222222', 'bob@example.test'),
    ('33333333-3333-3333-3333-333333333333', 'carol@example.test')
on conflict (id) do nothing;

insert into public.teams (id, name, owner_id) values
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Acme',   '11111111-1111-1111-1111-111111111111'),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Globex', '33333333-3333-3333-3333-333333333333')
on conflict (id) do nothing;

insert into public.memberships (team_id, user_id, role) values
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 'owner'),
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '22222222-2222-2222-2222-222222222222', 'admin'),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '33333333-3333-3333-3333-333333333333', 'owner')
on conflict (team_id, user_id) do nothing;
