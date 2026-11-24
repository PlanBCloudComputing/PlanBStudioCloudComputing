-- psql_demo.sql: the database-policy demo (video scene 7). No Flask involved.
--
-- Purpose: show, with real output, that PostgreSQL itself enforces the rules in
-- docs/ROLE_DESIGN.md: the app roles have no admin rights, a viewer cannot write,
-- an editor cannot touch the decision log, a lead can change only their own
-- activity, the decision log cannot be edited or deleted even by the organiser,
-- and tables cannot be dropped.
--
-- How to run (local Docker database, started with `docker compose up -d`):
--   PGPASSWORD=local_dev_only psql -h localhost -p 5433 -U planb_viewer -d planb -a -f docs/psql_demo.sql
-- Against Cloud SQL through the Auth Proxy, use the proxy host and port and put each
-- role's password in your ~/.pgpass (never in this file). Never connect as postgres.
--
-- Important logic:
--   * Every step logs in as a real app role with \c, never as postgres. The setup
--     steps (creating users, an event, activities) also use only app roles.
--   * "Who is calling" is passed the way Flask does it: set_config('app.user_id', ..., true)
--     inside a transaction, so row-level security can see the caller.
--   * Each attempt that may fail runs in its own transaction and ends with ROLLBACK,
--     because after an error PostgreSQL ignores everything until the transaction ends.
--   * Row-level security usually shows up as "0 rows" (UPDATE 0, or no rows selected),
--     not as an error. Only an INSERT that breaks a policy raises an error.
--   * Each run uses fresh ids and email addresses, so it can be repeated. Note that the
--     decision row it records can never be deleted (that is the point of the demo).

\set ON_ERROR_STOP off
\pset pager off

\echo
\echo '=== 1. Who are the roles? (no superuser and no Bypass RLS on the app roles) ==='
\du

\echo
\echo '=== 2. What may each role do? (grants, column grants and policies) ==='
\dp decision_log
\dp activities
\dp users

-- ---------------------------------------------------------------------------
\echo
\echo '=== Setup: fresh ids, then create the demo data using app roles only ==='
SELECT substr(md5(random()::text), 1, 8) AS tag,
       gen_random_uuid() AS org_id,   gen_random_uuid() AS lead_b_id,
       gen_random_uuid() AS lead_c_id, gen_random_uuid() AS editor_id,
       gen_random_uuid() AS viewer_id, gen_random_uuid() AS stranger_id,
       gen_random_uuid() AS event_id, gen_random_uuid() AS act_b, gen_random_uuid() AS act_c,
       gen_random_uuid() AS plan_id, gen_random_uuid() AS snap_id,
       gen_random_uuid() AS cmp_id, gen_random_uuid() AS decision_id \gset

\c planb planb_auth
INSERT INTO users (id, email, display_name, password_hash) VALUES
    (:'org_id',    'demo-org-'    || :'tag' || '@example.com', 'Olivia (organiser)', 'not-a-real-hash'),
    (:'lead_b_id', 'demo-leadb-'  || :'tag' || '@example.com', 'Ben (lead)',         'not-a-real-hash'),
    (:'lead_c_id', 'demo-leadc-'  || :'tag' || '@example.com', 'Cara (lead)',        'not-a-real-hash'),
    (:'editor_id', 'demo-editor-' || :'tag' || '@example.com', 'Ed (editor)',        'not-a-real-hash'),
    (:'viewer_id', 'demo-viewer-' || :'tag' || '@example.com', 'Vic (viewer)',       'not-a-real-hash');

\c planb planb_organiser
BEGIN;
SELECT set_config('app.user_id', :'org_id', true) \gset
INSERT INTO events (id, owner_id, title, event_date, timezone, venue_name, venue_lat, venue_lon)
    VALUES (:'event_id', :'org_id', 'Summer fete', '2026-12-20', 'Europe/London', 'Village green', 51.5, -0.1);
-- The first organiser row: allowed only because the caller owns the event and it has no members yet.
INSERT INTO event_members (event_id, user_id, role) VALUES (:'event_id', :'org_id', 'organiser');
INSERT INTO event_members (event_id, user_id, role) VALUES
    (:'event_id', :'lead_b_id', 'lead'), (:'event_id', :'lead_c_id', 'lead'),
    (:'event_id', :'editor_id', 'editor'), (:'event_id', :'viewer_id', 'viewer');
INSERT INTO activities (id, event_id, title, start_time, duration_minutes, lead_user_id) VALUES
    (:'act_b', :'event_id', 'Rounders',  '10:00', 60, :'lead_b_id'),
    (:'act_c', :'event_id', 'Quiz',      '12:00', 60, :'lead_c_id');
INSERT INTO plans (id, event_id, label) VALUES (:'plan_id', :'event_id', 'Original');
COMMIT;

\c planb weather_ingest
BEGIN;
SELECT set_config('app.user_id', :'org_id', true) \gset
INSERT INTO weather_snapshots (id, event_id, fetched_at, expires_at, hourly)
    VALUES (:'snap_id', :'event_id', now(), now() + interval '1 hour', '[]');
COMMIT;

\c planb planb_organiser
BEGIN;
SELECT set_config('app.user_id', :'org_id', true) \gset
INSERT INTO comparisons (id, event_id, snapshot_id, method_version, seed, runs, results, created_by)
    VALUES (:'cmp_id', :'event_id', :'snap_id', 'v1', 1, 100, '[]', :'org_id');
COMMIT;

-- ---------------------------------------------------------------------------
\echo
\echo '=== 3. A viewer can read but INSERT is denied ==='
\c planb planb_viewer
BEGIN;
SELECT set_config('app.user_id', :'viewer_id', true) \gset
SELECT title, start_time FROM activities ORDER BY start_time;
INSERT INTO activities (id, event_id, title, start_time, duration_minutes)
    VALUES (gen_random_uuid(), :'event_id', 'Sneaky extra', '15:00', 30);
ROLLBACK;

\echo
\echo '=== 4. Row-level security: someone who is not a member sees no rows (no error) ==='
BEGIN;
SELECT set_config('app.user_id', :'stranger_id', true) \gset
SELECT count(*) AS activities_a_stranger_can_see FROM activities;
ROLLBACK;

\echo
\echo '=== 5. Normal tiers cannot read password hashes ==='
BEGIN;
SELECT set_config('app.user_id', :'viewer_id', true) \gset
SELECT password_hash FROM users;
ROLLBACK;

-- ---------------------------------------------------------------------------
\echo
\echo '=== 6. An editor can change activities but cannot write the decision log ==='
\c planb planb_editor
BEGIN;
SELECT set_config('app.user_id', :'editor_id', true) \gset
UPDATE activities SET notes = 'bring a tent' WHERE id = :'act_b';
INSERT INTO decision_log (id, event_id, plan_id, comparison_id, created_by)
    VALUES (gen_random_uuid(), :'event_id', :'plan_id', :'cmp_id', :'editor_id');
ROLLBACK;

-- ---------------------------------------------------------------------------
\echo
\echo '=== 7. A lead changes 0 rows on another lead''s activity (no error), data unchanged ==='
\c planb planb_lead
BEGIN;
SELECT set_config('app.user_id', :'lead_b_id', true) \gset
SELECT title AS cara_activity_before FROM activities WHERE id = :'act_c';
UPDATE activities SET title = 'Hijacked by Ben' WHERE id = :'act_c';
SELECT title AS cara_activity_after FROM activities WHERE id = :'act_c';
ROLLBACK;

\echo
\echo '=== 8. The same lead CAN change their own activity (UPDATE 1) ... ==='
BEGIN;
SELECT set_config('app.user_id', :'lead_b_id', true) \gset
UPDATE activities SET title = 'Rounders (renamed by its lead)' WHERE id = :'act_b';
SELECT title FROM activities WHERE id = :'act_b';
ROLLBACK;

\echo
\echo '=== 9. ... but only the allowed columns: start_time is refused ==='
BEGIN;
SELECT set_config('app.user_id', :'lead_b_id', true) \gset
UPDATE activities SET start_time = '09:00' WHERE id = :'act_b';
ROLLBACK;

-- ---------------------------------------------------------------------------
\echo
\echo '=== 10. The organiser can INSERT into the decision log ==='
\c planb planb_organiser
BEGIN;
SELECT set_config('app.user_id', :'org_id', true) \gset
INSERT INTO decision_log (id, event_id, plan_id, comparison_id, note, created_by)
    VALUES (:'decision_id', :'event_id', :'plan_id', :'cmp_id', 'Going with the original plan', :'org_id');
COMMIT;

\echo
\echo '=== 11. ... but UPDATE and DELETE are denied, even for the organiser ==='
BEGIN;
SELECT set_config('app.user_id', :'org_id', true) \gset
UPDATE decision_log SET note = 'quietly rewritten' WHERE id = :'decision_id';
ROLLBACK;
BEGIN;
SELECT set_config('app.user_id', :'org_id', true) \gset
DELETE FROM decision_log WHERE id = :'decision_id';
ROLLBACK;
BEGIN;
SELECT set_config('app.user_id', :'org_id', true) \gset
SELECT note, created_at FROM decision_log WHERE id = :'decision_id';
ROLLBACK;

\echo
\echo '=== 12. An event with recorded decisions cannot be deleted ==='
BEGIN;
SELECT set_config('app.user_id', :'org_id', true) \gset
DELETE FROM events WHERE id = :'event_id';
ROLLBACK;

\echo
\echo '=== 13. The organiser tier cannot be used by someone who is not an organiser of the event ==='
BEGIN;
SELECT set_config('app.user_id', :'stranger_id', true) \gset
INSERT INTO decision_log (id, event_id, plan_id, comparison_id, created_by)
    VALUES (gen_random_uuid(), :'event_id', :'plan_id', :'cmp_id', :'stranger_id');
ROLLBACK;

\echo
\echo '=== 14. DROP TABLE is denied (the app roles own nothing) ==='
BEGIN;
DROP TABLE activities;
ROLLBACK;

\echo
\echo '=== Done. Nothing above used postgres or any role with admin rights. ==='
