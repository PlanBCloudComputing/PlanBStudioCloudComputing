# Role design (owner: Steven)

This file drives the schema, the auth code and the psql denial demo. It is the plan for `db/migrations/001_roles.sql`, `002_schema.sql` and `003_policies.sql`. The starting table is in `PLAN.md` section 5.

Two marked criteria stay separate:
- **Accounts**: the `users` and `event_members` tables, and the Flask code around them.
- **Database policies**: only what PostgreSQL itself refuses (GRANTs, RLS, no UPDATE/DELETE on `decision_log`).

Login roles are **capability tiers, not people**. A person has one row in `users`, and one membership role per event in `event_members`. Flask picks the database role that matches the membership role (`app/auth.py: role_to_pool`).

## 0. Two layers of defence

1. **GRANT** (the tier): what kind of statement the database role may run on which table or column. A refused GRANT gives `ERROR: permission denied`.
2. **RLS** (the row filter): which rows that tier may see or change, based on the caller's membership on that event. A refused RLS read or update usually gives **zero rows, not an error**. Only an INSERT that breaks a policy raises `ERROR: new row violates row-level security policy`.

Flask tells the database who is calling with `set_config('app.user_id', '<uuid>', true)` at the start of every transaction (`true` = local to the transaction, like `SET LOCAL`). Nothing is stored between requests, so Cloud Run replicas behave the same.

## 1. Login roles and GRANTs

| Role | Login? | Tables and actions allowed |
|---|---|---|
| `planb_migrator` | No | Owns all tables, functions and policies. Runs migrations only. The app never connects as it. |
| `planb_auth` | Yes | `users`: SELECT, INSERT. `event_members`: SELECT. Nothing else. Used for register, login, role lookup and finding a user by email. |
| `planb_viewer` | Yes | SELECT on `events`, `event_members`, `activities`, `plans`, `plan_items`, `weather_snapshots`, `comparisons`, `decision_log`, and on `users(id, email, display_name)` only (never `password_hash`). |
| `planb_editor` | Yes | Viewer rights, plus INSERT/UPDATE/DELETE on `activities`, `plans`, `plan_items`; UPDATE on `events(title, event_date, timezone, venue_name, venue_lat, venue_lon)`; INSERT on `comparisons`. |
| `planb_lead` | Yes | Viewer rights, plus UPDATE on `activities` limited to the columns `title, notes, duration_minutes, max_precip_prob, max_wind_kmh, fallback_title, fallback_duration_minutes`. |
| `planb_organiser` | Yes | Editor rights, plus INSERT on `events`, DELETE on `events`, INSERT/UPDATE/DELETE on `event_members`, INSERT on `decision_log`. |
| `weather_ingest` | Yes | INSERT and SELECT on `weather_snapshots` only. Used only by Katie's weather adapter. |

Rules that apply to every role:
- `REVOKE ALL ... FROM PUBLIC` on every table and on the `public` schema's CREATE right, so nothing is open by default. Then grant only what the table above lists.
- **No role gets UPDATE or DELETE on `decision_log`, not even the organiser.** The log is append-only. This is a GRANT, not an RLS policy, so it cannot be bypassed by a policy mistake.
- App roles are created `NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`, and they own nothing. So `DROP TABLE` fails with `must be owner of table ...`.
- The app never connects as `postgres`, `planb_migrator` or any admin role. `postgres` is for running migrations by hand.
- Login passwords are not in git. Locally they are fake placeholders in `docker-compose.yml`. On Cloud SQL they are random, set with `ALTER ROLE`, and stored in the `planb-db-passwords` secret by Alvi.

Additions beyond the `PLAN.md` table, needed by `docs/API_SPEC.md` (flag to Alvi and Katie):
- `PATCH /events/{id}` is editor+, so editor and organiser need UPDATE on the listed `events` columns.
- `POST /events` and `DELETE /events/{id}` need INSERT/DELETE on `events` for the organiser tier.
- `POST /events/{id}/comparisons` is editor+, so editor and organiser need INSERT on `comparisons`.
- Viewer and above need SELECT on three `users` columns, to show member names.

## 2. Row-level security policies

RLS is switched on for every table except `users` (see the note on `users` below). App roles are non-owners, so RLS always applies to them. `planb_migrator` owns the tables but cannot log in. We do not use `FORCE ROW LEVEL SECURITY`, because the helper functions below rely on the owner reading `event_members` without recursion; since nobody can log in as the owner, FORCE would add nothing.

### Helper functions

All are owned by `planb_migrator`, `SECURITY DEFINER`, with `SET search_path = public`. `EXECUTE` is revoked from PUBLIC and granted to the app roles. They exist so a policy can look at `event_members` without the policy on `event_members` calling itself forever.

| Function | Returns | Meaning |
|---|---|---|
| `app_user_id()` | uuid | `nullif(current_setting('app.user_id', true), '')::uuid`. NULL if Flask did not set it, so nothing matches. |
| `role_rank(text)` | int | viewer 1, lead 2, editor 3, organiser 4. |
| `member_role(event_id)` | text | The caller's role on that event, or NULL. |
| `has_role(event_id, min_role)` | boolean | `role_rank(member_role(event_id)) >= role_rank(min_role)`. |
| `is_event_owner(event_id)` | boolean | `events.owner_id = app_user_id()`. Used only for the first-organiser step. |
| `event_has_members(event_id)` | boolean | Any row in `event_members` for that event. Used only for the first-organiser step. |
| `shares_event_with(user_id)` | boolean | The caller and that user are members of one common event. |

### Policies per table

"Tier" is the database role the policy applies to (`TO ...`). V = viewer, L = lead, E = editor, O = organiser.

| Table | Command | Tier | Condition |
|---|---|---|---|
| `events` | SELECT | V, L, E, O | `has_role(id, 'viewer')` |
| `events` | INSERT | O | `owner_id = app_user_id()` (the first-organiser rule, see section 3) |
| `events` | UPDATE | E, O | `has_role(id, 'editor')` (USING and WITH CHECK) |
| `events` | DELETE | O | `has_role(id, 'organiser')` |
| `event_members` | SELECT | V, L, E, O | `has_role(event_id, 'viewer')` (every member can list the members) |
| `event_members` | SELECT | auth | `true` (needs the role lookup before an event context exists; the role has SELECT only) |
| `event_members` | INSERT | O | `has_role(event_id, 'organiser')`, OR the bootstrap row: `user_id = app_user_id() AND role = 'organiser' AND is_event_owner(event_id) AND NOT event_has_members(event_id)` |
| `event_members` | UPDATE, DELETE | O | `has_role(event_id, 'organiser')` |
| `activities` | SELECT | V, L, E, O | `has_role(event_id, 'viewer')` |
| `activities` | INSERT, DELETE | E, O | `has_role(event_id, 'editor')` |
| `activities` | UPDATE | E, O | `has_role(event_id, 'editor')` |
| `activities` | UPDATE | **L** | `lead_user_id = app_user_id() AND has_role(event_id, 'lead')` (USING and WITH CHECK, so a lead cannot hand the activity to someone else). The column list is limited by GRANT, so `start_time`, `outdoor` and `lead_user_id` cannot be changed. |
| `plans`, `plan_items` | SELECT | V, L, E, O | `has_role(event_id, 'viewer')` |
| `plans`, `plan_items` | INSERT, UPDATE, DELETE | E, O | `has_role(event_id, 'editor')` |
| `weather_snapshots` | SELECT | V, L, E, O | `has_role(event_id, 'viewer')` |
| `weather_snapshots` | INSERT | weather_ingest | `has_role(event_id, 'editor')`; the adapter's transaction carries the caller's `app.user_id`, so a refresh by a viewer is refused even through this role |
| `weather_snapshots` | SELECT | weather_ingest | `has_role(event_id, 'editor')` |
| `comparisons` | SELECT | V, L, E, O | `has_role(event_id, 'viewer')` |
| `comparisons` | INSERT | E, O | `has_role(event_id, 'editor') AND created_by = app_user_id()` |
| `decision_log` | SELECT | V, L, E, O | `has_role(event_id, 'viewer')` |
| `decision_log` | INSERT | O | `has_role(event_id, 'organiser') AND created_by = app_user_id()` |
| `decision_log` | UPDATE, DELETE | nobody | No GRANT, so no policy is needed |

**`users`**: RLS is on, with two policies. `planb_auth` can SELECT and INSERT any row (it must find the user by email before anyone is logged in). The four membership tiers see only `id = app_user_id() OR shares_event_with(id)`, and only the columns `id, email, display_name`. `password_hash` is readable by `planb_auth` only. Looking up a user by email to add a member goes through `planb_auth`, then the insert goes through the organiser tier.

### The lead rule, in one line

`planb_lead` has an UPDATE policy on `activities` that requires `lead_user_id = app_user_id()`. For any other activity the UPDATE succeeds and changes **0 rows** (no error). Flask turns "0 rows changed" into 403 or 404 after checking.

### Setting the user ID

Every `get_conn(role, user_id)` runs `SELECT set_config('app.user_id', %s, true)` first. In psql the demo does the same by hand inside `BEGIN; ... COMMIT;`.

## 3. Schema

All ids are `uuid`; Flask generates them (`uuid4`) so inserts need no `RETURNING`. Timestamps are `timestamptz` in UTC. Column names match `docs/API_SPEC.md`.

| Table | Columns | Keys and checks |
|---|---|---|
| `users` | `id`, `email`, `display_name`, `password_hash`, `created_at` | PK `id`; unique index on `lower(email)` (409 on duplicate); `display_name` length 1-60 |
| `events` | `id`, `owner_id`, `title`, `event_date` (date), `timezone`, `venue_name`, `venue_lat`, `venue_lon`, `created_at`, `updated_at` | PK `id`; FK `owner_id` to `users`; `venue_lat` -90..90, `venue_lon` -180..180 |
| `event_members` | `event_id`, `user_id`, `role`, `added_at` | PK `(event_id, user_id)`; FK `event_id` to `events` ON DELETE CASCADE; FK `user_id` to `users`; `role` in (viewer, lead, editor, organiser); unique `(event_id, user_id)` is the target of the activity lead key |
| `activities` | `id`, `event_id`, `title`, `start_time` (time), `duration_minutes`, `outdoor`, `max_precip_prob`, `max_wind_kmh`, `lead_user_id` (nullable), `fallback_title`, `fallback_duration_minutes`, `notes`, `created_at` | PK `id`; unique `(event_id, id)`; FK `event_id` CASCADE; composite FK `(event_id, lead_user_id)` to `event_members(event_id, user_id)` (a lead must be a member of the same event; NULL skips the check); checks: `duration_minutes` 5-480, `max_precip_prob` 0-100, `max_wind_kmh` 0-120, fallback duration 5-480 when set |
| `plans` | `id`, `event_id`, `label`, `created_at` | PK `id`; unique `(event_id, id)`; FK `event_id` CASCADE |
| `plan_items` | `id`, `plan_id`, `event_id`, `activity_id`, `start_time`, `use_fallback` | PK `id`; composite FK `(event_id, plan_id)` to `plans(event_id, id)` CASCADE; composite FK `(event_id, activity_id)` to `activities(event_id, id)` CASCADE; unique `(plan_id, activity_id)` (409 if already in plan) |
| `weather_snapshots` | `id`, `event_id`, `fetched_at`, `expires_at`, `hourly` (jsonb) | PK `id`; unique `(event_id, id)`; FK `event_id` CASCADE |
| `comparisons` | `id`, `event_id`, `snapshot_id`, `method_version`, `seed`, `runs`, `results` (jsonb), `created_by`, `created_at` | PK `id`; unique `(event_id, id)`; composite FK `(event_id, snapshot_id)` to `weather_snapshots(event_id, id)`; FK `created_by` to `users`; `runs` 100-5000 |
| `decision_log` | `id`, `event_id`, `plan_id`, `comparison_id`, `note`, `created_by`, `created_at` | PK `id`; composite FKs `(event_id, plan_id)` to `plans`, `(event_id, comparison_id)` to `comparisons`; FK `created_by` to `users`. Append-only. |

**Indexes** (besides the keys): `events(owner_id)`, `event_members(user_id)` (finds a user's events), `activities(event_id)`, `plans(event_id)`, `plan_items(plan_id)`, `weather_snapshots(event_id, fetched_at DESC)` (latest snapshot), `comparisons(event_id, created_at DESC)`, `decision_log(event_id, created_at)`.

### Decisions settled

- **First organiser.** Any logged-in user may create an event. Flask opens one transaction as `planb_organiser` with the creator's `app.user_id`. It INSERTs the event (policy: `owner_id = app_user_id()`), then INSERTs the creator's `organiser` membership row. The bootstrap clause on `event_members` allows that single row only when the caller owns the event and it has no members yet. Nobody can use it to join someone else's event. The event id is generated in Flask, so the insert needs no `RETURNING` (which would need SELECT access before the membership row exists).
- **Who reads `users` at login.** `planb_auth`: SELECT and INSERT on `users`, SELECT on `event_members` for the role lookup (`require_role`). Nothing else.
- **How the lead rule works.** See section 2: GRANT limits the columns, the policy limits the rows by `lead_user_id`.
- **Cross-event references.** Every child table carries `event_id`, and each reference to a sibling table is a composite foreign key `(event_id, other_id)`. A plan item for event A pointing at an activity of event B has no matching `(event_id, id)` pair, so PostgreSQL refuses it with a foreign-key error (Flask answers 422). The same applies to a plan or comparison named in `decision_log`, a snapshot named in `comparisons`, and a lead who is not a member of that event.
- **Last organiser (409).** Enforced in Flask, in one transaction that first locks the organiser rows with `SELECT ... FOR UPDATE`, then counts them. A database trigger is possible but is a Phase 2 extra, not needed for the marks.
- **Limits of 20 activities and 3 plans per event.** Checked in Flask (422), not in the database.
- **Removing a member who leads an activity.** The composite key blocks it (no `ON DELETE` action). Flask first clears `lead_user_id` on that member's activities in the same transaction.

## 4. Connection handling

- One small pool per database role, **created lazily** the first time that role is used in a process. Pools are keyed by role and held in module-level state in `app/db.py`; that holds only connections, never a "current user".
- Each pool holds at most 1-2 connections. The user id is passed per transaction, so the same pooled connection can serve different people safely: `set_config(..., true)` is cleared when the transaction ends.
- Budget: connections ≈ instances × worker processes × roles × pool size. With Cloud Run capped at 3 instances, 1 worker, 6 login roles and a pool of 1, that is at most 18. A pool of 2 gives 36. The `db-f1-micro` instance has a small `max_connections` (to confirm with `SHOW max_connections;` on `planb-db`). Start with a pool size of 1, and count Alvi's gunicorn worker setting before raising it.
- Connections go through the Cloud SQL connector or the unix socket Cloud Run provides, never a public IP.

## 5. Demo script (psql, no Flask)

Run with real logins as each role (through the Cloud SQL Auth Proxy, or against the local Docker database), never as `postgres`. The seed data has three users: **A** (organiser), **B** (lead of activity 2), **C** (lead of activity 3), one event, three activities, one plan, one comparison. IDs below are placeholders, written `:A`, `:B`, `:event`.

| # | Command (outline) | Expected output |
|---|---|---|
| 1 | `\du` | The six app roles are listed with no `Superuser`, no `Bypass RLS`, no `Create role`, no `Create DB`. `planb_migrator` shows `Cannot login`. |
| 2 | `\dp` | Access privileges per table match section 1: `decision_log` shows `INSERT`/`SELECT` for the organiser tier and never `UPDATE` or `DELETE`. |
| 3 | Connect as `planb_viewer`. `BEGIN; SELECT set_config('app.user_id', :'A', true); INSERT INTO activities (...) VALUES (...);` | `ERROR: permission denied for table activities` |
| 4 | Connect as `planb_viewer`, same transaction style: `SELECT count(*) FROM activities;` | Count of the event's activities. Same query with another user's id (not a member): count 0. |
| 5 | Connect as `planb_editor`. `INSERT INTO decision_log (...) VALUES (...);` | `ERROR: permission denied for table decision_log` |
| 6 | Connect as `planb_lead`, user B. `UPDATE activities SET title = 'x' WHERE id = :activity_of_C;` then `SELECT title FROM activities WHERE id = :activity_of_C;` | `UPDATE 0`, and the title is unchanged. (No error: RLS filtered the row.) |
| 7 | Same lead, own activity: `UPDATE activities SET title = 'x' WHERE id = :activity_of_B;` | `UPDATE 1` |
| 8 | Same lead, forbidden column: `UPDATE activities SET start_time = '09:00' WHERE id = :activity_of_B;` | `ERROR: permission denied for table activities` (column not granted) |
| 9 | Connect as `planb_organiser`, user A. `INSERT INTO decision_log (id, event_id, plan_id, comparison_id, note, created_by) VALUES (...);` | `INSERT 0 1` |
| 10 | Same organiser: `UPDATE decision_log SET note = 'edit' WHERE id = :log;` | `ERROR: permission denied for table decision_log` |
| 11 | Same organiser: `DELETE FROM decision_log WHERE id = :log;` | `ERROR: permission denied for table decision_log` |
| 12 | Same organiser: `DROP TABLE activities;` | `ERROR: must be owner of table activities` |
| 13 | Cross-event reference: as editor, `INSERT INTO plan_items` with an activity of another event | `ERROR: insert or update on table "plan_items" violates foreign key constraint` |

The exact text of each message is captured from a real run in P2-S4 and saved in `docs/psql_demo_output.txt`. Until then this column is what we expect.

### Gotchas to test (and not to hide in the demo)

- RLS gives **zero rows or `UPDATE 0`** instead of an error. Rows 4 and 6 show unchanged data, not an error. Only an INSERT that violates a policy raises one (`new row violates row-level security policy`).
- Owners and superusers bypass RLS. Always test with a real login or `SET ROLE` to an app role, never as `postgres`. A test as `postgres` proves nothing.
- If `app.user_id` is unset, `app_user_id()` returns NULL and every membership check is false, so a forgotten `set_config` returns nothing rather than leaking rows. Add a test for it.
- Policies on `event_members` that query `event_members` recurse forever. That is why the helper functions are `SECURITY DEFINER`.
- Cross-user tests (P2-S5): user A cannot read user B's event (404 in Flask, 0 rows in psql), forged parent ids rejected by foreign keys, role matrix viewer/lead/editor/organiser/outsider.

## 6. Open questions for the lecturer

- One login role per person, or per type of user? (We designed per type, with the person identified by `app.user_id` and per-event membership rows.)
- Is it acceptable that a few columns are protected by column-level GRANTs plus RLS together (the lead rule), or should that be split into two separate demonstrations?

## 7. Open items for the team

- Alvi: confirm `max_connections` on `planb-db` and the gunicorn worker count (section 4).
- Katie: the weather adapter must call `get_conn('weather_ingest', user_id)` with the real user id, because the insert policy checks the caller's role (section 2).
- All three: approve the extra GRANTs listed at the end of section 1, since `API_SPEC.md` is the contract.
