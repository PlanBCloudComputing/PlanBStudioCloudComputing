"""Cross-user and role-matrix checks that PostgreSQL itself enforces (task P2-S5).

Purpose: prove, without Flask, that the GRANTs and row-level security in
db/migrations/003_policies.sql hold for every role. These are the "database policies"
the marks are for, so each test talks to the database as a real app role through
app/db.py and passes the caller with app.user_id, exactly like the routes do.
Runs on the LOCAL Docker Postgres only (host port 5433, start it with
`docker compose up -d`); skipped if it is not reachable. Never use Cloud SQL.
Remember: row-level security often means "0 rows" or "UPDATE 0", not an error;
only a refused GRANT, a broken INSERT policy or a foreign key raises an error.
"""
import json
import uuid

import psycopg
import pytest

from app import config, db

ROLES = ("auth", "viewer", "lead", "editor", "organiser", "weather_ingest")
DENIED = psycopg.errors.InsufficientPrivilege  # refused GRANT, or INSERT breaking a policy
FK = psycopg.errors.ForeignKeyViolation


def uid():
    """A new random id as text."""
    return str(uuid.uuid4())


def run(role, user_id, sql, params=()):
    """Run one statement as a database role for a user. Returns the rows, or the row count for writes."""
    with db.get_conn(role, user_id) as conn:
        cur = conn.execute(sql, params)
        return cur.fetchall() if cur.description else cur.rowcount


@pytest.fixture
def world(monkeypatch):
    """Two events with people in every role. Returns a dict of ids.

    Event 1: organiser A, leads B and C (one activity each), editor E, viewer V.
    Event 2: organiser X (one activity), and E is also an editor there.
    S is a stranger who belongs to no event.
    """
    monkeypatch.delenv("DB_INSTANCE_CONNECTION_NAME", raising=False)
    monkeypatch.setenv("DB_HOST", "localhost")
    monkeypatch.setattr(config, "DB_PORT", 5433)
    monkeypatch.setenv("DB_PASSWORDS_JSON", json.dumps({r: "local_dev_only" for r in ROLES}))
    db.close_all_pools()
    try:
        with db.get_conn("auth") as conn:
            conn.execute("SELECT 1")
    except Exception as exc:  # database not running: skip instead of failing
        db.close_all_pools()
        pytest.skip("local Docker Postgres is not reachable: %s" % exc)

    w = {name: uid() for name in "ABCEVXS"}
    w.update(ev1=uid(), ev2=uid(), act_b=uid(), act_c=uid(), act_x=uid(),
             plan1=uid(), plan2=uid())
    tag = uuid.uuid4().hex[:8]
    for name in "ABCEVXS":
        run("auth", None, "INSERT INTO users (id, email, display_name, password_hash)"
            " VALUES (%s, %s, %s, 'x')", (w[name], "pol-%s-%s@example.com" % (name, tag), "User " + name))

    def event(ev, owner, title):
        run("organiser", owner, "INSERT INTO events (id, owner_id, title, event_date, timezone,"
            " venue_name, venue_lat, venue_lon) VALUES (%s, %s, %s, '2026-12-20', 'Europe/London', 'Park', 51.5, -0.1)",
            (ev, owner, title))
        run("organiser", owner, "INSERT INTO event_members (event_id, user_id, role) VALUES (%s, %s, 'organiser')",
            (ev, owner))

    def member(ev, owner, user, role):
        run("organiser", owner, "INSERT INTO event_members (event_id, user_id, role) VALUES (%s, %s, %s)",
            (ev, user, role))

    def activity(ev, owner, act, lead=None):
        run("organiser", owner, "INSERT INTO activities (id, event_id, title, start_time, duration_minutes,"
            " lead_user_id) VALUES (%s, %s, 'Activity', '10:00', 60, %s)", (act, ev, lead))

    event(w["ev1"], w["A"], "Event one")
    for user, role in (("B", "lead"), ("C", "lead"), ("E", "editor"), ("V", "viewer")):
        member(w["ev1"], w["A"], w[user], role)
    event(w["ev2"], w["X"], "Event two")
    member(w["ev2"], w["X"], w["E"], "editor")
    activity(w["ev1"], w["A"], w["act_b"], w["B"])
    activity(w["ev1"], w["A"], w["act_c"], w["C"])
    activity(w["ev2"], w["X"], w["act_x"])
    run("organiser", w["A"], "INSERT INTO plans (id, event_id, label) VALUES (%s, %s, 'Plan')", (w["plan1"], w["ev1"]))
    run("organiser", w["X"], "INSERT INTO plans (id, event_id, label) VALUES (%s, %s, 'Plan')", (w["plan2"], w["ev2"]))
    yield w
    db.close_all_pools()


# ---- Reading: a user sees only the events they belong to -------------------------------

def test_each_user_sees_only_their_own_events(world):
    w = world
    assert {r[0] for r in run("viewer", w["V"], "SELECT id FROM events")} == {uuid.UUID(w["ev1"])}
    assert {r[0] for r in run("viewer", w["X"], "SELECT id FROM events")} == {uuid.UUID(w["ev2"])}
    assert {r[0] for r in run("viewer", w["E"], "SELECT id FROM events")} == {uuid.UUID(w["ev1"]), uuid.UUID(w["ev2"])}
    assert run("viewer", w["S"], "SELECT id FROM events") == []  # stranger: nothing, no error


def test_child_tables_follow_the_same_rule(world):
    w = world
    for table in ("activities", "plans", "event_members"):
        rows = run("viewer", w["V"], "SELECT DISTINCT event_id FROM " + table)
        assert rows == [(uuid.UUID(w["ev1"]),)]
        assert run("viewer", w["S"], "SELECT count(*) FROM " + table) == [(0,)]
    assert run("viewer", w["V"], "SELECT count(*) FROM activities WHERE event_id = %s", (w["ev2"],)) == [(0,)]


def test_without_a_user_id_nothing_is_visible(world):
    assert run("viewer", None, "SELECT count(*) FROM events") == [(0,)]
    assert run("viewer", None, "SELECT count(*) FROM activities") == [(0,)]


def test_users_table_is_limited(world):
    w = world
    with pytest.raises(DENIED):
        run("viewer", w["V"], "SELECT * FROM users")  # password_hash is not granted
    with pytest.raises(DENIED):
        run("editor", w["E"], "SELECT password_hash FROM users")
    seen = {r[0] for r in run("viewer", w["V"], "SELECT id FROM users")}
    assert uuid.UUID(w["A"]) in seen and uuid.UUID(w["V"]) in seen  # people from the same event
    assert uuid.UUID(w["X"]) not in seen and uuid.UUID(w["S"]) not in seen  # strangers are hidden


# ---- Writing: the role matrix on activities --------------------------------------------

NEW_ACTIVITY = ("INSERT INTO activities (id, event_id, title, start_time, duration_minutes)"
                " VALUES (%s, %s, 'New', '11:00', 30)")


def test_only_editor_and_organiser_tiers_can_create_activities(world):
    w = world
    for role, user in (("viewer", "V"), ("lead", "B")):
        with pytest.raises(DENIED):
            run(role, w[user], NEW_ACTIVITY, (uid(), w["ev1"]))
    assert run("editor", w["E"], NEW_ACTIVITY, (uid(), w["ev1"])) == 1
    assert run("organiser", w["A"], NEW_ACTIVITY, (uid(), w["ev1"])) == 1


def test_editor_tier_cannot_change_an_event_you_are_not_in(world):
    w = world
    # B is not a member of event 2, so even with the editor tier the policies refuse or hide it.
    with pytest.raises(DENIED):
        run("editor", w["B"], NEW_ACTIVITY, (uid(), w["ev2"]))  # not a member: policy refuses the INSERT
    # UPDATE and DELETE on rows the caller cannot see change 0 rows (no error).
    assert run("editor", w["B"], "UPDATE activities SET title = 'x' WHERE id = %s", (w["act_x"],)) == 0
    assert run("editor", w["B"], "DELETE FROM activities WHERE id = %s", (w["act_x"],)) == 0
    assert run("viewer", w["X"], "SELECT title FROM activities WHERE id = %s", (w["act_x"],)) == [("Activity",)]


def test_lead_can_change_only_their_own_activity_and_only_allowed_columns(world):
    w = world
    assert run("lead", w["B"], "UPDATE activities SET title = 'mine' WHERE id = %s", (w["act_b"],)) == 1
    assert run("lead", w["B"], "UPDATE activities SET title = 'theirs' WHERE id = %s", (w["act_c"],)) == 0
    assert run("viewer", w["A"], "SELECT title FROM activities WHERE id = %s", (w["act_c"],)) == [("Activity",)]
    for column, value in (("start_time", "'09:00'"), ("lead_user_id", "'%s'" % w["B"]), ("outdoor", "true")):
        with pytest.raises(DENIED):
            run("lead", w["B"], "UPDATE activities SET %s = %s WHERE id = %%s" % (column, value), (w["act_b"],))
    with pytest.raises(DENIED):
        run("lead", w["B"], "DELETE FROM activities WHERE id = %s", (w["act_b"],))


def test_lead_cannot_use_the_tier_on_an_event_they_are_not_in(world):
    w = world
    # B leads act_b in event 1; give a different person's id to the lead tier: no row matches.
    assert run("lead", w["S"], "UPDATE activities SET title = 'x' WHERE id = %s", (w["act_b"],)) == 0
    # E is only an editor, not a lead: the lead policy needs lead_user_id = caller AND role lead.
    assert run("lead", w["E"], "UPDATE activities SET title = 'x' WHERE id = %s", (w["act_b"],)) == 0


# ---- Events and members ----------------------------------------------------------------

def test_event_changes_by_role(world):
    w = world
    assert run("editor", w["E"], "UPDATE events SET title = 'Renamed' WHERE id = %s", (w["ev1"],)) == 1
    with pytest.raises(DENIED):
        run("viewer", w["V"], "UPDATE events SET title = 'x' WHERE id = %s", (w["ev1"],))
    with pytest.raises(DENIED):
        run("editor", w["E"], "DELETE FROM events WHERE id = %s", (w["ev1"],))
    with pytest.raises(DENIED):
        run("editor", w["E"], "UPDATE events SET owner_id = %s WHERE id = %s", (w["E"], w["ev1"]))  # owner not editable
    assert run("organiser", w["X"], "DELETE FROM events WHERE id = %s", (w["ev1"],)) == 0  # not X's event


def test_membership_can_only_be_managed_by_that_events_organiser(world):
    w = world
    add = "INSERT INTO event_members (event_id, user_id, role) VALUES (%s, %s, 'viewer')"
    for role, user in (("viewer", "V"), ("lead", "B"), ("editor", "E")):
        with pytest.raises(DENIED):
            run(role, w[user], add, (w["ev1"], w["S"]))
    with pytest.raises(DENIED):
        run("organiser", w["X"], add, (w["ev1"], w["S"]))  # organiser of ANOTHER event
    assert run("organiser", w["A"], add, (w["ev1"], w["S"])) == 1
    assert run("organiser", w["X"], "UPDATE event_members SET role = 'organiser' WHERE event_id = %s AND user_id = %s",
               (w["ev1"], w["V"])) == 0
    assert run("organiser", w["X"], "DELETE FROM event_members WHERE event_id = %s AND user_id = %s",
               (w["ev1"], w["V"])) == 0


def test_first_organiser_rule_cannot_be_abused(world):
    w = world
    # Creating an event owned by someone else is refused.
    with pytest.raises(DENIED):
        run("organiser", w["S"], "INSERT INTO events (id, owner_id, title, event_date, timezone, venue_name,"
            " venue_lat, venue_lon) VALUES (%s, %s, 'Fake', '2026-12-20', 'Europe/London', 'Park', 51, 0)",
            (uid(), w["A"]))
    # A stranger cannot make themself organiser of an existing event (it already has members).
    with pytest.raises(DENIED):
        run("organiser", w["S"], "INSERT INTO event_members (event_id, user_id, role) VALUES (%s, %s, 'organiser')",
            (w["ev1"], w["S"]))


# ---- Foreign keys: forged parent ids ---------------------------------------------------

def test_cross_event_references_are_refused_by_the_database(world):
    w = world
    # E is an editor in BOTH events, so row-level security lets the insert through;
    # only the composite foreign keys stand in the way.
    item = ("INSERT INTO plan_items (id, plan_id, event_id, activity_id, start_time)"
            " VALUES (%s, %s, %s, %s, '10:00')")
    assert run("editor", w["E"], item, (uid(), w["plan1"], w["ev1"], w["act_b"])) == 1  # same event: fine
    with pytest.raises(FK):
        run("editor", w["E"], item, (uid(), w["plan1"], w["ev1"], w["act_x"]))  # activity of event 2
    with pytest.raises(FK):
        run("editor", w["E"], item, (uid(), w["plan2"], w["ev1"], w["act_b"]))  # plan of event 2
    with pytest.raises(FK):
        run("editor", w["E"], item, (uid(), w["plan1"], w["ev2"], w["act_x"]))  # plan of event 1 under event 2


def test_a_lead_must_be_a_member_of_the_same_event(world):
    w = world
    with pytest.raises(FK):
        run("editor", w["E"], "INSERT INTO activities (id, event_id, title, start_time, duration_minutes,"
            " lead_user_id) VALUES (%s, %s, 'x', '10:00', 30, %s)", (uid(), w["ev1"], w["X"]))  # X is not in event 1


def test_comparison_and_decision_must_use_the_same_events_parents(world):
    w = world
    snap1, snap2, cmp1 = uid(), uid(), uid()
    for ev, user, snap in ((w["ev1"], w["A"], snap1), (w["ev2"], w["X"], snap2)):
        run("weather_ingest", user, "INSERT INTO weather_snapshots (id, event_id, fetched_at, expires_at, hourly)"
            " VALUES (%s, %s, now(), now() + interval '1 hour', '[]')", (snap, ev))
    comparison = ("INSERT INTO comparisons (id, event_id, snapshot_id, method_version, seed, runs, results,"
                  " created_by) VALUES (%s, %s, %s, 'v1', 1, 100, '[]', %s)")
    with pytest.raises(FK):
        run("editor", w["E"], comparison, (uid(), w["ev1"], snap2, w["E"]))  # snapshot of event 2
    assert run("editor", w["E"], comparison, (cmp1, w["ev1"], snap1, w["E"])) == 1
    decision = ("INSERT INTO decision_log (id, event_id, plan_id, comparison_id, created_by)"
                " VALUES (%s, %s, %s, %s, %s)")
    with pytest.raises(FK):
        run("organiser", w["A"], decision, (uid(), w["ev1"], w["plan2"], cmp1, w["A"]))  # plan of event 2
    assert run("organiser", w["A"], decision, (uid(), w["ev1"], w["plan1"], cmp1, w["A"])) == 1
    with pytest.raises(DENIED):  # created_by must be the caller
        run("organiser", w["A"], decision, (uid(), w["ev1"], w["plan1"], cmp1, w["B"]))


# ---- Weather and decision log tiers ----------------------------------------------------

def test_weather_ingest_is_limited_to_snapshots_for_editors(world):
    w = world
    snapshot = ("INSERT INTO weather_snapshots (id, event_id, fetched_at, expires_at, hourly)"
                " VALUES (%s, %s, now(), now() + interval '1 hour', '[]')")
    assert run("weather_ingest", w["E"], snapshot, (uid(), w["ev1"])) == 1
    with pytest.raises(DENIED):
        run("weather_ingest", w["V"], snapshot, (uid(), w["ev1"]))  # a viewer cannot cause a refresh
    with pytest.raises(DENIED):
        run("weather_ingest", w["S"], snapshot, (uid(), w["ev1"]))
    with pytest.raises(DENIED):
        run("weather_ingest", w["E"], "SELECT * FROM activities")  # no access to anything else
    with pytest.raises(DENIED):
        run("weather_ingest", w["E"], "DELETE FROM weather_snapshots")


def test_decision_log_is_append_only_for_every_role(world):
    w = world
    for role, user in (("viewer", "V"), ("lead", "B"), ("editor", "E")):
        with pytest.raises(DENIED):
            run(role, w[user], "INSERT INTO decision_log (id, event_id, plan_id, comparison_id, created_by)"
                " VALUES (%s, %s, %s, %s, %s)", (uid(), w["ev1"], w["plan1"], uid(), w[user]))
    for role in ("viewer", "lead", "editor", "organiser", "auth", "weather_ingest"):
        for sql in ("UPDATE decision_log SET note = 'x'", "DELETE FROM decision_log", "TRUNCATE decision_log"):
            with pytest.raises(DENIED):
                run(role, w["A"], sql)


def test_auth_tier_can_reach_nothing_else(world):
    w = world
    assert run("auth", w["A"], "SELECT count(*) FROM event_members WHERE user_id = %s", (w["A"],))[0][0] >= 1
    for table in ("events", "activities", "plans", "plan_items", "weather_snapshots", "comparisons", "decision_log"):
        with pytest.raises(DENIED):
            run("auth", w["A"], "SELECT * FROM " + table)
    with pytest.raises(DENIED):
        run("auth", w["A"], "INSERT INTO event_members (event_id, user_id, role) VALUES (%s, %s, 'viewer')",
            (w["ev1"], w["S"]))


def test_app_roles_cannot_change_the_schema(world):
    w = world
    for role in ROLES:
        with pytest.raises(DENIED):
            run(role, w["A"], "DROP TABLE activities")
        with pytest.raises(DENIED):
            run(role, w["A"], "CREATE TABLE sneaky (id int)")
        with pytest.raises(DENIED):
            run(role, w["A"], "ALTER TABLE activities DISABLE ROW LEVEL SECURITY")
