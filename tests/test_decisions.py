"""Checks for the decision log routes (task P2-S3), on the LOCAL Docker Postgres.

Start the database first with `docker compose up -d` (host port 5433); if it is not
reachable these tests are skipped. Never point them at Cloud SQL.
Covers commit (organiser only), the history list, 422 for ids from another event,
and the database-level rules: no UPDATE or DELETE on decision_log, and an event with
decisions cannot be deleted.
"""
import json
import uuid

import psycopg
import pytest
from flask import Flask

from app import config, db
from app.routes.auth import auth_bp
from app.routes.decisions import decisions_bp
from app.routes.members import members_bp
from test_members import make_event, make_user, url  # helpers shared with the members tests

ROLES = ("auth", "viewer", "lead", "editor", "organiser", "weather_ingest")
SECRET = "test-secret-only-for-local-tests-0123456789"


@pytest.fixture
def client(monkeypatch):
    """A Flask test client with auth, members and decisions blueprints on the local database."""
    monkeypatch.delenv("DB_INSTANCE_CONNECTION_NAME", raising=False)
    monkeypatch.setenv("DB_HOST", "localhost")
    monkeypatch.setattr(config, "DB_PORT", 5433)
    monkeypatch.setenv("DB_PASSWORDS_JSON", json.dumps({r: "local_dev_only" for r in ROLES}))
    monkeypatch.setenv("JWT_SECRET", SECRET)
    db.close_all_pools()
    try:
        with db.get_conn("auth") as conn:
            conn.execute("SELECT 1")
    except Exception as exc:  # database not running: skip instead of failing
        db.close_all_pools()
        pytest.skip("local Docker Postgres is not reachable: %s" % exc)
    app = Flask(__name__)
    for blueprint in (auth_bp, members_bp, decisions_bp):
        app.register_blueprint(blueprint)
    yield app.test_client()
    db.close_all_pools()


def add_plan_and_comparison(event_id, user_id):
    """Insert a plan, a weather snapshot and a comparison for the event. Returns (plan_id, comparison_id)."""
    plan_id, snapshot_id, comparison_id = (str(uuid.uuid4()) for _ in range(3))
    with db.get_conn("organiser", user_id) as conn:
        conn.execute("INSERT INTO plans (id, event_id, label) VALUES (%s, %s, 'Original')", (plan_id, event_id))
    with db.get_conn("weather_ingest", user_id) as conn:
        conn.execute(
            "INSERT INTO weather_snapshots (id, event_id, fetched_at, expires_at, hourly)"
            " VALUES (%s, %s, now(), now() + interval '1 hour', '[]')",
            (snapshot_id, event_id),
        )
    with db.get_conn("organiser", user_id) as conn:
        conn.execute(
            "INSERT INTO comparisons (id, event_id, snapshot_id, method_version, seed, runs, results, created_by)"
            " VALUES (%s, %s, %s, 'v1', 1, 100, '[]', %s)",
            (comparison_id, event_id, snapshot_id, user_id),
        )
    return plan_id, comparison_id


@pytest.fixture
def team(client):
    """An event (with a plan and a comparison) and an organiser, editor, viewer and outsider."""
    org_id, _, org_h = make_user(client)
    event_id = make_event(org_id)
    people = {"event": event_id, "organiser": (org_id, org_h)}
    for role in ("editor", "viewer"):
        uid, email, headers = make_user(client)
        assert client.post(url(event_id), json={"email": email, "role": role}, headers=org_h).status_code == 201
        people[role] = (uid, headers)
    outsider_id, _, outsider_headers = make_user(client)
    people["outsider"] = (outsider_id, outsider_headers)
    people["plan"], people["comparison"] = add_plan_and_comparison(event_id, org_id)
    return people


def commit_url(event_id):
    """URL of the commit route for an event."""
    return "/api/v1/events/%s/commit" % event_id


def test_organiser_commits_and_members_read_history(client, team):
    body = {"plan_id": team["plan"], "comparison_id": team["comparison"], "note": "Going with the original"}
    resp = client.post(commit_url(team["event"]), json=body, headers=team["organiser"][1])
    assert resp.status_code == 201
    assert resp.headers["Location"] == "/api/v1/events/%s/decisions" % team["event"]
    made = resp.get_json()
    assert made["created_by"] == team["organiser"][0] and made["note"] == "Going with the original"

    for role in ("organiser", "editor", "viewer"):
        listed = client.get("/api/v1/events/%s/decisions" % team["event"], headers=team[role][1])
        assert listed.status_code == 200
        assert [d["id"] for d in listed.get_json()] == [made["id"]]
    outsider = client.get("/api/v1/events/%s/decisions" % team["event"], headers=team["outsider"][1])
    assert outsider.status_code == 404


def test_only_organiser_may_commit(client, team):
    body = {"plan_id": team["plan"], "comparison_id": team["comparison"]}
    assert client.post(commit_url(team["event"]), json=body).status_code == 401
    for role in ("editor", "viewer"):
        assert client.post(commit_url(team["event"]), json=body, headers=team[role][1]).status_code == 403
    assert client.post(commit_url(team["event"]), json=body, headers=team["outsider"][1]).status_code == 404


def test_commit_validation(client, team):
    h = team["organiser"][1]
    good = {"plan_id": team["plan"], "comparison_id": team["comparison"]}
    assert client.post(commit_url(team["event"]), data="{nope", content_type="application/json", headers=h).status_code == 400
    for bad in (
        {"comparison_id": team["comparison"]},
        {"plan_id": team["plan"]},
        {**good, "plan_id": "not-a-uuid"},
        {**good, "note": 5},
        {**good, "note": "x" * 1001},
    ):
        assert client.post(commit_url(team["event"]), json=bad, headers=h).status_code == 422
    # Valid ids that do not exist: the foreign keys refuse them.
    missing = {"plan_id": str(uuid.uuid4()), "comparison_id": team["comparison"]}
    assert client.post(commit_url(team["event"]), json=missing, headers=h).status_code == 422


def test_plan_or_comparison_from_another_event_is_422(client, team):
    other_owner, _, other_h = make_user(client)
    other_event = make_event(other_owner)
    other_plan, other_comparison = add_plan_and_comparison(other_event, other_owner)
    h = team["organiser"][1]
    for body in (
        {"plan_id": other_plan, "comparison_id": team["comparison"]},
        {"plan_id": team["plan"], "comparison_id": other_comparison},
    ):
        assert client.post(commit_url(team["event"]), json=body, headers=h).status_code == 422
    # And the other event's organiser cannot use this event's ids.
    body = {"plan_id": team["plan"], "comparison_id": team["comparison"]}
    assert client.post(commit_url(other_event), json=body, headers=other_h).status_code == 422


def test_decisions_cannot_be_changed_or_the_event_deleted(client, team):
    org_id, h = team["organiser"]
    made = client.post(
        commit_url(team["event"]), json={"plan_id": team["plan"], "comparison_id": team["comparison"]}, headers=h
    ).get_json()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.get_conn("organiser", org_id) as conn:
            conn.execute("UPDATE decision_log SET note = 'edited' WHERE id = %s", (made["id"],))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.get_conn("organiser", org_id) as conn:
            conn.execute("DELETE FROM decision_log WHERE id = %s", (made["id"],))
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with db.get_conn("organiser", org_id) as conn:
            conn.execute("DELETE FROM events WHERE id = %s", (team["event"],))
    listed = client.get("/api/v1/events/%s/decisions" % team["event"], headers=h).get_json()
    assert [d["id"] for d in listed] == [made["id"]]
