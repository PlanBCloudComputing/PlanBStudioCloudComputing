"""Checks for require_role and the members routes (task P2-S1), on the LOCAL Docker Postgres.

Start the database first with `docker compose up -d` (host port 5433); if it is not
reachable these tests are skipped. Never point them at Cloud SQL.
Covers the role matrix (outsider 404, viewer or lead 403, organiser ok), the
last-organiser rule (409) and "a lead cannot be removed" (409).
"""
import json
import uuid

import pytest
from flask import Flask

from app import config, db
from app.auth import role_to_pool
from app.routes.auth import auth_bp
from app.routes.members import members_bp

ROLES = ("auth", "viewer", "lead", "editor", "organiser", "weather_ingest")
SECRET = "test-secret-only-for-local-tests-0123456789"
PASSWORD = "correct horse battery"


@pytest.fixture
def client(monkeypatch):
    """A Flask test client with the auth and members blueprints on the local database."""
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
    app.register_blueprint(auth_bp)
    app.register_blueprint(members_bp)
    yield app.test_client()
    db.close_all_pools()


def make_user(client):
    """Register and log in a new user. Returns (user_id, email, auth headers)."""
    email = "m-%s@example.com" % uuid.uuid4().hex[:12]
    reg = client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "Member", "password": PASSWORD},
    ).get_json()
    token = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}).get_json()["access_token"]
    return reg["id"], email, {"Authorization": "Bearer " + token}


def make_event(owner_id):
    """Create an event the way Flask will: insert it, then the owner's organiser row."""
    event_id = str(uuid.uuid4())
    with db.get_conn(role_to_pool("organiser"), owner_id) as conn:
        conn.execute(
            "INSERT INTO events (id, owner_id, title, event_date, timezone, venue_name, venue_lat, venue_lon)"
            " VALUES (%s, %s, 'Test', '2026-12-20', 'Europe/London', 'Park', 51.5, -0.1)",
            (event_id, owner_id),
        )
        conn.execute(
            "INSERT INTO event_members (event_id, user_id, role) VALUES (%s, %s, 'organiser')",
            (event_id, owner_id),
        )
    return event_id


def url(event_id, user_id=None):
    """Members URL for an event, or for one member."""
    base = "/api/v1/events/%s/members" % event_id
    return base + ("/" + user_id if user_id else "")


@pytest.fixture
def team(client):
    """An event with one member of each role, plus an outsider. Returns a dict of people."""
    org_id, org_email, org_h = make_user(client)
    event_id = make_event(org_id)
    people = {"event": event_id, "organiser": (org_id, org_email, org_h)}
    for role in ("viewer", "lead", "editor"):
        uid, email, headers = make_user(client)
        added = client.post(url(event_id), json={"email": email, "role": role}, headers=org_h)
        assert added.status_code == 201
        people[role] = (uid, email, headers)
    people["outsider"] = make_user(client)
    return people


def test_list_members_any_member_but_not_outsider(client, team):
    for role in ("viewer", "lead", "editor", "organiser"):
        resp = client.get(url(team["event"]), headers=team[role][2])
        assert resp.status_code == 200
        assert {m["role"] for m in resp.get_json()} == {"organiser", "viewer", "lead", "editor"}
    assert client.get(url(team["event"]), headers=team["outsider"][2]).status_code == 404


def test_no_token_is_401_and_bad_event_id_is_404(client, team):
    assert client.get(url(team["event"])).status_code == 401
    assert client.get(url("not-a-uuid"), headers=team["organiser"][2]).status_code == 404
    assert client.get(url(str(uuid.uuid4())), headers=team["organiser"][2]).status_code == 404


def test_only_organiser_may_change_members(client, team):
    target = team["outsider"]
    for role in ("viewer", "lead", "editor"):
        h = team[role][2]
        assert client.post(url(team["event"]), json={"email": target[1], "role": "viewer"}, headers=h).status_code == 403
        assert client.patch(url(team["event"], team["viewer"][0]), json={"role": "lead"}, headers=h).status_code == 403
        assert client.delete(url(team["event"], team["viewer"][0]), headers=h).status_code == 403
    assert client.post(url(team["event"]), json={"email": target[1], "role": "viewer"}, headers=team["outsider"][2]).status_code == 404


def test_add_member_errors(client, team):
    h = team["organiser"][2]
    ok = client.post(url(team["event"]), json={"email": team["outsider"][1].upper(), "role": "viewer"}, headers=h)
    assert ok.status_code == 201
    assert ok.headers["Location"] == url(team["event"], team["outsider"][0])
    again = client.post(url(team["event"]), json={"email": team["outsider"][1], "role": "viewer"}, headers=h)
    assert again.status_code == 409
    nobody = client.post(url(team["event"]), json={"email": "nobody@example.com", "role": "viewer"}, headers=h)
    assert nobody.status_code == 404
    for body in ({"email": team["outsider"][1], "role": "boss"}, {"email": team["outsider"][1]}, {"role": "viewer"}):
        assert client.post(url(team["event"]), json=body, headers=h).status_code == 422


def test_change_role_and_unknown_member(client, team):
    h = team["organiser"][2]
    resp = client.patch(url(team["event"], team["viewer"][0]), json={"role": "editor"}, headers=h)
    assert resp.status_code == 200 and resp.get_json()["role"] == "editor"
    assert client.patch(url(team["event"], team["viewer"][0]), json={"role": "nope"}, headers=h).status_code == 422
    stranger = team["outsider"][0]
    assert client.patch(url(team["event"], stranger), json={"role": "viewer"}, headers=h).status_code == 404
    assert client.patch(url(team["event"], "not-a-uuid"), json={"role": "viewer"}, headers=h).status_code == 404


def test_last_organiser_cannot_be_demoted_or_removed(client, team):
    org_id, _, h = team["organiser"]
    assert client.patch(url(team["event"], org_id), json={"role": "viewer"}, headers=h).status_code == 409
    assert client.delete(url(team["event"], org_id), headers=h).status_code == 409
    # With a second organiser the first may step down.
    editor_id = team["editor"][0]
    assert client.patch(url(team["event"], editor_id), json={"role": "organiser"}, headers=h).status_code == 200
    assert client.patch(url(team["event"], org_id), json={"role": "viewer"}, headers=h).status_code == 200


def test_remove_member(client, team):
    h = team["organiser"][2]
    assert client.delete(url(team["event"], team["viewer"][0]), headers=h).status_code == 204
    assert client.delete(url(team["event"], team["viewer"][0]), headers=h).status_code == 404
    # The removed user is now an outsider.
    assert client.get(url(team["event"]), headers=team["viewer"][2]).status_code == 404


def test_member_who_leads_an_activity_cannot_be_removed(client, team):
    org_id, _, h = team["organiser"]
    lead_id = team["lead"][0]
    activity_id = str(uuid.uuid4())
    with db.get_conn(role_to_pool("organiser"), org_id) as conn:
        conn.execute(
            "INSERT INTO activities (id, event_id, title, start_time, duration_minutes, lead_user_id)"
            " VALUES (%s, %s, 'Rounders', '10:00', 60, %s)",
            (activity_id, team["event"], lead_id),
        )
    resp = client.delete(url(team["event"], lead_id), headers=h)
    assert resp.status_code == 409
    assert resp.get_json()["error"] == "member_is_lead"
    # Still a member afterwards (the failed delete was rolled back).
    assert client.get(url(team["event"]), headers=team["lead"][2]).status_code == 200


def test_role_to_pool_rejects_unknown_roles():
    assert role_to_pool("lead") == "lead"
    for bad in ("postgres", "admin", "", None):
        with pytest.raises(ValueError):
            role_to_pool(bad)
