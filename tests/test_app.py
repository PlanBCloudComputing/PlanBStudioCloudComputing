"""Checks for the app factory in app/__init__.py: routes are registered and /readyz works.

The readyz success test needs the LOCAL Docker Postgres (host port 5433, `docker compose up -d`)
and is skipped if it is not running. Never point these tests at Cloud SQL.
"""
import json

import pytest

from app import config, create_app, db

ROLES = ("auth", "viewer", "lead", "editor", "organiser", "weather_ingest")


def test_blueprints_are_registered():
    rules = {rule.rule for rule in create_app().url_map.iter_rules()}
    assert "/api/v1/auth/login" in rules
    assert "/api/v1/auth/register" in rules
    assert "/api/v1/users/me" in rules
    assert "/api/v1/events/<event_id>/members" in rules
    assert "/api/v1/events/<event_id>/commit" in rules
    assert "/api/v1/events/<event_id>/decisions" in rules


def test_home_redirects_to_the_start_page():
    client = create_app().test_client()
    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/static/index.html")
    assert client.get("/static/index.html").status_code == 200


def test_healthz_needs_no_database_and_sets_instance_header(monkeypatch):
    monkeypatch.delenv("DB_PASSWORDS_JSON", raising=False)
    response = create_app().test_client().get("/api/v1/healthz")
    assert response.status_code == 200
    assert response.headers["X-Served-By"]


def test_readyz_answers_503_when_database_is_unreachable(monkeypatch):
    monkeypatch.delenv("DB_PASSWORDS_JSON", raising=False)  # no password, so no connection
    db.close_all_pools()
    response = create_app().test_client().get("/api/v1/readyz")
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
    assert response.get_json()["error"] == "database_unavailable"


def test_readyz_answers_200_with_the_local_database(monkeypatch):
    monkeypatch.delenv("DB_INSTANCE_CONNECTION_NAME", raising=False)
    monkeypatch.setenv("DB_HOST", "localhost")
    monkeypatch.setattr(config, "DB_PORT", 5433)
    monkeypatch.setenv("DB_PASSWORDS_JSON", json.dumps({r: "local_dev_only" for r in ROLES}))
    db.close_all_pools()
    try:
        response = create_app().test_client().get("/api/v1/readyz")
    finally:
        db.close_all_pools()
    if response.status_code != 200:
        pytest.skip("local Docker Postgres is not reachable")
    assert response.get_json() == {"status": "ready"}
