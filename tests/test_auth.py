"""Checks for register, login and tokens (task P1-S3), against the LOCAL Docker Postgres.

Start the database first with `docker compose up -d` (host port 5433). If it is not
reachable these tests are skipped. Never point them at Cloud SQL.
Covers the cases the demo video needs: wrong password 401, duplicate email 409,
short password 422, expired token 401, tampered token 401.
"""
import datetime
import json
import uuid

import jwt
import pytest
from flask import Flask

from app import config, db
from app.auth import create_token
from app.routes.auth import auth_bp

ROLES = ("auth", "viewer", "lead", "editor", "organiser", "weather_ingest")
SECRET = "test-secret-only-for-local-tests-0123456789"
PASSWORD = "correct horse battery"


@pytest.fixture
def client(monkeypatch):
    """A Flask test client with the auth blueprint, wired to the local database."""
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
    yield app.test_client()
    db.close_all_pools()


def new_email():
    """A unique email so tests never collide with rows left in the local database."""
    return "user-%s@example.com" % uuid.uuid4().hex[:12]


_UNSET = object()


def register(client, email=_UNSET, password=PASSWORD, name="Test User"):
    """POST /auth/register and return (response, email).

    A fresh unique email is used unless one is given (even an empty one or None,
    so tests can send bad values).
    """
    if email is _UNSET:
        email = new_email()
    resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": name, "password": password},
    )
    return resp, email


def login(client, email, password=PASSWORD):
    """POST /auth/login and return the response."""
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def test_register_creates_account(client):
    resp, email = register(client)
    assert resp.status_code == 201
    assert resp.headers["Location"] == "/api/v1/users/me"
    body = resp.get_json()
    assert set(body) == {"id", "email", "display_name"}  # never the password or hash
    assert body["email"] == email


def test_password_is_stored_as_argon2id(client):
    _, email = register(client)
    with db.get_conn("auth") as conn:
        stored = conn.execute("SELECT password_hash FROM users WHERE email = %s", (email,)).fetchone()[0]
    assert stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_duplicate_email_is_409_ignoring_case(client):
    _, email = register(client)
    resp, _ = register(client, email=email.upper())
    assert resp.status_code == 409
    assert resp.get_json()["error"] == "email_taken"


@pytest.mark.parametrize("password", ["short", "123456789", "x" * 129, None, 12345678901234])
def test_bad_password_is_422(client, password):
    resp, _ = register(client, password=password)
    assert resp.status_code == 422
    assert resp.get_json()["error"] == "validation_error"


def test_ten_character_password_is_accepted(client):
    resp, _ = register(client, password="1234567890")
    assert resp.status_code == 201


@pytest.mark.parametrize("email", ["", "no-at-sign", "a@b", "has space@x.com", None])
def test_bad_email_is_422(client, email):
    resp, _ = register(client, email=email)
    assert resp.status_code == 422


@pytest.mark.parametrize("name", ["", "   ", "x" * 61, None])
def test_bad_display_name_is_422(client, name):
    resp, _ = register(client, name=name)
    assert resp.status_code == 422


def test_malformed_json_is_400(client):
    resp = client.post("/api/v1/auth/register", data="{not json", content_type="application/json")
    assert resp.status_code == 400
    assert set(resp.get_json()) == {"error", "message"}


def test_login_returns_a_token(client):
    _, email = register(client)
    resp = login(client, email.upper())  # email is matched ignoring case
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 1800
    claims = jwt.decode(body["access_token"], SECRET, algorithms=["HS256"])
    assert set(claims) == {"sub", "iat", "exp"}
    assert claims["exp"] - claims["iat"] == 1800


def test_wrong_password_and_unknown_email_look_identical(client):
    _, email = register(client)
    wrong = login(client, email, password="not the password")
    unknown = login(client, new_email())
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.get_json() == unknown.get_json()


def test_users_me_with_valid_token(client):
    resp, email = register(client)
    token = login(client, email).get_json()["access_token"]
    me = client.get("/api/v1/users/me", headers={"Authorization": "Bearer " + token})
    assert me.status_code == 200
    assert me.get_json() == resp.get_json()


def test_users_me_without_token_is_401(client):
    for headers in ({}, {"Authorization": "Bearer"}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer junk"}):
        resp = client.get("/api/v1/users/me", headers=headers)
        assert resp.status_code == 401
        assert set(resp.get_json()) == {"error", "message"}


def test_expired_token_is_401(client):
    resp, _ = register(client)
    user_id = resp.get_json()["id"]
    now = datetime.datetime.now(datetime.timezone.utc)
    expired = jwt.encode(
        {"sub": user_id, "iat": now - datetime.timedelta(hours=1), "exp": now - datetime.timedelta(minutes=30)},
        SECRET,
        algorithm="HS256",
    )
    assert client.get("/api/v1/users/me", headers={"Authorization": "Bearer " + expired}).status_code == 401


def test_tampered_or_forged_token_is_401(client):
    resp, _ = register(client)
    user_id = resp.get_json()["id"]
    good = create_token(user_id)
    header, payload, signature = good.split(".")
    flipped = signature[:-2] + ("AA" if not signature.endswith("AA") else "BB")
    wrong_key = jwt.encode({"sub": user_id, "iat": 1, "exp": 9999999999}, "another-secret-key-0123456789abcdef", algorithm="HS256")
    no_signature = jwt.encode({"sub": user_id, "iat": 1, "exp": 9999999999}, None, algorithm="none")
    for bad in (header + "." + payload + "." + flipped, wrong_key, no_signature):
        assert client.get("/api/v1/users/me", headers={"Authorization": "Bearer " + bad}).status_code == 401
    # Sanity check: the untouched token works.
    assert client.get("/api/v1/users/me", headers={"Authorization": "Bearer " + good}).status_code == 200
