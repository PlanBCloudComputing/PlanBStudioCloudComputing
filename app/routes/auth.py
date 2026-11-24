"""Register, login and "who am I" routes (task P1-S3).

Purpose: the account endpoints from docs/API_SPEC.md under /api/v1:
  POST /auth/register   create an account
  POST /auth/login      exchange email and password for a token
  GET  /users/me        the logged-in user's own details
Important logic:
  * Everything here talks to the database as the planb_auth role, which can only
    read and insert users (and read event_members). Nothing else.
  * The password is hashed with Argon2id before it is stored (app/auth.py).
  * Validation failures are 422, malformed JSON is 400, duplicate email is 409.
  * Wrong password and unknown email give the SAME 401 message, so the API does
    not reveal which emails have accounts.
  * The email is stored as typed but compared case-insensitively (unique index
    on lower(email) in the database).
Register this blueprint in app/__init__.py with app.register_blueprint(auth_bp).
"""
import re
import uuid

import psycopg
from flask import Blueprint, g, jsonify, request

from app import db
from app.auth import (
    TOKEN_LIFETIME_SECONDS,
    api_error,
    create_token,
    hash_password,
    require_auth,
    verify_password,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1")

# A simple shape check: something@something.something, no spaces.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

MIN_PASSWORD_LENGTH = 10
# Upper limit so nobody can make the server hash a gigantic string.
MAX_PASSWORD_LENGTH = 128


def _json_body():
    """Return the request body as a dict, or None if it is not a JSON object."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def _invalid_login():
    """The one 401 used for both an unknown email and a wrong password."""
    return api_error(401, "invalid_credentials", "Invalid email or password")


@auth_bp.post("/auth/register")
def register():
    """Create an account. Body: email, display_name, password. Returns 201 or 400/409/422."""
    body = _json_body()
    if body is None:
        return api_error(400, "bad_request", "Body must be a JSON object")

    email = body.get("email")
    display_name = body.get("display_name")
    password = body.get("password")

    if not isinstance(email, str) or len(email.strip()) > 254 or not _EMAIL_RE.match(email.strip()):
        return api_error(422, "validation_error", "email must be a valid email address")
    if not isinstance(display_name, str) or not 1 <= len(display_name.strip()) <= 60:
        return api_error(422, "validation_error", "display_name must be 1 to 60 characters")
    if not isinstance(password, str) or not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        return api_error(
            422,
            "validation_error",
            "password must be %d to %d characters" % (MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH),
        )

    email = email.strip()
    display_name = display_name.strip()
    user_id = uuid.uuid4()
    try:
        with db.get_conn("auth") as conn:
            conn.execute(
                "INSERT INTO users (id, email, display_name, password_hash) VALUES (%s, %s, %s, %s)",
                (user_id, email, display_name, hash_password(password)),
            )
    except psycopg.errors.UniqueViolation:
        return api_error(409, "email_taken", "An account with this email already exists")

    response = jsonify(id=str(user_id), email=email, display_name=display_name)
    response.status_code = 201
    response.headers["Location"] = "/api/v1/users/me"
    return response


@auth_bp.post("/auth/login")
def login():
    """Check email and password and return a token. Body: email, password."""
    body = _json_body()
    if body is None:
        return api_error(400, "bad_request", "Body must be a JSON object")

    email = body.get("email")
    password = body.get("password")
    if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
        return api_error(422, "validation_error", "email and password are required")
    if len(password) > MAX_PASSWORD_LENGTH:
        return _invalid_login()

    with db.get_conn("auth") as conn:
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE lower(email) = lower(%s)",
            (email.strip(),),
        ).fetchone()

    # Unknown email: still do the hash work (stored_hash=None) so timing does not leak it.
    if not verify_password(row[1] if row else None, password):
        return _invalid_login()

    return jsonify(
        access_token=create_token(row[0]),
        token_type="Bearer",
        expires_in=TOKEN_LIFETIME_SECONDS,
    )


@auth_bp.get("/users/me")
@require_auth
def me():
    """Return the logged-in user's id, email and display name."""
    with db.get_conn("auth") as conn:
        row = conn.execute(
            "SELECT id, email, display_name FROM users WHERE id = %s", (g.user_id,)
        ).fetchone()
    if row is None:
        # A valid token for a user that no longer exists.
        return api_error(401, "unauthorized", "Missing or invalid token")
    return jsonify(id=str(row[0]), email=row[1], display_name=row[2])
