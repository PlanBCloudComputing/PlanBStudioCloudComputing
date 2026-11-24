"""Authentication and role checks for Plan B Studio (tasks P1-S3 and P2-S1).

Purpose: password hashing, login tokens, the error body, and the decorators that
routes use to require a logged-in user and a minimum role on an event.
Important logic:
  * Passwords are hashed with Argon2id (argon2-cffi). We never store or log a password.
  * Tokens are PyJWT HS256 with a 30-minute expiry and the claims sub (user id),
    iat and exp. The signing key comes from config.jwt_secret(). Decoding allows
    only HS256, so a token with "alg": "none" or another algorithm is refused.
  * require_auth sets g.user_id from the token, or answers 401. Every kind of bad
    token (missing, malformed, tampered, expired) gets the same 401.
  * Every error body is {"error": "<code>", "message": "<text>"} (docs/API_SPEC.md).
  * Membership roles are ordered viewer < lead < editor < organiser.
  * require_role looks up the caller's role on the event in the URL as planb_auth
    (which can read event_members), sets g.role, and answers 404 if the caller is
    not a member (hides that the event exists) or 403 if the role is too low.
  * role_to_pool turns a membership role into the database role for get_conn().
"""
import datetime
import uuid
from functools import wraps

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import g, jsonify, request

from app import config, db

# Membership roles from lowest to highest rights.
ROLE_ORDER = ("viewer", "lead", "editor", "organiser")

# Tokens last 30 minutes (docs/API_SPEC.md).
TOKEN_LIFETIME_SECONDS = 30 * 60

# PasswordHasher() uses Argon2id with the library's recommended cost settings.
_hasher = PasswordHasher()
_dummy_hash = None


def api_error(status, code, message):
    """Return a Flask response with the standard error body and the given status."""
    response = jsonify(error=code, message=message)
    response.status_code = status
    return response


def hash_password(password):
    """Return the Argon2id hash (a string that includes its own random salt)."""
    return _hasher.hash(password)


def verify_password(stored_hash, password):
    """Return True if the password matches the stored hash, otherwise False.

    When the email is unknown, pass stored_hash=None: the password is still
    checked against a dummy hash, so a login for an unknown email takes about
    as long as one for a wrong password and the two cannot be told apart.
    """
    global _dummy_hash
    if stored_hash is None:
        if _dummy_hash is None:
            _dummy_hash = _hasher.hash("dummy password for timing only")
        try:
            _hasher.verify(_dummy_hash, password)
        except VerificationError:
            pass
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def create_token(user_id):
    """Return a signed token for the user, valid for TOKEN_LIFETIME_SECONDS."""
    now = datetime.datetime.now(datetime.timezone.utc)
    claims = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + datetime.timedelta(seconds=TOKEN_LIFETIME_SECONDS),
    }
    return jwt.encode(claims, config.jwt_secret(), algorithm="HS256")


def decode_token(token):
    """Return the user id (a string) from a valid token.

    Raises jwt.InvalidTokenError for anything wrong: bad signature, expired,
    malformed, wrong algorithm, or missing claims.
    """
    claims = jwt.decode(
        token,
        config.jwt_secret(),
        algorithms=["HS256"],
        options={"require": ["sub", "exp", "iat"]},
    )
    try:
        return str(uuid.UUID(claims["sub"]))
    except (ValueError, TypeError):
        raise jwt.InvalidTokenError("sub is not a user id") from None


def require_auth(view):
    """Decorator: check the bearer token, set g.user_id, else return 401."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme != "Bearer" or not token:
            return api_error(401, "unauthorized", "Missing or invalid token")
        try:
            g.user_id = decode_token(token.strip())
        except jwt.InvalidTokenError:
            return api_error(401, "unauthorized", "Missing or invalid token")
        return view(*args, **kwargs)

    return wrapper


def role_to_pool(role):
    """Map a membership role to the database role name for get_conn().

    role: one of ROLE_ORDER. Returns 'viewer', 'lead', 'editor' or 'organiser'.
    Each membership role has a database role of the same name (planb_<role>).
    Raises ValueError for anything else, so a typo cannot pick an admin role.
    """
    if role not in ROLE_ORDER:
        raise ValueError("unknown membership role %r" % (role,))
    return role


def require_role(min_role):
    """Decorator factory: require at least min_role on the event in the URL.

    The route must have an event_id URL parameter, for example
    /events/<event_id>/members. This decorator also does the require_auth check,
    so a route needs only @require_role(...). It looks up the caller's role in
    event_members (as planb_auth) and sets g.role for the view.
    Answers 401 without a valid token, 404 if the event id is not a valid id or
    the caller is not a member (this hides whether the event exists), and
    403 if the member's role is lower than min_role.
    """
    if min_role not in ROLE_ORDER:
        raise ValueError("unknown membership role %r" % (min_role,))

    def decorator(view):
        @require_auth
        @wraps(view)
        def wrapper(*args, **kwargs):
            try:
                event_id = str(uuid.UUID(str(kwargs.get("event_id"))))
            except ValueError:
                return api_error(404, "not_found", "Event not found")
            with db.get_conn("auth", g.user_id) as conn:
                row = conn.execute(
                    "SELECT role FROM event_members WHERE event_id = %s AND user_id = %s",
                    (event_id, g.user_id),
                ).fetchone()
            if row is None:
                return api_error(404, "not_found", "Event not found")
            if ROLE_ORDER.index(row[0]) < ROLE_ORDER.index(min_role):
                return api_error(403, "forbidden", "Your role on this event is too low for this action")
            g.role = row[0]
            return view(*args, **kwargs)

        return wrapper

    return decorator
