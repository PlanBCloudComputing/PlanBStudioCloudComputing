"""Event membership routes (task P2-S1): who is on an event and with which role.

Purpose: the member endpoints from docs/API_SPEC.md under /api/v1/events/<event_id>/members:
  GET    list the members (any member)
  POST   add a member by email (organiser)
  PATCH  change a member's role (organiser)
  DELETE remove a member (organiser)
Important logic:
  * @require_role(...) checks the token and the caller's role on the event first
    (404 if not a member, 403 if the role is too low).
  * Database work uses the pool that matches the caller's role (role_to_pool), so
    PostgreSQL itself also checks the grants and row-level security. Looking up a
    user by email uses planb_auth, which is allowed to read users.
  * The last organiser cannot be demoted or removed (409). The organiser rows are
    locked with SELECT ... FOR UPDATE in the same transaction as the change, so
    two organisers cannot remove each other at the same moment.
  * A member who is still the lead of an activity cannot be removed: the database
    foreign key refuses, and we answer 409.
Register this blueprint in app/__init__.py with app.register_blueprint(members_bp).
"""
import uuid

import psycopg
from flask import Blueprint, g, jsonify, request

from app import db
from app.auth import api_error, require_role, role_to_pool

members_bp = Blueprint("members", __name__, url_prefix="/api/v1")

VALID_ROLES = ("viewer", "lead", "editor", "organiser")


def _json_body():
    """Return the request body as a dict, or None if it is not a JSON object."""
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def _uuid_or_none(value):
    """Return the value as a normal uuid string, or None if it is not a valid id."""
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        return None


def _is_last_organiser(conn, event_id, user_id):
    """Return True if user_id is the only organiser of the event.

    Locks all organiser rows of the event until the transaction ends, so the
    answer cannot change before the caller's update or delete runs.
    """
    rows = conn.execute(
        "SELECT user_id FROM event_members WHERE event_id = %s AND role = 'organiser' FOR UPDATE",
        (event_id,),
    ).fetchall()
    return len(rows) == 1 and str(rows[0][0]) == user_id


@members_bp.get("/events/<event_id>/members")
@require_role("viewer")
def list_members(event_id):
    """List the event's members with their roles. Any member may call this."""
    with db.get_conn(role_to_pool(g.role), g.user_id) as conn:
        rows = conn.execute(
            "SELECT m.user_id, u.email, u.display_name, m.role, m.added_at"
            " FROM event_members m JOIN users u ON u.id = m.user_id"
            " WHERE m.event_id = %s ORDER BY m.added_at, u.email",
            (event_id,),
        ).fetchall()
    return jsonify(
        [
            {
                "user_id": str(r[0]),
                "email": r[1],
                "display_name": r[2],
                "role": r[3],
                "added_at": r[4].isoformat(),
            }
            for r in rows
        ]
    )


@members_bp.post("/events/<event_id>/members")
@require_role("organiser")
def add_member(event_id):
    """Add a user to the event. Body: email, role. 201, or 404 unknown user, 409 already a member."""
    body = _json_body()
    if body is None:
        return api_error(400, "bad_request", "Body must be a JSON object")
    email = body.get("email")
    role = body.get("role")
    if not isinstance(email, str) or not email.strip():
        return api_error(422, "validation_error", "email is required")
    if role not in VALID_ROLES:
        return api_error(422, "validation_error", "role must be one of: " + ", ".join(VALID_ROLES))

    # Finding a user by email is the job of planb_auth; organisers cannot see strangers.
    with db.get_conn("auth") as conn:
        user = conn.execute(
            "SELECT id, email, display_name FROM users WHERE lower(email) = lower(%s)",
            (email.strip(),),
        ).fetchone()
    if user is None:
        return api_error(404, "user_not_found", "No user with that email")

    try:
        with db.get_conn(role_to_pool("organiser"), g.user_id) as conn:
            conn.execute(
                "INSERT INTO event_members (event_id, user_id, role) VALUES (%s, %s, %s)",
                (event_id, user[0], role),
            )
    except psycopg.errors.UniqueViolation:
        return api_error(409, "already_member", "That user is already a member of this event")

    response = jsonify(user_id=str(user[0]), email=user[1], display_name=user[2], role=role)
    response.status_code = 201
    response.headers["Location"] = "/api/v1/events/%s/members/%s" % (event_id, user[0])
    return response


@members_bp.patch("/events/<event_id>/members/<user_id>")
@require_role("organiser")
def change_role(event_id, user_id):
    """Change a member's role. Body: role. 200, or 404 not a member, 409 last organiser."""
    body = _json_body()
    if body is None:
        return api_error(400, "bad_request", "Body must be a JSON object")
    role = body.get("role")
    if role not in VALID_ROLES:
        return api_error(422, "validation_error", "role must be one of: " + ", ".join(VALID_ROLES))
    target = _uuid_or_none(user_id)
    if target is None:
        return api_error(404, "not_found", "Member not found")

    with db.get_conn(role_to_pool("organiser"), g.user_id) as conn:
        if role != "organiser" and _is_last_organiser(conn, event_id, target):
            return api_error(409, "last_organiser", "An event must keep at least one organiser")
        changed = conn.execute(
            "UPDATE event_members SET role = %s WHERE event_id = %s AND user_id = %s",
            (role, event_id, target),
        ).rowcount
    if changed == 0:
        return api_error(404, "not_found", "Member not found")
    return jsonify(user_id=target, role=role)


@members_bp.delete("/events/<event_id>/members/<user_id>")
@require_role("organiser")
def remove_member(event_id, user_id):
    """Remove a member. 204, or 404 not a member, 409 last organiser or still an activity lead."""
    target = _uuid_or_none(user_id)
    if target is None:
        return api_error(404, "not_found", "Member not found")

    try:
        with db.get_conn(role_to_pool("organiser"), g.user_id) as conn:
            if _is_last_organiser(conn, event_id, target):
                return api_error(409, "last_organiser", "An event must keep at least one organiser")
            removed = conn.execute(
                "DELETE FROM event_members WHERE event_id = %s AND user_id = %s",
                (event_id, target),
            ).rowcount
    except psycopg.errors.ForeignKeyViolation:
        return api_error(409, "member_is_lead", "Reassign this member's activities before removing them")
    if removed == 0:
        return api_error(404, "not_found", "Member not found")
    return "", 204
