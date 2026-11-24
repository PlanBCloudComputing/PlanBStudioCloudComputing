"""Decision log routes (task P2-S3): commit a plan and read the history.

Purpose: the two endpoints from docs/API_SPEC.md:
  POST /api/v1/events/<event_id>/commit     organiser records the chosen plan
  GET  /api/v1/events/<event_id>/decisions  any member reads the history
Important logic:
  * The decision_log table is append-only. Nobody, not even the organiser, has
    UPDATE or DELETE on it (a GRANT in 003_policies.sql), so a recorded decision
    cannot be edited or erased through the app or through psql.
  * Because of that, an event, plan or comparison that has recorded decisions
    cannot be deleted either; the database refuses and the delete route there
    should answer 409.
  * The comparison already holds the weather snapshot, seed and method version, so
    a decision can be reproduced later from the ids stored here.
  * plan_id and comparison_id must belong to the same event as the URL. The
    database enforces this with composite foreign keys; we answer 422.
Register this blueprint in app/__init__.py with app.register_blueprint(decisions_bp).
"""
import uuid

import psycopg
from flask import Blueprint, g, jsonify, request

from app import db
from app.auth import api_error, require_role, role_to_pool

decisions_bp = Blueprint("decisions", __name__, url_prefix="/api/v1")

MAX_NOTE_LENGTH = 1000


def _uuid_or_none(value):
    """Return the value as a normal uuid string, or None if it is not a valid id."""
    if not isinstance(value, str):
        return None
    try:
        return str(uuid.UUID(value))
    except ValueError:
        return None


def _decision_json(row):
    """Turn a decision_log row (id, event, plan, comparison, note, by, name, when) into a dict."""
    return {
        "id": str(row[0]),
        "event_id": str(row[1]),
        "plan_id": str(row[2]),
        "comparison_id": str(row[3]),
        "note": row[4],
        "created_by": str(row[5]),
        "created_by_name": row[6],
        "created_at": row[7].isoformat(),
    }


@decisions_bp.post("/events/<event_id>/commit")
@require_role("organiser")
def commit_decision(event_id):
    """Record the chosen plan. Body: plan_id, comparison_id, optional note. 201 or 422."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error(400, "bad_request", "Body must be a JSON object")

    plan_id = _uuid_or_none(body.get("plan_id"))
    comparison_id = _uuid_or_none(body.get("comparison_id"))
    note = body.get("note")
    if plan_id is None or comparison_id is None:
        return api_error(422, "validation_error", "plan_id and comparison_id must be valid ids")
    if note is not None and (not isinstance(note, str) or len(note) > MAX_NOTE_LENGTH):
        return api_error(422, "validation_error", "note must be text of at most %d characters" % MAX_NOTE_LENGTH)

    decision_id = str(uuid.uuid4())
    try:
        with db.get_conn(role_to_pool("organiser"), g.user_id) as conn:
            created_at = conn.execute(
                "INSERT INTO decision_log (id, event_id, plan_id, comparison_id, note, created_by)"
                " VALUES (%s, %s, %s, %s, %s, %s) RETURNING created_at",
                (decision_id, event_id, plan_id, comparison_id, note, g.user_id),
            ).fetchone()[0]
            name = conn.execute(
                "SELECT display_name FROM users WHERE id = %s", (g.user_id,)
            ).fetchone()[0]
    except psycopg.errors.ForeignKeyViolation:
        # The plan or the comparison does not exist, or belongs to another event.
        return api_error(422, "validation_error", "plan_id and comparison_id must belong to this event")

    response = jsonify(
        _decision_json((decision_id, event_id, plan_id, comparison_id, note, g.user_id, name, created_at))
    )
    response.status_code = 201
    response.headers["Location"] = "/api/v1/events/%s/decisions" % event_id
    return response


@decisions_bp.get("/events/<event_id>/decisions")
@require_role("viewer")
def list_decisions(event_id):
    """List the event's recorded decisions, oldest first. Any member may call this."""
    with db.get_conn(role_to_pool(g.role), g.user_id) as conn:
        # LEFT JOIN: keep the row even if the person who decided has left the event.
        rows = conn.execute(
            "SELECT d.id, d.event_id, d.plan_id, d.comparison_id, d.note, d.created_by,"
            "       u.display_name, d.created_at"
            " FROM decision_log d LEFT JOIN users u ON u.id = d.created_by"
            " WHERE d.event_id = %s ORDER BY d.created_at, d.id",
            (event_id,),
        ).fetchall()
    return jsonify([_decision_json(r) for r in rows])
