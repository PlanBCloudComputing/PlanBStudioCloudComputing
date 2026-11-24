"""Database access for Plan B Studio (interface stub, task P0-S3; real code in P1-S4).

Purpose: the one place the app opens PostgreSQL connections.
Important logic (to be implemented in P1-S4):
  * There is one small connection pool (1-2 connections) per database role,
    created lazily the first time that role is used.
  * The app NEVER connects as postgres, the table owner, or any superuser or
    BYPASSRLS role. Only the six roles in DB_ROLES below are allowed.
  * get_conn() starts a transaction and sets app.user_id for that transaction
    only (set_config(..., true)). Row-level security policies read this value,
    so there is no global "current user" and replicas stay stateless.
"""
from contextlib import contextmanager

# The only database login roles the app may use (see docs/ROLE_DESIGN.md).
DB_ROLES = ("auth", "viewer", "lead", "editor", "organiser", "weather_ingest")


@contextmanager
def get_conn(role, user_id=None):
    """Yield a database connection inside one transaction for the given role.

    role: one of DB_ROLES; picks the pool, which logs in as planb_<role>
        (the weather_ingest role logs in as weather_ingest).
    user_id: id of the logged-in user, or None. When given, it is stored with
        set_config('app.user_id', user_id, true) so RLS policies can see it.

    Commits when the with-block ends normally and rolls back if it raises.
    """
    raise NotImplementedError("P1-S4")
    yield  # pragma: no cover - makes this function a generator, as @contextmanager needs
