"""Database access for Plan B Studio (task P1-S4).

Purpose: the one place the app opens PostgreSQL connections.
Important logic:
  * There is one small connection pool per database role, created lazily the
    first time that role is used. Each pool holds at most ONE connection and
    closes it after a short idle time, so the worst case is
    6 roles x 1 connection x 3 Cloud Run instances = 18, under the 22 usable
    connections of the db-f1-micro Cloud SQL instance.
  * The app NEVER connects as postgres, the table owner (planb_migrator) or any
    superuser or BYPASSRLS role. Only the six roles in DB_ROLES are accepted;
    anything else raises ValueError.
  * get_conn() starts a transaction and sets app.user_id for that transaction
    only (set_config(..., true)). Row-level security policies read this value,
    so there is no global "current user" and replicas stay stateless.
  * Host, port, database name and passwords come from app/config.py only.
Notes for callers (see docs/ROLE_DESIGN.md section 3):
  * Do not hold a connection during slow work. A pool has only one connection,
    so the next request for that role waits. For CPU-heavy work (the stress
    test): read the data, leave the with-block, compute, then open a new
    get_conn() block to save the result.
  * Creating an event: INSERT the event, INSERT the creator's organiser
    membership, and only then read the event. INSERT ... RETURNING on events is
    refused by RLS because the creator is not a member yet.
  * The membership tiers may SELECT only id, email, display_name from users;
    SELECT * fails with permission denied by design.
  * Deleting a member who still leads an activity, or an event, plan or
    comparison that has recorded decisions, fails on a foreign key: answer 409.
  * RLS often returns zero rows, or changes zero rows, instead of an error.
"""
import threading
from contextlib import contextmanager

from psycopg_pool import ConnectionPool

from app import config

# The only database login roles the app may use (see docs/ROLE_DESIGN.md).
DB_ROLES = ("auth", "viewer", "lead", "editor", "organiser", "weather_ingest")

# Seconds an unused connection is kept before it is closed.
_MAX_IDLE_SECONDS = 30
# Seconds to wait for the single connection before giving up (the pool is busy).
_WAIT_TIMEOUT_SECONDS = 10

# role -> ConnectionPool. Filled lazily; the lock stops two threads creating one twice.
_pools = {}
_pools_lock = threading.Lock()


def _login_name(role):
    """Return the PostgreSQL login name for a short role name.

    'viewer' -> 'planb_viewer'; 'weather_ingest' logs in as 'weather_ingest'.
    Raises ValueError if the role is not one of DB_ROLES.
    """
    if role not in DB_ROLES:
        raise ValueError("unknown database role %r; allowed: %s" % (role, ", ".join(DB_ROLES)))
    return role if role == "weather_ingest" else "planb_" + role


def _get_pool(role):
    """Return the pool for a role, creating it on first use.

    The pool opens no connection until a request needs one (min_size=0) and
    never holds more than one (max_size=1).
    """
    login = _login_name(role)
    with _pools_lock:
        pool = _pools.get(role)
        if pool is None:
            pool = ConnectionPool(
                conninfo="",
                kwargs={
                    "host": config.db_host(),
                    "port": config.DB_PORT,
                    "dbname": config.DB_NAME,
                    "user": login,
                    "password": config.db_password(role),
                },
                min_size=0,
                max_size=1,
                max_idle=_MAX_IDLE_SECONDS,
                timeout=_WAIT_TIMEOUT_SECONDS,
                open=True,
            )
            _pools[role] = pool
        return pool


def close_all_pools():
    """Close every pool and forget it (used by tests and on shutdown)."""
    with _pools_lock:
        for pool in _pools.values():
            pool.close()
        _pools.clear()


@contextmanager
def get_conn(role, user_id=None):
    """Yield a database connection inside one transaction for the given role.

    role: one of DB_ROLES; picks the pool, which logs in as planb_<role>
        (the weather_ingest role logs in as weather_ingest).
    user_id: id of the logged-in user, or None. When given, it is stored with
        set_config('app.user_id', user_id, true) so RLS policies can see it.
        The setting lasts only for this transaction.

    Commits when the with-block ends normally and rolls back if it raises.
    """
    pool = _get_pool(role)
    # pool.connection() commits on a normal exit and rolls back on an exception.
    with pool.connection() as conn:
        if user_id is not None:
            conn.execute("SELECT set_config('app.user_id', %s, true)", (str(user_id),))
        yield conn
