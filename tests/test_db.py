"""Checks for app/db.py (task P1-S4), run against the LOCAL Docker Postgres only.

Start it first with `docker compose up -d` (host port 5433). The fixture below points
the app at it with the fake password from docker-compose.yml. If the database is not
reachable the database tests are skipped, so a plain `pytest` still runs elsewhere.
Never point these tests at Cloud SQL.
"""
import json
import uuid

import psycopg
import pytest

from app import config, db

ROLES = ("auth", "viewer", "lead", "editor", "organiser", "weather_ingest")


@pytest.fixture
def local_db(monkeypatch):
    """Point the app at the local Docker database and start with no pools open."""
    monkeypatch.delenv("DB_INSTANCE_CONNECTION_NAME", raising=False)
    monkeypatch.setenv("DB_HOST", "localhost")
    monkeypatch.setattr(config, "DB_PORT", 5433)
    monkeypatch.setenv("DB_PASSWORDS_JSON", json.dumps({r: "local_dev_only" for r in ROLES}))
    db.close_all_pools()
    try:
        with db.get_conn("viewer") as conn:
            conn.execute("SELECT 1")
    except Exception as exc:  # database not running: skip instead of failing
        db.close_all_pools()
        pytest.skip("local Docker Postgres is not reachable: %s" % exc)
    yield
    db.close_all_pools()


def test_unknown_role_is_rejected():
    for bad in ("postgres", "planb_migrator", "admin", "planb_viewer", ""):
        with pytest.raises(ValueError):
            with db.get_conn(bad):
                pass


def test_each_role_logs_in_as_its_own_user(local_db):
    expected = {r: ("weather_ingest" if r == "weather_ingest" else "planb_" + r) for r in ROLES}
    for role, login in expected.items():
        with db.get_conn(role) as conn:
            assert conn.execute("SELECT current_user").fetchone()[0] == login


def test_app_roles_have_no_admin_rights(local_db):
    for role in ROLES:
        with db.get_conn(role) as conn:
            sup, bypass = conn.execute(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
            ).fetchone()
            assert (sup, bypass) == (False, False)


def test_user_id_is_set_for_the_transaction_only(local_db):
    me = str(uuid.uuid4())
    with db.get_conn("viewer", me) as conn:
        assert conn.execute("SELECT current_setting('app.user_id', true)").fetchone()[0] == me
    # Next transaction on the same pooled connection: the setting must be gone.
    with db.get_conn("viewer") as conn:
        assert conn.execute("SELECT current_setting('app.user_id', true)").fetchone()[0] in (None, "")


def test_viewer_cannot_insert(local_db):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with db.get_conn("viewer", str(uuid.uuid4())) as conn:
            conn.execute(
                "INSERT INTO activities (id, event_id, title, start_time, duration_minutes)"
                " VALUES (gen_random_uuid(), gen_random_uuid(), 'x', '09:00', 30)"
            )


def test_error_rolls_the_transaction_back(local_db):
    email = "rollback-%s@example.com" % uuid.uuid4().hex
    with pytest.raises(RuntimeError):
        with db.get_conn("auth") as conn:
            conn.execute(
                "INSERT INTO users (id, email, display_name, password_hash)"
                " VALUES (gen_random_uuid(), %s, 'tmp', 'x')",
                (email,),
            )
            raise RuntimeError("fail after the insert")
    with db.get_conn("auth") as conn:
        count = conn.execute("SELECT count(*) FROM users WHERE email = %s", (email,)).fetchone()[0]
    assert count == 0


def test_success_commits(local_db):
    email = "commit-%s@example.com" % uuid.uuid4().hex
    with db.get_conn("auth") as conn:
        conn.execute(
            "INSERT INTO users (id, email, display_name, password_hash)"
            " VALUES (gen_random_uuid(), %s, 'tmp', 'x')",
            (email,),
        )
    with db.get_conn("auth") as conn:
        count = conn.execute("SELECT count(*) FROM users WHERE email = %s", (email,)).fetchone()[0]
    assert count == 1  # left in the local test database; "docker compose down -v" resets it


def test_pool_is_lazy_and_has_one_connection(local_db):
    assert "lead" not in db._pools  # nothing opened for a role that was never used
    with db.get_conn("lead"):
        pass
    stats = db._pools["lead"].get_stats()
    assert db._pools["lead"].max_size == 1
    assert stats["pool_max"] == 1
