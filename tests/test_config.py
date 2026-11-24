"""Checks for app/config.py (task P1-A3): database host choice and secret lookups."""
import pytest

from app import config


def test_db_host_uses_cloud_sql_socket_when_connection_name_set(monkeypatch):
    monkeypatch.setenv("DB_INSTANCE_CONNECTION_NAME", "proj:europe-west2:planb-db")
    assert config.db_host() == "/cloudsql/proj:europe-west2:planb-db"


def test_db_host_falls_back_to_local(monkeypatch):
    monkeypatch.delenv("DB_INSTANCE_CONNECTION_NAME", raising=False)
    monkeypatch.delenv("DB_HOST", raising=False)
    assert config.db_host() == "localhost"


def test_db_password_per_role(monkeypatch):
    monkeypatch.setenv("DB_PASSWORDS_JSON", '{"viewer": "v-pass", "editor": "e-pass"}')
    assert config.db_password("editor") == "e-pass"
    with pytest.raises(RuntimeError):
        config.db_password("organiser")  # role not in the JSON


def test_missing_or_bad_secrets_fail_loudly(monkeypatch):
    monkeypatch.delenv("DB_PASSWORDS_JSON", raising=False)
    monkeypatch.delenv("JWT_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        config.db_password("viewer")
    with pytest.raises(RuntimeError):
        config.jwt_secret()
    monkeypatch.setenv("DB_PASSWORDS_JSON", "not json")
    with pytest.raises(RuntimeError):
        config.db_password("viewer")
