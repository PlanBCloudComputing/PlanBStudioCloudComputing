"""Settings for Plan B Studio, read from environment variables only (task P1-A3).

Purpose: one place that says where the database is, which secrets the app needs and
which weather service URL to call. Nothing is stored in files or in the code, so every
Cloud Run instance behaves the same and no secret can end up in git.

Important logic:
  * Plain settings are read once when this module is imported.
  * Secrets and the database host are read by functions at call time, so a missing
    secret only fails when it is actually needed (importing the app never breaks).
  * On Cloud Run, DB_INSTANCE_CONNECTION_NAME is set and the database is reached
    through the unix socket /cloudsql/<connection name>. Locally it is not set, so
    the host is DB_HOST (default localhost), for example the Cloud SQL Auth Proxy
    or the local Docker Postgres.
  * DB_PASSWORDS_JSON is a JSON object that maps each database login role to its
    password, for example {"viewer": "...", "editor": "..."}. The app never uses an
    admin account (see app/db.py for the allowed roles).
"""
import json
import os

# Weather provider base URL. Point it at a dead host to demonstrate the 502/503 paths.
OPEN_METEO_BASE_URL = os.environ.get("OPEN_METEO_BASE_URL", "https://api.open-meteo.com/v1")

DB_NAME = os.environ.get("DB_NAME", "planb")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))


def db_host():
    """Return the database host: the Cloud SQL socket on Cloud Run, else DB_HOST."""
    connection_name = os.environ.get("DB_INSTANCE_CONNECTION_NAME")
    if connection_name:
        return "/cloudsql/" + connection_name
    return os.environ.get("DB_HOST", "localhost")


def db_password(role):
    """Return the password for one database login role (for example 'viewer').

    Raises RuntimeError if DB_PASSWORDS_JSON is missing, is not valid JSON, or has no
    entry for the role.
    """
    raw = os.environ.get("DB_PASSWORDS_JSON")
    if not raw:
        raise RuntimeError("DB_PASSWORDS_JSON is not set")
    try:
        passwords = json.loads(raw)
    except ValueError:
        raise RuntimeError("DB_PASSWORDS_JSON is not valid JSON") from None
    if role not in passwords:
        raise RuntimeError("DB_PASSWORDS_JSON has no password for role '%s'" % role)
    return passwords[role]


def jwt_secret():
    """Return the key used to sign login tokens. Raises RuntimeError if it is not set."""
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET is not set")
    return secret
