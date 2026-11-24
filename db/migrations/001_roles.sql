-- 001_roles.sql: creates the database roles (see docs/ROLE_DESIGN.md section 1).
--
-- Logic:
--   * planb_migrator owns every table and function. It cannot log in.
--   * The six app roles can log in but are NOSUPERUSER and NOBYPASSRLS, and own
--     nothing, so row-level security and GRANTs always apply to them.
--   * No passwords are set here, so these files are safe to run on any server.
--     Locally, docker-compose.yml sets fake passwords. On Cloud SQL, random
--     passwords are set by hand with ALTER ROLE and never go into git.
--   * What each role may do is granted in 003_policies.sql.
-- Run as the database admin (postgres) only. The app never connects as postgres.

CREATE ROLE planb_migrator NOLOGIN;

CREATE ROLE planb_auth       LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE planb_viewer     LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE planb_editor     LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE planb_lead       LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE planb_organiser  LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
CREATE ROLE weather_ingest   LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- Nobody gets anything by default: only the roles named below may connect.
REVOKE CONNECT ON DATABASE planb FROM PUBLIC;
GRANT CONNECT ON DATABASE planb TO
    planb_auth, planb_viewer, planb_editor, planb_lead, planb_organiser, weather_ingest;

-- The migrator creates tables in the public schema; nobody else may create objects there.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO planb_migrator;
GRANT USAGE ON SCHEMA public TO
    planb_auth, planb_viewer, planb_editor, planb_lead, planb_organiser, weather_ingest;

-- Functions are executable by PUBLIC by default. Turn that off for everything the migrator creates.
ALTER DEFAULT PRIVILEGES FOR ROLE planb_migrator IN SCHEMA public
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
