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
-- On Cloud SQL the admin user (postgres) is not a true superuser, so it cannot
-- SET ROLE to a role it created unless it is explicitly granted that right.
-- 002 and 003 start with SET ROLE planb_migrator, so grant it here (harmless locally).
GRANT planb_migrator TO CURRENT_USER WITH SET TRUE;

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

-- PostgreSQL lets PUBLIC execute every new function. That is a global default, so it
-- can only be removed globally (a REVOKE limited to one schema has no effect).
-- This turns it off for all functions the migrator creates; 003_policies.sql then
-- grants EXECUTE on the helper functions to the roles that need them.
-- It needs membership of planb_migrator, so it must come after the GRANT above.
ALTER DEFAULT PRIVILEGES FOR ROLE planb_migrator
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
