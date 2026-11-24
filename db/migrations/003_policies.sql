-- 003_policies.sql: GRANTs and row-level security (see docs/ROLE_DESIGN.md sections 1 and 2).
--
-- Two layers:
--   1. GRANT decides which kind of statement a role may run (refusal = ERROR: permission denied).
--   2. RLS policies decide which rows it may see or change, using the caller's
--      membership role on that event. Flask passes the caller with
--      set_config('app.user_id', '<uuid>', true) at the start of every transaction.
--      A refused read or update usually gives 0 rows, not an error.
-- Tables are owned by planb_migrator and nobody can log in as it, so the owner
-- bypass of RLS never applies to the app roles.
-- Run as postgres; the SET ROLE below switches to the owner role.

SET ROLE planb_migrator;

-- ---------------------------------------------------------------------------
-- Helper functions. SECURITY DEFINER = they run as the owner, who may read
-- event_members without triggering that table's own policy (prevents endless recursion).
-- ---------------------------------------------------------------------------

-- Who is calling? NULL when Flask did not set app.user_id, so no membership matches.
CREATE FUNCTION app_user_id() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;

-- Order of membership roles: viewer < lead < editor < organiser.
CREATE FUNCTION role_rank(r text) RETURNS integer
    LANGUAGE sql IMMUTABLE
    AS $$ SELECT CASE r WHEN 'viewer' THEN 1 WHEN 'lead' THEN 2
                        WHEN 'editor' THEN 3 WHEN 'organiser' THEN 4 ELSE 0 END $$;

-- The caller's membership role on one event, or NULL if not a member.
CREATE FUNCTION member_role(p_event uuid) RETURNS text
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
    AS $$ SELECT role FROM event_members
          WHERE event_id = p_event AND user_id = app_user_id() $$;

-- True when the caller has at least min_role on the event.
CREATE FUNCTION has_role(p_event uuid, min_role text) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
    AS $$ SELECT role_rank(member_role(p_event)) >= role_rank(min_role) $$;

-- First-organiser rule: is the caller the owner of this event?
CREATE FUNCTION is_event_owner(p_event uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
    AS $$ SELECT EXISTS (SELECT 1 FROM events
                         WHERE id = p_event AND owner_id = app_user_id()) $$;

-- First-organiser rule: does the event already have any member?
CREATE FUNCTION event_has_members(p_event uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
    AS $$ SELECT EXISTS (SELECT 1 FROM event_members WHERE event_id = p_event) $$;

-- Do the caller and that user belong to at least one common event?
CREATE FUNCTION shares_event_with(p_user uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
    AS $$ SELECT EXISTS (
              SELECT 1 FROM event_members a JOIN event_members b USING (event_id)
              WHERE a.user_id = app_user_id() AND b.user_id = p_user) $$;

GRANT EXECUTE ON FUNCTION app_user_id(), role_rank(text), member_role(uuid),
    has_role(uuid, text), is_event_owner(uuid), event_has_members(uuid),
    shares_event_with(uuid)
    TO planb_viewer, planb_lead, planb_editor, planb_organiser, weather_ingest;

-- ---------------------------------------------------------------------------
-- Start from nothing: no table is open to PUBLIC, then grant only what is needed.
-- ---------------------------------------------------------------------------
REVOKE ALL ON users, events, event_members, activities, plans, plan_items,
    weather_snapshots, comparisons, decision_log FROM PUBLIC;

ALTER TABLE users             ENABLE ROW LEVEL SECURITY;
ALTER TABLE events            ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_members     ENABLE ROW LEVEL SECURITY;
ALTER TABLE activities        ENABLE ROW LEVEL SECURITY;
ALTER TABLE plans             ENABLE ROW LEVEL SECURITY;
ALTER TABLE plan_items        ENABLE ROW LEVEL SECURITY;
ALTER TABLE weather_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE comparisons       ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_log      ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- users: planb_auth reads and creates any user (login and register).
-- The four membership tiers see only id, email, display_name (never password_hash),
-- and only for themselves and people they share an event with.
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON users TO planb_auth;
GRANT SELECT (id, email, display_name) ON users
    TO planb_viewer, planb_lead, planb_editor, planb_organiser;

CREATE POLICY users_auth_select ON users FOR SELECT TO planb_auth USING (true);
CREATE POLICY users_auth_insert ON users FOR INSERT TO planb_auth WITH CHECK (true);
CREATE POLICY users_tiers_select ON users FOR SELECT
    TO planb_viewer, planb_lead, planb_editor, planb_organiser
    USING (id = app_user_id() OR shares_event_with(id));

-- ---------------------------------------------------------------------------
-- events
-- ---------------------------------------------------------------------------
GRANT SELECT ON events TO planb_viewer, planb_lead, planb_editor, planb_organiser;
GRANT INSERT, DELETE ON events TO planb_organiser;
GRANT UPDATE (title, event_date, timezone, venue_name, venue_lat, venue_lon, updated_at)
    ON events TO planb_editor, planb_organiser;

CREATE POLICY events_select ON events FOR SELECT
    TO planb_viewer, planb_lead, planb_editor, planb_organiser
    USING (has_role(id, 'viewer'));
-- Any logged-in user creates events, but only as themselves (the owner).
CREATE POLICY events_insert ON events FOR INSERT TO planb_organiser
    WITH CHECK (owner_id = app_user_id());
CREATE POLICY events_update ON events FOR UPDATE TO planb_editor, planb_organiser
    USING (has_role(id, 'editor')) WITH CHECK (has_role(id, 'editor'));
CREATE POLICY events_delete ON events FOR DELETE TO planb_organiser
    USING (has_role(id, 'organiser'));

-- ---------------------------------------------------------------------------
-- event_members
-- ---------------------------------------------------------------------------
GRANT SELECT ON event_members TO planb_auth, planb_viewer, planb_lead, planb_editor, planb_organiser;
GRANT INSERT, UPDATE, DELETE ON event_members TO planb_organiser;

-- planb_auth looks up a role before any event context exists; it has SELECT only.
CREATE POLICY members_auth_select ON event_members FOR SELECT TO planb_auth USING (true);
CREATE POLICY members_select ON event_members FOR SELECT
    TO planb_viewer, planb_lead, planb_editor, planb_organiser
    USING (has_role(event_id, 'viewer'));
-- An organiser manages members. The OR branch is the one-off first-organiser row:
-- the event owner adds themself as organiser while the event has no members yet.
CREATE POLICY members_insert ON event_members FOR INSERT TO planb_organiser
    WITH CHECK (
        has_role(event_id, 'organiser')
        OR (user_id = app_user_id() AND role = 'organiser'
            AND is_event_owner(event_id) AND NOT event_has_members(event_id))
    );
CREATE POLICY members_update ON event_members FOR UPDATE TO planb_organiser
    USING (has_role(event_id, 'organiser')) WITH CHECK (has_role(event_id, 'organiser'));
CREATE POLICY members_delete ON event_members FOR DELETE TO planb_organiser
    USING (has_role(event_id, 'organiser'));

-- ---------------------------------------------------------------------------
-- activities
-- ---------------------------------------------------------------------------
GRANT SELECT ON activities TO planb_viewer, planb_lead, planb_editor, planb_organiser;
GRANT INSERT, UPDATE, DELETE ON activities TO planb_editor, planb_organiser;
-- A lead may change only these columns (a column not listed gives "permission denied").
GRANT UPDATE (title, notes, duration_minutes, max_precip_prob, max_wind_kmh,
              fallback_title, fallback_duration_minutes)
    ON activities TO planb_lead;

CREATE POLICY activities_select ON activities FOR SELECT
    TO planb_viewer, planb_lead, planb_editor, planb_organiser
    USING (has_role(event_id, 'viewer'));
CREATE POLICY activities_insert ON activities FOR INSERT TO planb_editor, planb_organiser
    WITH CHECK (has_role(event_id, 'editor'));
CREATE POLICY activities_update ON activities FOR UPDATE TO planb_editor, planb_organiser
    USING (has_role(event_id, 'editor')) WITH CHECK (has_role(event_id, 'editor'));
CREATE POLICY activities_delete ON activities FOR DELETE TO planb_editor, planb_organiser
    USING (has_role(event_id, 'editor'));
-- The lead rule: only activities assigned to the caller. Other rows: UPDATE changes 0 rows.
CREATE POLICY activities_lead_update ON activities FOR UPDATE TO planb_lead
    USING (lead_user_id = app_user_id() AND has_role(event_id, 'lead'))
    WITH CHECK (lead_user_id = app_user_id() AND has_role(event_id, 'lead'));

-- ---------------------------------------------------------------------------
-- plans and plan_items (same pattern: everyone reads, editors and organisers write)
-- ---------------------------------------------------------------------------
GRANT SELECT ON plans, plan_items TO planb_viewer, planb_lead, planb_editor, planb_organiser;
GRANT INSERT, UPDATE, DELETE ON plans, plan_items TO planb_editor, planb_organiser;

CREATE POLICY plans_select ON plans FOR SELECT
    TO planb_viewer, planb_lead, planb_editor, planb_organiser
    USING (has_role(event_id, 'viewer'));
CREATE POLICY plans_insert ON plans FOR INSERT TO planb_editor, planb_organiser
    WITH CHECK (has_role(event_id, 'editor'));
CREATE POLICY plans_update ON plans FOR UPDATE TO planb_editor, planb_organiser
    USING (has_role(event_id, 'editor')) WITH CHECK (has_role(event_id, 'editor'));
CREATE POLICY plans_delete ON plans FOR DELETE TO planb_editor, planb_organiser
    USING (has_role(event_id, 'editor'));

CREATE POLICY plan_items_select ON plan_items FOR SELECT
    TO planb_viewer, planb_lead, planb_editor, planb_organiser
    USING (has_role(event_id, 'viewer'));
CREATE POLICY plan_items_insert ON plan_items FOR INSERT TO planb_editor, planb_organiser
    WITH CHECK (has_role(event_id, 'editor'));
CREATE POLICY plan_items_update ON plan_items FOR UPDATE TO planb_editor, planb_organiser
    USING (has_role(event_id, 'editor')) WITH CHECK (has_role(event_id, 'editor'));
CREATE POLICY plan_items_delete ON plan_items FOR DELETE TO planb_editor, planb_organiser
    USING (has_role(event_id, 'editor'));

-- ---------------------------------------------------------------------------
-- weather_snapshots: written only by weather_ingest, on behalf of an editor or above.
-- ---------------------------------------------------------------------------
GRANT SELECT ON weather_snapshots TO planb_viewer, planb_lead, planb_editor, planb_organiser;
GRANT SELECT, INSERT ON weather_snapshots TO weather_ingest;

CREATE POLICY weather_select ON weather_snapshots FOR SELECT
    TO planb_viewer, planb_lead, planb_editor, planb_organiser
    USING (has_role(event_id, 'viewer'));
CREATE POLICY weather_ingest_select ON weather_snapshots FOR SELECT TO weather_ingest
    USING (has_role(event_id, 'editor'));
CREATE POLICY weather_ingest_insert ON weather_snapshots FOR INSERT TO weather_ingest
    WITH CHECK (has_role(event_id, 'editor'));

-- ---------------------------------------------------------------------------
-- comparisons: everyone reads, editors and organisers add (as themselves).
-- ---------------------------------------------------------------------------
GRANT SELECT ON comparisons TO planb_viewer, planb_lead, planb_editor, planb_organiser;
GRANT INSERT ON comparisons TO planb_editor, planb_organiser;

CREATE POLICY comparisons_select ON comparisons FOR SELECT
    TO planb_viewer, planb_lead, planb_editor, planb_organiser
    USING (has_role(event_id, 'viewer'));
CREATE POLICY comparisons_insert ON comparisons FOR INSERT TO planb_editor, planb_organiser
    WITH CHECK (has_role(event_id, 'editor') AND created_by = app_user_id());

-- ---------------------------------------------------------------------------
-- decision_log: append-only. Only the organiser may INSERT. NOBODY is granted
-- UPDATE or DELETE, so they are refused by GRANT, whatever the policies say.
-- ---------------------------------------------------------------------------
GRANT SELECT ON decision_log TO planb_viewer, planb_lead, planb_editor, planb_organiser;
GRANT INSERT ON decision_log TO planb_organiser;

CREATE POLICY decision_log_select ON decision_log FOR SELECT
    TO planb_viewer, planb_lead, planb_editor, planb_organiser
    USING (has_role(event_id, 'viewer'));
CREATE POLICY decision_log_insert ON decision_log FOR INSERT TO planb_organiser
    WITH CHECK (has_role(event_id, 'organiser') AND created_by = app_user_id());

RESET ROLE;
