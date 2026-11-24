-- 002_schema.sql: creates the tables (see docs/ROLE_DESIGN.md section 3).
--
-- Logic:
--   * Everything is created as planb_migrator, so it owns the tables.
--   * Every child table carries event_id, and references to sibling tables are
--     composite foreign keys (event_id, other_id). A row can therefore never
--     point at something that belongs to a different event.
--   * Flask generates the uuid ids, so the columns have no default.
-- Run as postgres; the SET ROLE below switches to the owner role.

SET ROLE planb_migrator;

CREATE TABLE users (
    id            uuid PRIMARY KEY,
    email         text NOT NULL,
    display_name  text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 60),
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
-- One account per email, ignoring upper/lower case (duplicate -> 409 in Flask).
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

CREATE TABLE events (
    id         uuid PRIMARY KEY,
    owner_id   uuid NOT NULL REFERENCES users (id),
    title      text NOT NULL,
    event_date date NOT NULL,
    timezone   text NOT NULL,
    venue_name text NOT NULL,
    venue_lat  double precision NOT NULL CHECK (venue_lat BETWEEN -90 AND 90),
    venue_lon  double precision NOT NULL CHECK (venue_lon BETWEEN -180 AND 180),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX events_owner_idx ON events (owner_id);

-- One row per person per event; "role" is the per-event membership role.
CREATE TABLE event_members (
    event_id uuid NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    user_id  uuid NOT NULL REFERENCES users (id),
    role     text NOT NULL CHECK (role IN ('viewer', 'lead', 'editor', 'organiser')),
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, user_id)
);
CREATE INDEX event_members_user_idx ON event_members (user_id);

CREATE TABLE activities (
    id                        uuid PRIMARY KEY,
    event_id                  uuid NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    title                     text NOT NULL,
    start_time                time NOT NULL,
    duration_minutes          integer NOT NULL CHECK (duration_minutes BETWEEN 5 AND 480),
    outdoor                   boolean NOT NULL DEFAULT false,
    max_precip_prob           integer NOT NULL DEFAULT 100 CHECK (max_precip_prob BETWEEN 0 AND 100),
    max_wind_kmh              integer NOT NULL DEFAULT 120 CHECK (max_wind_kmh BETWEEN 0 AND 120),
    lead_user_id              uuid,
    fallback_title            text,
    fallback_duration_minutes integer CHECK (fallback_duration_minutes BETWEEN 5 AND 480),
    notes                     text,
    created_at                timestamptz NOT NULL DEFAULT now(),
    UNIQUE (event_id, id),
    -- A lead must be a member of the same event. NULL lead_user_id skips this check.
    FOREIGN KEY (event_id, lead_user_id) REFERENCES event_members (event_id, user_id)
);
CREATE INDEX activities_event_idx ON activities (event_id);

CREATE TABLE plans (
    id         uuid PRIMARY KEY,
    event_id   uuid NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    label      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (event_id, id)
);
CREATE INDEX plans_event_idx ON plans (event_id);

CREATE TABLE plan_items (
    id          uuid PRIMARY KEY,
    plan_id     uuid NOT NULL,
    event_id    uuid NOT NULL,
    activity_id uuid NOT NULL,
    start_time  time NOT NULL,
    use_fallback boolean NOT NULL DEFAULT false,
    -- Plan and activity must both belong to the item's event.
    FOREIGN KEY (event_id, plan_id)     REFERENCES plans (event_id, id)      ON DELETE CASCADE,
    FOREIGN KEY (event_id, activity_id) REFERENCES activities (event_id, id) ON DELETE CASCADE,
    -- An activity can appear once per plan (duplicate -> 409 in Flask).
    UNIQUE (plan_id, activity_id)
);
CREATE INDEX plan_items_plan_idx ON plan_items (plan_id);

CREATE TABLE weather_snapshots (
    id         uuid PRIMARY KEY,
    event_id   uuid NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    fetched_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    hourly     jsonb NOT NULL,
    UNIQUE (event_id, id)
);
CREATE INDEX weather_snapshots_latest_idx ON weather_snapshots (event_id, fetched_at DESC);

CREATE TABLE comparisons (
    id             uuid PRIMARY KEY,
    event_id       uuid NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    snapshot_id    uuid NOT NULL,
    method_version text NOT NULL,
    seed           bigint NOT NULL,
    runs           integer NOT NULL CHECK (runs BETWEEN 100 AND 5000),
    results        jsonb NOT NULL,
    created_by     uuid NOT NULL REFERENCES users (id),
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (event_id, id),
    FOREIGN KEY (event_id, snapshot_id) REFERENCES weather_snapshots (event_id, id)
);
CREATE INDEX comparisons_event_idx ON comparisons (event_id, created_at DESC);

-- Append-only record of committed decisions (INSERT only, see 003_policies.sql).
CREATE TABLE decision_log (
    id            uuid PRIMARY KEY,
    event_id      uuid NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    plan_id       uuid NOT NULL,
    comparison_id uuid NOT NULL,
    note          text,
    created_by    uuid NOT NULL REFERENCES users (id),
    created_at    timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (event_id, plan_id)       REFERENCES plans (event_id, id),
    FOREIGN KEY (event_id, comparison_id) REFERENCES comparisons (event_id, id)
);
CREATE INDEX decision_log_event_idx ON decision_log (event_id, created_at);

RESET ROLE;
