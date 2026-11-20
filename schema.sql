-- =============================================================================
-- SecureEvent  --  PostgreSQL schema  (Supabase)
-- Run this in the Supabase SQL Editor once.
-- =============================================================================

-- ── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(80)  NOT NULL,
    email           VARCHAR(120) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(20)  NOT NULL DEFAULT 'student'
                        CHECK (role IN ('student','organizer','admin')),
    failed_attempts INTEGER      NOT NULL DEFAULT 0,
    locked_until    TIMESTAMP    NULL
);

-- ── Events ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id              SERIAL PRIMARY KEY,
    organizer_id    INTEGER      NOT NULL REFERENCES users(id),
    title           VARCHAR(120) NOT NULL,
    description     TEXT,
    event_date      TIMESTAMP    NOT NULL,
    capacity        INTEGER      NOT NULL,
    reg_deadline    TIMESTAMP    NOT NULL
);

-- ── Registrations ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS registrations (
    id              SERIAL PRIMARY KEY,
    event_id        INTEGER      NOT NULL REFERENCES events(id),
    user_id         INTEGER      NOT NULL REFERENCES users(id),
    ticket_code     VARCHAR(100) NOT NULL UNIQUE,
    status          VARCHAR(20)  NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','cancelled')),
    checked_in      BOOLEAN      NOT NULL DEFAULT FALSE,
    checked_in_at   TIMESTAMP    NULL,
    UNIQUE (event_id, user_id)   -- prevents double registration at DB level
);

-- ── Audit log ────────────────────────────────────────────────────────────────
-- The app role only has INSERT + SELECT here (no UPDATE/DELETE).
-- Even a compromised app cannot erase its own log entries.
CREATE TABLE IF NOT EXISTS audit_log (
    id      SERIAL PRIMARY KEY,
    ts      TIMESTAMP NOT NULL DEFAULT NOW(),
    user_id INTEGER   NULL,
    action  VARCHAR(60)  NOT NULL,
    detail  VARCHAR(255),
    ip      VARCHAR(45)
);

-- =============================================================================
-- Least-privilege role for the application
-- (Supabase projects already use the postgres superuser for setup;
--  create a separate role for the app to match the MySQL original.)
-- =============================================================================
-- Run these as the postgres superuser in the Supabase SQL Editor:

-- CREATE ROLE secureevent_app WITH LOGIN PASSWORD 'choose-a-strong-password';
-- GRANT SELECT, INSERT, UPDATE ON users         TO secureevent_app;
-- GRANT SELECT, INSERT, UPDATE ON events        TO secureevent_app;
-- GRANT SELECT, INSERT, UPDATE ON registrations TO secureevent_app;
-- GRANT SELECT, INSERT         ON audit_log     TO secureevent_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO secureevent_app;

-- =============================================================================
-- Seed data: one admin account (password: Admin@1234)
-- Generate a fresh hash in Python:
--   import bcrypt; bcrypt.hashpw(b"Admin@1234", bcrypt.gensalt(12)).decode()
-- =============================================================================
-- INSERT INTO users (name, email, password_hash, role)
-- VALUES ('Admin', 'admin@secureevent.local',
--         '$2b$12$REPLACE_WITH_REAL_HASH', 'admin');
