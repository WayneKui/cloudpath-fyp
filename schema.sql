-- ============================================================
-- CloudPath PostgreSQL schema
-- ============================================================
--
-- This schema underpins CloudPath's multi-tenant architecture.
-- Each row in the users table represents a tenant; their data
-- (cloud credentials, ingestion jobs) is foreign-keyed back to
-- their user_id. Per-tenant Neo4j data isolation is achieved by
-- creating a separate Neo4j database named "tenant_<user_id>"
-- at signup time.
--
-- Design notes:
--   - user.id IS the tenant_id. A single-user-per-tenant model
--     is sufficient for FYP scope; team accounts are documented
--     as future work.
--   - All credentials are stored Fernet-encrypted in a BYTEA
--     blob. The encryption key lives in the CLOUDPATH_ENCRYPTION_KEY
--     environment variable.
--   - subscription_tier is stored now and used later for the
--     deferred subscription-tier feature.
--
-- Apply with:
--   docker exec -i cloudpath-postgres psql -U cloudpath -d cloudpath < schema.sql

BEGIN;

-- ------------------------------------------------------------
-- USERS: Authentication and tenant identity
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id                    SERIAL PRIMARY KEY,
    email                 VARCHAR(255) NOT NULL UNIQUE,
    password_hash         VARCHAR(255) NOT NULL,
    display_name          VARCHAR(100),
    subscription_tier     VARCHAR(20) NOT NULL DEFAULT 'free'
                          CHECK (subscription_tier IN ('free', 'plus', 'max')),
    neo4j_database_name   VARCHAR(63) NOT NULL UNIQUE,
    aws_external_id       VARCHAR(100) NOT NULL UNIQUE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at         TIMESTAMPTZ,
    is_active             BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

COMMENT ON TABLE  users                       IS 'Auth + tenant identity (user.id is tenant_id)';
COMMENT ON COLUMN users.password_hash         IS 'bcrypt hash; never plaintext';
COMMENT ON COLUMN users.neo4j_database_name   IS 'Generated at signup: tenant_<id>';
COMMENT ON COLUMN users.aws_external_id       IS 'Per-tenant token in role trust policy; prevents confused-deputy attacks';
COMMENT ON COLUMN users.subscription_tier     IS 'free|plus|max; tier gating deferred';


-- ------------------------------------------------------------
-- CLOUD_CREDENTIALS: Per-user cloud account credentials
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cloud_credentials (
    id                    SERIAL PRIMARY KEY,
    user_id               INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cloud                 VARCHAR(10) NOT NULL CHECK (cloud IN ('aws', 'gcp')),
    label                 VARCHAR(100) NOT NULL,
    encrypted_blob        BYTEA NOT NULL,
    aws_role_arn          VARCHAR(2048),
    aws_external_id       VARCHAR(2048),
    last_refreshed_at     TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, cloud, label)
);

CREATE INDEX IF NOT EXISTS idx_creds_user        ON cloud_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_creds_expires_at  ON cloud_credentials(expires_at)
    WHERE expires_at IS NOT NULL;

COMMENT ON TABLE  cloud_credentials                IS 'Encrypted per-user cloud creds';
COMMENT ON COLUMN cloud_credentials.encrypted_blob IS 'Fernet-encrypted JSON of cred fields';
COMMENT ON COLUMN cloud_credentials.aws_role_arn   IS 'Set if this row is an STS assume-role config';
COMMENT ON COLUMN cloud_credentials.expires_at     IS 'When STS-derived creds expire; NULL for static creds';


-- ------------------------------------------------------------
-- INGESTION_JOBS: Track background pipeline runs
-- ------------------------------------------------------------
-- Replaces the in-memory PIPELINE_JOB global from earlier sessions.
-- Persisting jobs to the database means status survives Flask restarts
-- and is queryable across requests/sessions.
CREATE TABLE IF NOT EXISTS ingestion_jobs (
    id                    SERIAL PRIMARY KEY,
    user_id               INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status                VARCHAR(20) NOT NULL DEFAULT 'queued'
                          CHECK (status IN ('queued', 'running', 'complete', 'failed')),
    current_step          VARCHAR(50),
    step_log              JSONB NOT NULL DEFAULT '[]'::jsonb,
    error                 TEXT,
    started_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at           TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_jobs_user_status ON ingestion_jobs(user_id, status);
CREATE INDEX IF NOT EXISTS idx_jobs_started     ON ingestion_jobs(started_at DESC);

COMMENT ON TABLE ingestion_jobs IS 'Per-tenant pipeline execution log';
COMMENT ON COLUMN ingestion_jobs.step_log IS 'JSONB array of {name, status, error?, timing_ms?} objects';

COMMIT;