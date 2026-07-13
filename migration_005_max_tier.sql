-- =====================================================================
-- Migration 005 - Max tier features
-- =====================================================================
-- Adds tables for the two Max-tier features that need persistence:
--   1. api_keys - user-issued REST API tokens (never stored in plaintext)
--   2. webhooks - customer-configured HTTP endpoints for event delivery
--
-- Both are user-scoped and gated at the endpoint level to the 'max' tier.
-- Free/Plus users can't create rows here because the UI + API endpoints
-- refuse them; the DB doesn't need to enforce that.
-- =====================================================================

-- ---------------------------------------------------------------------
-- api_keys
-- ---------------------------------------------------------------------
-- We NEVER store the raw key. On create we return the plaintext once
-- to the caller, then store only:
--   key_hash    - SHA-256 hex of the raw key. Used for lookup at auth
--                 time (indexed).
--   key_prefix  - The first 12 chars of the raw key, e.g. "cpk_a1b2c3d4".
--                 Shown in the UI so the user can identify the key
--                 without exposing anything sensitive. Not secret.
-- Revocation is soft-delete via revoked_at so we keep an audit trail.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_keys (
    id            SERIAL PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    key_hash      TEXT NOT NULL UNIQUE,
    key_prefix    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS ix_api_keys_user_id
    ON api_keys(user_id);

-- Partial index makes auth lookups fast without scanning revoked keys.
CREATE INDEX IF NOT EXISTS ix_api_keys_hash_active
    ON api_keys(key_hash)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------
-- webhooks
-- ---------------------------------------------------------------------
-- events is an array of event names the user has subscribed to.
-- Current supported values:
--   'scan.completed'   - fires when any scan (manual or scheduled) ends
--   'finding.critical' - fires when critical or high severity paths appear
-- secret is a random string; we sign the payload with HMAC-SHA256
-- and put the signature in the X-CloudPath-Signature header. The
-- customer's endpoint verifies with the same secret.
-- failure_count is a monotonic counter used for exponential backoff
-- decisions. Reset on successful delivery. If it exceeds a threshold
-- (e.g. 10) the webhook_sender may auto-disable the hook.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS webhooks (
    id                SERIAL PRIMARY KEY,
    user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url               TEXT NOT NULL,
    secret            TEXT NOT NULL,
    events            TEXT[] NOT NULL DEFAULT ARRAY['scan.completed']::TEXT[],
    active            BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_success_at   TIMESTAMPTZ,
    last_failure_at   TIMESTAMPTZ,
    last_error        TEXT,
    failure_count     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_webhooks_user_id
    ON webhooks(user_id);

CREATE INDEX IF NOT EXISTS ix_webhooks_active
    ON webhooks(active)
    WHERE active = TRUE;
