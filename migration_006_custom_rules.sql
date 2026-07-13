-- =====================================================================
-- Migration 006 - Custom detection rules (per-tenant)
-- =====================================================================
-- Backs the Rule Manager's "Save Rule" button with real persistence.
-- Previously /rules only displayed the 4 built-in YAML rules and the
-- Save button was a no-op (fake success message, nothing written
-- anywhere). This table lets each user save/edit/delete their own
-- Cypher detection rules, scoped strictly to their account.
--
-- The 4 built-in rules (rules/*.yaml) stay immutable and are not
-- stored here — this table is additive, not a replacement.
--
-- rule_key is unique PER USER (not globally), so Alice and Bob can
-- both use "T9001" as their own mnemonic id without colliding.
-- =====================================================================

CREATE TABLE IF NOT EXISTS custom_rules (
    id           SERIAL PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rule_key     VARCHAR(50) NOT NULL,
    mitre_name   VARCHAR(200) NOT NULL,
    tactic       VARCHAR(50) NOT NULL,
    severity     VARCHAR(20) NOT NULL DEFAULT 'medium'
                 CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    cloud        VARCHAR(20) NOT NULL DEFAULT 'aws',
    description  TEXT,
    cypher       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, rule_key)
);

CREATE INDEX IF NOT EXISTS ix_custom_rules_user_id
    ON custom_rules(user_id);
