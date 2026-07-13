-- ============================================================================
-- Migration 003: Subscription billing columns
-- ============================================================================
-- Adds columns required for LemonSqueezy subscription tracking.
--
-- The existing `subscription_tier` column (from schema.sql) already enforces
-- the free / plus / max enum via CHECK constraint. This migration adds:
--   - `lemonsqueezy_customer_id`  — LemonSqueezy's identifier for this user
--                                    (set on first subscription)
--   - `lemonsqueezy_subscription_id` — Current active subscription
--                                       (NULL when on free tier)
--   - `tier_updated_at`           — Audit timestamp; when tier last changed
-- ============================================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS lemonsqueezy_customer_id     VARCHAR(64),
    ADD COLUMN IF NOT EXISTS lemonsqueezy_subscription_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS tier_updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Index for webhook lookup: webhooks arrive identifying the customer or
-- subscription, and we need to find the corresponding user quickly.
CREATE INDEX IF NOT EXISTS idx_users_lemonsqueezy_customer
    ON users (lemonsqueezy_customer_id)
    WHERE lemonsqueezy_customer_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_users_lemonsqueezy_subscription
    ON users (lemonsqueezy_subscription_id)
    WHERE lemonsqueezy_subscription_id IS NOT NULL;

-- ============================================================================
-- Verification queries (run manually after migration):
--
-- SELECT column_name, data_type, is_nullable
-- FROM information_schema.columns
-- WHERE table_name='users' AND column_name LIKE 'lemonsqueezy%'
--    OR column_name = 'tier_updated_at';
--
-- Expected: 3 rows.
-- ============================================================================