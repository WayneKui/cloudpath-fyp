-- ============================================================
-- CloudPath migration 002 — add aws_external_id to users
-- ============================================================
--
-- The external ID is a per-user UUID-flavoured token that the user
-- includes in their IAM role's trust policy. When the server later
-- calls sts:AssumeRole against that role, it passes this external ID.
-- AWS verifies it matches — preventing the "confused deputy" attack
-- where a malicious tenant tricks us into assuming the wrong role.
--
-- We generate the external ID once at user signup and never change it.
-- Format: "cloudpath-tenant-<user_id>-<8-hex-chars>" — recognisable
-- in CloudTrail logs, unguessable suffix.
--
-- This migration is idempotent (IF NOT EXISTS) so it can be re-applied
-- safely. For your local dev environment, easiest is to re-run the
-- whole stack with `docker-compose down -v && up -d` so schema.sql
-- runs from scratch with the new column already included. Or apply
-- this migration manually:
--
--   docker exec -i cloudpath-postgres psql -U cloudpath -d cloudpath \
--     < migration_002_aws_external_id.sql

BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS aws_external_id VARCHAR(100) UNIQUE;

COMMENT ON COLUMN users.aws_external_id IS
    'Per-tenant external ID used in AWS sts:AssumeRole trust policy. '
    'Generated at signup; never changes. Prevents confused-deputy attacks.';

-- Backfill: any existing users without an external ID get one now.
-- gen_random_uuid() is built into PostgreSQL 13+ (no extension needed).
UPDATE users
   SET aws_external_id = 'cloudpath-tenant-' || id || '-' ||
                         substring(replace(gen_random_uuid()::text, '-', ''), 1, 8)
 WHERE aws_external_id IS NULL;

-- Make the column NOT NULL going forward. Safe because the backfill
-- above ensured every existing row has a value.
ALTER TABLE users
    ALTER COLUMN aws_external_id SET NOT NULL;

COMMIT;
