-- ============================================================================
-- Migration 004: Scheduled scans (Plus tier)
-- ============================================================================
-- Adds two tables:
--   scan_schedules : one row per user, defines their recurring scan setup
--   scan_history   : one row per completed scan run (manual or scheduled),
--                    used to display the History page
--
-- Design notes:
--   - schedule_frequency stored as enum-like VARCHAR ('daily' | 'weekly')
--   - day_of_week is only meaningful for 'weekly' (NULL for 'daily')
--   - time_of_day uses TIME (PostgreSQL's hour-minute type, no date)
--   - All times conceptually MYT (UTC+8). Stored as TIME without timezone;
--     the scheduler converts MYT to UTC internally when comparing to NOW().
--   - is_paused lets users pause without deleting their schedule
--   - last_run_at / next_run_at are denormalized for fast scheduler queries
-- ============================================================================

CREATE TABLE IF NOT EXISTS scan_schedules (
    id                  SERIAL PRIMARY KEY,
    user_id             INTEGER NOT NULL UNIQUE
                            REFERENCES users(id) ON DELETE CASCADE,
    schedule_frequency  VARCHAR(20) NOT NULL
                            CHECK (schedule_frequency IN ('daily', 'weekly')),
    day_of_week         INTEGER
                            CHECK (day_of_week IS NULL
                                   OR (day_of_week BETWEEN 0 AND 6)),
    time_of_day         TIME NOT NULL DEFAULT '09:00:00',
    is_paused           BOOLEAN NOT NULL DEFAULT FALSE,
    last_run_at         TIMESTAMPTZ,
    next_run_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_schedules_next_run
    ON scan_schedules (next_run_at)
    WHERE is_paused = FALSE;


CREATE TABLE IF NOT EXISTS scan_history (
    id                  SERIAL PRIMARY KEY,
    user_id             INTEGER NOT NULL
                            REFERENCES users(id) ON DELETE CASCADE,
    triggered_by        VARCHAR(20) NOT NULL
                            CHECK (triggered_by IN ('manual', 'scheduled', 'api')),
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ,
    status              VARCHAR(20) NOT NULL DEFAULT 'running'
                            CHECK (status IN ('running', 'success', 'failure')),
    error_message       TEXT,
    paths_found         INTEGER,
    critical_paths      INTEGER,
    high_paths          INTEGER,
    medium_paths        INTEGER,
    low_paths           INTEGER,
    detections_count    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_scan_history_user_started
    ON scan_history (user_id, started_at DESC);

-- ============================================================================
-- Verification queries (run manually after migration):
--
-- \d scan_schedules
-- \d scan_history
--
-- Expected: both tables exist with the columns above.
-- ============================================================================
