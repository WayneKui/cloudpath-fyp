-- =====================================================================
-- Migration 007 - Fix scan_history.triggered_by CHECK constraint
-- =====================================================================
-- migration_004 created scan_history with
--   CHECK (triggered_by IN ('manual', 'scheduled'))
-- but api_v1.py's trigger_scan() has always recorded triggered_by='api'
-- for scans started via POST /api/v1/scans (a Max-tier feature). Every
-- such insert has been silently failing (caught and logged, not
-- fatal — the scan itself still runs), which means API-triggered scans
-- have never appeared in scan_history or the /history page, and their
-- completion never gets recorded either since history_id stays NULL.
--
-- migration_004_scheduled_scans.sql has also been updated so a fresh
-- install gets the correct constraint from the start; this migration
-- fixes an already-applied database.
-- =====================================================================

ALTER TABLE scan_history
    DROP CONSTRAINT IF EXISTS scan_history_triggered_by_check;

ALTER TABLE scan_history
    ADD CONSTRAINT scan_history_triggered_by_check
    CHECK (triggered_by IN ('manual', 'scheduled', 'api'));
