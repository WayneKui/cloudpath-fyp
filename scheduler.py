"""
scheduler.py — Scheduled scans (Plus tier).

Stage 1 (this file): CRUD endpoints for the user's schedule.
  GET    /api/schedule           Returns current user's schedule
  POST   /api/schedule           Create or update schedule
  POST   /api/schedule/pause     Pause/resume
  DELETE /api/schedule           Delete schedule

Tier gating:
  - All endpoints require login.
  - All endpoints require subscription_tier in ('plus', 'max').
    Free tier gets a 403 with a friendly message pointing at /billing.
"""
import datetime
import logging
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

import db

logger = logging.getLogger(__name__)
scheduler_bp = Blueprint("scheduler", __name__)


def _require_paid_tier():
    """Return (ok, response). If not paid, response is the 403 to return."""
    tier = getattr(current_user, "subscription_tier", "free")
    if tier in ("plus", "max"):
        return True, None
    return False, (jsonify({
        "status": "error",
        "message": "Scheduled scans are a Plus tier feature.",
        "upgrade_url": "/billing",
    }), 403)


def _serialize_schedule(row):
    """Convert a scan_schedules row (dict) into JSON-safe shape."""
    if not row:
        return None
    tod = row.get("time_of_day")
    return {
        "id":                 row.get("id"),
        "schedule_frequency": row.get("schedule_frequency"),
        "day_of_week":        row.get("day_of_week"),
        "time_of_day":        tod.isoformat() if hasattr(tod, "isoformat") else str(tod),
        "is_paused":          bool(row.get("is_paused")),
        "last_run_at":        str(row.get("last_run_at")) if row.get("last_run_at") else None,
        "next_run_at":        str(row.get("next_run_at")) if row.get("next_run_at") else None,
    }


@scheduler_bp.route("/api/schedule", methods=["GET"])
@login_required
def get_schedule():
    """Return the current user's schedule, or null if they don't have one.

    Honest design: we return 200 with `schedule: null` rather than 404
    so the frontend doesn't have to treat the absence of schedule as
    an error case.
    """
    ok, err = _require_paid_tier()
    if not ok:
        return err
    row = db.get_user_schedule_sync(current_user.id)
    return jsonify({
        "status":   "ok",
        "schedule": _serialize_schedule(row),
    })


@scheduler_bp.route("/api/schedule", methods=["POST"])
@login_required
def upsert_schedule():
    """Create or update the user's schedule.

    Request body:
        {
          "frequency":   "daily" | "weekly",
          "day_of_week": 0-6 (Monday=0) | null,
          "time_of_day": "HH:MM" (MYT)
        }
    """
    ok, err = _require_paid_tier()
    if not ok:
        return err

    body = request.get_json(silent=True) or {}
    frequency = body.get("frequency")
    day_of_week = body.get("day_of_week")
    time_str = body.get("time_of_day")

    if frequency not in ("daily", "weekly"):
        return jsonify({
            "status": "error",
            "message": "frequency must be 'daily' or 'weekly'",
        }), 400
    if frequency == "weekly":
        if day_of_week is None:
            return jsonify({
                "status": "error",
                "message": "Weekly schedule requires day_of_week (0-6)",
            }), 400
        try:
            day_of_week = int(day_of_week)
        except (TypeError, ValueError):
            return jsonify({
                "status": "error",
                "message": "day_of_week must be an integer 0-6",
            }), 400
        if not 0 <= day_of_week <= 6:
            return jsonify({
                "status": "error",
                "message": "day_of_week must be between 0 (Mon) and 6 (Sun)",
            }), 400
    else:
        day_of_week = None

    # Parse "HH:MM" to datetime.time
    if not isinstance(time_str, str):
        return jsonify({
            "status": "error",
            "message": "time_of_day must be a 'HH:MM' string",
        }), 400
    try:
        parts = time_str.split(":")
        hh = int(parts[0])
        mm = int(parts[1]) if len(parts) > 1 else 0
        if not (0 <= hh <= 23 and 0 <= mm <= 59):
            raise ValueError
        time_of_day = datetime.time(hh, mm)
    except (ValueError, IndexError):
        return jsonify({
            "status": "error",
            "message": "time_of_day must be a valid 'HH:MM' (24-hour)",
        }), 400

    try:
        sched_id = db.upsert_user_schedule_sync(
            current_user.id, frequency, day_of_week, time_of_day,
        )
    except Exception as e:
        logger.exception("Failed to save schedule")
        return jsonify({
            "status": "error",
            "message": f"Could not save schedule: {e}",
        }), 500

    logger.info(
        "User %s saved schedule (id=%s, %s, dow=%s, time=%s)",
        current_user.id, sched_id, frequency, day_of_week, time_of_day,
    )

    row = db.get_user_schedule_sync(current_user.id)
    return jsonify({
        "status":   "ok",
        "schedule": _serialize_schedule(row),
    })


@scheduler_bp.route("/api/schedule/pause", methods=["POST"])
@login_required
def pause_schedule():
    """Pause or resume the user's schedule.

    Request body: { "paused": true | false }
    """
    ok, err = _require_paid_tier()
    if not ok:
        return err

    body = request.get_json(silent=True) or {}
    paused = bool(body.get("paused", True))

    existed = db.pause_user_schedule_sync(current_user.id, paused)
    if not existed:
        return jsonify({
            "status": "error",
            "message": "No schedule found to pause/resume",
        }), 404

    row = db.get_user_schedule_sync(current_user.id)
    return jsonify({
        "status":   "ok",
        "schedule": _serialize_schedule(row),
    })


@scheduler_bp.route("/api/schedule", methods=["DELETE"])
@login_required
def delete_schedule():
    """Delete the user's schedule entirely."""
    ok, err = _require_paid_tier()
    if not ok:
        return err
    existed = db.delete_user_schedule_sync(current_user.id)
    return jsonify({
        "status":  "ok",
        "deleted": existed,
    })


# ===========================================================================
# Background scheduler thread (Stage 2)
# ===========================================================================
# Runs alongside Flask. Wakes every SCHEDULER_TICK_SECONDS, queries the DB
# for any schedule whose next_run_at is in the past and isn't paused, and
# fires a full pipeline scan for that user.
#
# Honest design choices:
#   1. Tick interval is 60 seconds. Faster = more DB load + better
#      responsiveness. 60s is the sweet spot: a user scheduling "10:00"
#      sees the scan start by 10:01 at the latest.
#   2. We mark schedule as "ran" (update last_run_at + next_run_at) BEFORE
#      firing the scan. This way if the scan takes longer than the next
#      interval, we don't fire it twice.
#   3. Each scan runs INSIDE the existing PIPELINE_LOCK (acquired by the
#      app.py _run_pipeline_thread). The lock serialises scans across
#      manual and scheduled triggers — no two scans at once.
#   4. We catch+log exceptions so one user's scan failure doesn't kill
#      the scheduler.
#   5. The thread is daemon=True so it dies when Flask shuts down.
# ===========================================================================
import threading
import time

# Tick interval. 60s is a reasonable default. Set to 10s for testing
# (so a schedule set to "now+1min" fires noticeably).
SCHEDULER_TICK_SECONDS = 60

# Set by start_scheduler() so the thread can call into app.py without
# creating a circular import at module load time.
_pipeline_runner = None
_pipeline_job_dict = None


def start_scheduler(pipeline_runner_fn, pipeline_job_dict):
    """Start the background scheduler thread.

    Args:
        pipeline_runner_fn: callable(job_id, user_id) — same signature as
            app.py's _run_pipeline_thread. Called on every due schedule.
        pipeline_job_dict: the shared PIPELINE_JOB dict from app.py so we
            can monitor whether a scan is already running.
    """
    global _pipeline_runner, _pipeline_job_dict
    _pipeline_runner = pipeline_runner_fn
    _pipeline_job_dict = pipeline_job_dict
    t = threading.Thread(target=_scheduler_loop, daemon=True, name="scheduler")
    t.start()
    print(f"[scheduler] started; tick={SCHEDULER_TICK_SECONDS}s", flush=True)
    logger.info("Scheduler thread started (tick=%ds)", SCHEDULER_TICK_SECONDS)


def _scheduler_loop():
    """Main loop. Wakes every tick, processes due schedules, repeats."""
    while True:
        try:
            _process_due_schedules()
        except Exception as e:
            print(f"[scheduler] loop crashed: {e}", flush=True)
            logger.exception("Scheduler loop iteration crashed")
        time.sleep(SCHEDULER_TICK_SECONDS)


def _process_due_schedules():
    """Find all due schedules and fire scans for them."""
    if _pipeline_runner is None:
        return
    try:
        due = db.get_due_schedules_sync()
    except Exception as e:
        print(f"[scheduler] DB query failed: {e}", flush=True)
        logger.exception("Could not query due schedules")
        return
    if not due:
        return
    print(f"[scheduler] {len(due)} schedule(s) due", flush=True)
    logger.info("Scheduler: %d schedule(s) due", len(due))
    for sched in due:
        _fire_scan_for_schedule(sched)


def _fire_scan_for_schedule(sched):
    """Fire one scheduled scan, marking the schedule as ran first."""
    user_id = sched["user_id"]
    sched_id = sched["id"]
    try:
        db.mark_schedule_ran_sync(
            sched_id,
            sched["schedule_frequency"],
            sched["day_of_week"],
            sched["time_of_day"],
        )
    except Exception as e:
        print(f"[scheduler] mark_ran failed for sched {sched_id}: {e}", flush=True)
        logger.exception("Could not mark schedule %s as ran; skipping", sched_id)
        return

    # SECURITY/CORRECTNESS: this used to check _pipeline_job_dict's
    # cached "status" field — a reference captured once in
    # start_scheduler() that goes stale the moment ANY manual or API
    # scan rebinds app.PIPELINE_JOB (its own docstring above admits
    # this: "the reference we captured... is stale after the first
    # manual scan"). It was also a non-atomic check: two things could
    # race between the read and the thread spawn below. The actual
    # cross-process guard is app.PIPELINE_LOCK — every scan trigger
    # (manual, API, scheduled) must go through it, or tag_tenant_nodes'
    # scan-start time fence (which assumes scans never overlap) can
    # misattribute nodes to the wrong tenant. Acquire it atomically
    # here; _run_scheduled_scan -> _pipeline_runner (app.py's
    # _run_pipeline_thread) releases it in its own finally block, same
    # as the manual and API trigger paths.
    try:
        import app as _app
    except Exception as e:
        print(f"[scheduler] could not import app for lock check: {e}", flush=True)
        return
    if not _app.PIPELINE_LOCK.acquire(blocking=False):
        print(f"[scheduler] scan already running; skipping sched {sched_id} for user {user_id}", flush=True)
        return

    history_id = None
    try:
        history_id = db.record_scan_started_sync(user_id, "scheduled")
    except Exception as e:
        print(f"[scheduler] history insert failed for user {user_id}: {e}", flush=True)

    job_id = f"sched-{sched_id}-{int(time.time())}"
    scan_thread = threading.Thread(
        target=_run_scheduled_scan,
        args=(job_id, user_id, history_id),
        daemon=True,
        name=f"sched-scan-{user_id}",
    )
    scan_thread.start()
    print(f"[scheduler] fired scan for user {user_id} (sched {sched_id}, job {job_id})", flush=True)


def _run_scheduled_scan(job_id, user_id, history_id):
    """Wrapper that runs the pipeline and records the result to scan_history.

    Important: the manual flow REBINDS the module-level PIPELINE_JOB name
    in app.py (assigns a new dict), which means the reference we captured
    in start_scheduler() is stale after the first manual scan. To read
    the CURRENT pipeline job state, we re-import from app.py fresh at
    read time.
    """
    status = "success"
    error_message = None
    summary = {
        "paths_found":      None,
        "critical_paths":   None,
        "high_paths":       None,
        "medium_paths":     None,
        "low_paths":        None,
        "detections_count": None,
    }
    # CRITICAL: reset PIPELINE_JOB to a fresh dict BEFORE calling the
    # pipeline runner. Without this, the pipeline sees stale state left
    # over from the previous MANUAL scan — same "steps" list, same
    # "history_id" (belonging to a completed manual row), same "result".
    # We set history_id = ours so _run_pipeline_thread's own finally
    # block will correctly UPDATE the scheduled scan's row. Our own
    # DB update below still runs as a belt-and-braces backup.
    try:
        import app as _app
        _app.PIPELINE_JOB = {
            "job_id":       job_id,
            "user_id":      user_id,
            "history_id":   history_id,
            "started_at":   int(time.time()),
            "finished_at":  None,
            "status":       "running",
            "current_step": None,
            "steps":        [],
            "result":       None,
            "error":        None,
        }
        # Also update our cached reference so status checks in
        # _fire_scan_for_schedule see the new dict, not the old one.
        global _pipeline_job_dict
        _pipeline_job_dict = _app.PIPELINE_JOB
    except Exception as _reset_err:
        print(f"[scheduler] could not reset PIPELINE_JOB: {_reset_err}", flush=True)
    try:
        _pipeline_runner(job_id, user_id)
        # Read the CURRENT PIPELINE_JOB fresh from app.py's module.
        # (Not the stale reference from start_scheduler.)
        try:
            import app as _app
            current_job = getattr(_app, "PIPELINE_JOB", None) or {}
        except Exception:
            current_job = {}

        if current_job.get("status") in ("failed", "failure"):
            status = "failure"
            error_message = current_job.get("error")
        elif current_job.get("status") == "complete":
            status = "success"
        result = current_job.get("result") or {}
        if isinstance(result, dict):
            kpi = result.get("kpi", {}) if isinstance(result.get("kpi"), dict) else {}
            summary = {
                "paths_found":      kpi.get("total_paths"),
                "critical_paths":   kpi.get("critical"),
                "high_paths":       kpi.get("high"),
                "medium_paths":     kpi.get("medium"),
                "low_paths":        kpi.get("low"),
                "detections_count": result.get("detection_count"),
            }

        # FALLBACK: if the pipeline succeeded but produced no usable KPI
        # (result missing / kpi empty / all None), recompute directly by
        # calling app.compute_dashboard_data(user_id). This is the same
        # function the manual scan uses and it reads live Neo4j state,
        # so it should always work if the scan ingested data properly.
        if status == "success" and summary.get("paths_found") is None:
            try:
                import app as _app
                fresh = _app.compute_dashboard_data(user_id)
                if isinstance(fresh, dict) and isinstance(fresh.get("kpi"), dict):
                    kpi = fresh["kpi"]
                    summary = {
                        "paths_found":      kpi.get("total_paths"),
                        "critical_paths":   kpi.get("critical"),
                        "high_paths":       kpi.get("high"),
                        "medium_paths":     kpi.get("medium"),
                        "low_paths":        kpi.get("low"),
                        "detections_count": fresh.get("detection_count"),
                    }
                    print(
                        f"[scheduler] fallback compute_dashboard_data for user "
                        f"{user_id}: paths={summary['paths_found']}",
                        flush=True,
                    )
            except Exception as _fb_err:
                print(f"[scheduler] fallback recompute failed: {_fb_err}", flush=True)
    except Exception as e:
        print(f"[scheduler] scheduled scan for user {user_id} crashed: {e}", flush=True)
        logger.exception("Scheduled scan for user %s crashed", user_id)
        status = "failure"
        error_message = str(e)

    # Always record completion in scan_history, regardless of outcome.
    if history_id is not None:
        try:
            db.record_scan_completed_sync(
                history_id, status,
                error_message=error_message, summary=summary,
            )
            print(
                f"[scheduler] scan complete for user {user_id}: "
                f"status={status}, paths={summary.get('paths_found')}",
                flush=True,
            )
        except Exception as e:
            print(f"[scheduler] history update failed: {e}", flush=True)
            logger.exception("Failed to record scan completion in history")