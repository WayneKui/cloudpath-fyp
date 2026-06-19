"""
CloudPath STS auto-refresh background worker.

Runs as a daemon thread inside the Flask process. Every REFRESH_INTERVAL
seconds it:

  1. Queries cloud_credentials for AWS entries whose expires_at is
     within REFRESH_WINDOW_MINUTES of NOW (or NULL, meaning never
     refreshed yet).
  2. For each such credential, calls sts:AssumeRole using the server's
     scanner-account credentials (AWS_ACCESS_KEY_ID env vars).
  3. On success: encrypts the new session credentials and updates the
     row's encrypted_blob, expires_at, last_refreshed_at.
  4. On failure: logs the AWS error code and message. Does NOT delete
     the row. expires_at stays at the old value (likely past, so the
     credential is treated as expired by downstream code).

Why a daemon thread (not a separate process or APScheduler):
  - Simpler. No new dependency. Flask is the only thing managing it.
  - When Flask stops, the worker stops with it (daemon=True). No
    orphaned processes.
  - One worker per Flask instance is correct because credentials are
    in PostgreSQL; multiple Flask instances would each see the same
    refresh queue but the database UPDATE is atomic — last writer
    wins, no duplication. We just call it slightly more often.
  - At FYP scale (1-10 users, a handful of credentials each), one
    thread doing one DB query every 5 minutes is essentially free.

Honest design caveats:
  - This is NOT a high-availability solution. If Flask crashes mid-
    refresh, the credential stays at its current expires_at and the
    next worker tick will pick it up. Worst case: a credential is
    stale for one extra refresh interval (~5 min).
  - There's no leader election. With multiple Flask processes, every
    process tries to refresh. asyncpg + the database's row-level
    locking keeps this correct but inefficient. For FYP scope this
    is fine; documented as future work.
  - sts:AssumeRole has a default duration of 1 hour. We don't request
    longer because some roles set MaxSessionDuration=1h. If a user's
    role allows longer sessions and we want fewer refreshes, we'd
    pass DurationSeconds=3600 explicitly (already is the default).

Logging:
  - Every refresh attempt logs to stdout with a clear prefix
    ([refresh_worker]) so it's distinguishable from Flask access
    logs in your terminal.
"""
import os
import sys
import time
import threading
import asyncio
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

import db


# ============================================================
# Configuration
# ============================================================

# How often the worker wakes up and scans for expiring credentials.
REFRESH_INTERVAL_SECONDS = int(os.environ.get(
    "CLOUDPATH_REFRESH_INTERVAL_SECONDS", "300"  # 5 minutes
))

# A credential is eligible for refresh if its expires_at is within
# this many minutes of NOW. With STS tokens that last 1 hour, a
# 10-minute window means we refresh ~50 minutes after the previous
# refresh — comfortably before expiry.
REFRESH_WINDOW_MINUTES = int(os.environ.get(
    "CLOUDPATH_REFRESH_WINDOW_MINUTES", "10"
))

# STS AssumeRole duration. 3600s (1h) is the default for most roles;
# the role's trust policy MaxSessionDuration is the upper bound.
ASSUME_ROLE_DURATION_SECONDS = 3600

# Module state — set when start_refresh_worker() is called.
_worker_thread: threading.Thread | None = None
_stop_event = threading.Event()


# ============================================================
# Core: refresh ONE credential
# ============================================================

def _log(level: str, message: str) -> None:
    """Tiny structured-ish logger so refresh output is greppable."""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[refresh_worker] {stamp} {level} {message}", flush=True)


def refresh_aws_credential(cred_row: dict) -> tuple[bool, str | None]:
    """Attempt sts:AssumeRole for one credential row, persist the new
    session credentials on success.

    cred_row shape (subset of what db.get_credentials_expiring_soon
    returns):
      {
        "id": 5,
        "user_id": 3,
        "aws_role_arn": "arn:aws:iam::222:role/CloudPathScanRole",
        "aws_external_id": "cloudpath-tenant-3-abc123",
        ...
      }

    Returns (ok, error_message). error_message is suitable for logging,
    not for user display (may contain AWS internal codes).
    """
    role_arn = cred_row.get("aws_role_arn")
    external_id = cred_row.get("aws_external_id")
    user_id = cred_row.get("user_id")
    credential_id = cred_row["id"]

    if not role_arn or not external_id:
        return False, f"credential {credential_id} missing role_arn or external_id"

    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        return False, "server AWS_ACCESS_KEY_ID env var not set"

    try:
        sts = boto3.client("sts")
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"cloudpath-refresh-{user_id}-{credential_id}",
            ExternalId=external_id,
            DurationSeconds=ASSUME_ROLE_DURATION_SECONDS,
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        msg = e.response.get("Error", {}).get("Message", str(e))
        return False, f"AssumeRole {code}: {msg}"
    except NoCredentialsError:
        return False, "server scanner-account credentials are invalid"
    except Exception as e:
        return False, f"unexpected {type(e).__name__}: {e}"

    # Persist the new session credentials.
    creds_block = resp["Credentials"]
    new_credential_dict = {
        "type": "aws-assume-role-session",
        "role_arn": role_arn,
        "access_key_id": creds_block["AccessKeyId"],
        "secret_access_key": creds_block["SecretAccessKey"],
        "session_token": creds_block["SessionToken"],
    }
    expires_at = creds_block["Expiration"]  # datetime with tzinfo

    try:
        # update_credential_refresh is async; bridge via asyncio.run
        asyncio.run(db.update_credential_refresh(
            credential_id=credential_id,
            new_credential_dict=new_credential_dict,
            expires_at=expires_at,
        ))
    except Exception as e:
        return False, f"DB update failed: {type(e).__name__}: {e}"

    return True, None


# ============================================================
# Worker loop
# ============================================================

def _refresh_tick() -> None:
    """One pass over the refresh queue. Called by the worker loop."""
    try:
        expiring = db.get_credentials_expiring_soon_sync(
            within_minutes=REFRESH_WINDOW_MINUTES,
        )
    except Exception as e:
        _log("ERROR", f"could not query expiring credentials: "
                       f"{type(e).__name__}: {e}")
        return

    if not expiring:
        return  # quietly — most ticks find nothing

    _log("INFO", f"{len(expiring)} credential(s) due for refresh")
    for cred in expiring:
        ok, err = refresh_aws_credential(cred)
        if ok:
            _log("INFO",
                 f"refreshed credential id={cred['id']} "
                 f"user_id={cred['user_id']} role_arn={cred['aws_role_arn']}")
        else:
            _log("WARN",
                 f"refresh FAILED for id={cred['id']} "
                 f"user_id={cred['user_id']}: {err}")


def _worker_loop() -> None:
    """The main loop. Wakes every REFRESH_INTERVAL_SECONDS until told
    to stop. Uses an Event.wait() instead of time.sleep so we can be
    woken early for a clean shutdown."""
    _log("INFO", f"started; interval={REFRESH_INTERVAL_SECONDS}s "
                  f"window={REFRESH_WINDOW_MINUTES}min")
    # Run one tick immediately at startup so any credentials saved
    # before the worker began are caught quickly.
    _refresh_tick()
    while not _stop_event.is_set():
        if _stop_event.wait(REFRESH_INTERVAL_SECONDS):
            break  # stop requested
        _refresh_tick()
    _log("INFO", "stopped")


# ============================================================
# Lifecycle
# ============================================================

def start_refresh_worker() -> None:
    """Start the worker thread. Safe to call multiple times; second
    and subsequent calls within the same process are no-ops.

    Honest note about Flask debug mode:
      When app.run(debug=True) is used, Flask's reloader spawns a
      child process. This module gets imported in BOTH the parent
      (supervisor) and the child (actual server), so the worker
      starts twice — once per process. This is harmless because:
        - PostgreSQL's row-level locking serialises concurrent
          UPDATEs in update_credential_refresh
        - Worst case: we make one extra AssumeRole call per cycle,
          which costs nothing
      To run a single worker in development you can either:
        - Set app.run(debug=False) (you lose hot-reload)
        - Or accept the duplication (the per-process logs make it
          obvious what's happening)
      In production (no debug mode), this issue does not occur.
    """
    global _worker_thread
    if _worker_thread is not None and _worker_thread.is_alive():
        _log("INFO", "already running, skipping start")
        return

    _stop_event.clear()
    _worker_thread = threading.Thread(
        target=_worker_loop,
        name="cloudpath-refresh-worker",
        daemon=True,  # dies with Flask
    )
    _worker_thread.start()


def stop_refresh_worker() -> None:
    """Signal the worker to stop. Mostly useful in tests. In
    production the daemon thread dies with the Flask process."""
    _stop_event.set()
    if _worker_thread:
        _worker_thread.join(timeout=5)