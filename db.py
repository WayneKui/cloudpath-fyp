"""
CloudPath database module — asyncpg-backed PostgreSQL layer.

Design overview:
  - Uses asyncpg for actual queries (async-native PostgreSQL driver).
  - Flask itself remains synchronous; every async function has a sync
    wrapper that calls it via asyncio.run().
  - IMPORTANT: each sync wrapper creates and tears down its own
    short-lived asyncpg connection. We do NOT keep a global pool
    across asyncio.run() calls because asyncpg pools are bound to
    the event loop that created them; reusing them across loops
    raises "another operation is in progress" / "Event loop is closed"
    errors. For FYP-scale traffic (one or two concurrent users) the
    per-request connect overhead (~5-10ms) is negligible.

  - Encryption: cryptography.Fernet with the key in
    CLOUDPATH_ENCRYPTION_KEY env var.
  - Passwords: bcrypt-hashed via the bcrypt package.
"""
import os
import json
import asyncio
import asyncpg
import bcrypt
from cryptography.fernet import Fernet
from datetime import datetime, timedelta, timezone


# ============================================================
# Configuration
# ============================================================

DB_DSN = os.environ.get(
    "CLOUDPATH_DB_DSN",
    "postgresql://cloudpath:cloudpath@localhost:5432/cloudpath",
)

# Fernet symmetric encryption key. Generate once with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Store the result in the CLOUDPATH_ENCRYPTION_KEY env var.
_ENC_KEY = os.environ.get("CLOUDPATH_ENCRYPTION_KEY", "")
if _ENC_KEY:
    _fernet = Fernet(_ENC_KEY.encode())
else:
    _fernet = None  # set lazily; functions that need it will raise if absent


# ============================================================
# Connection helper
# ============================================================

async def _connect():
    """Open a single short-lived connection for one operation.

    We deliberately don't use a global pool — see module docstring
    for why. For the FYP workload (a handful of requests per second
    at most) per-call connections are simpler and correct.
    """
    return await asyncpg.connect(dsn=DB_DSN, command_timeout=10)


# ============================================================
# Encryption helpers
# ============================================================

def _require_fernet() -> Fernet:
    """Return the Fernet instance, raising a clear error if the key is
    not configured. Better than a cryptic crash deeper in the call."""
    if _fernet is None:
        raise RuntimeError(
            "CLOUDPATH_ENCRYPTION_KEY env var is not set. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
    return _fernet


def encrypt_credential(plaintext_dict: dict) -> bytes:
    """Serialise a credential dict to JSON, encrypt, and return bytes
    suitable for storage in a BYTEA column."""
    fernet = _require_fernet()
    plaintext_bytes = json.dumps(plaintext_dict).encode("utf-8")
    return fernet.encrypt(plaintext_bytes)


def decrypt_credential(encrypted_bytes: bytes) -> dict:
    """Inverse of encrypt_credential. Returns the original dict."""
    fernet = _require_fernet()
    plaintext_bytes = fernet.decrypt(bytes(encrypted_bytes))
    return json.loads(plaintext_bytes.decode("utf-8"))


# ============================================================
# Password hashing
# ============================================================

def hash_password(plaintext: str) -> str:
    """bcrypt-hash a password. Returns the hash as a UTF-8 string ready
    for storage in users.password_hash."""
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """Constant-time password verification. Returns True if the password
    matches, False otherwise. Always returns a bool — never raises."""
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ============================================================
# User operations (async)
# ============================================================

async def create_user(
    email: str,
    password: str,
    display_name: str = None,
    aws_external_id: str = None,
) -> dict:
    """Insert a new user, hashing the password and generating a tenant-
    scoped Neo4j database name. The caller MUST supply aws_external_id
    (generated via generate_external_id() in auth.py at signup time);
    we pass it through rather than generating it here so the same value
    is available to the auth layer for redirect/welcome messaging.

    Raises asyncpg.UniqueViolationError if email already exists.
    """
    if not aws_external_id:
        raise ValueError("aws_external_id is required (generate in auth.py)")
    password_hash = hash_password(password)
    conn = await _connect()
    try:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                INSERT INTO users (email, password_hash, display_name,
                                   neo4j_database_name, aws_external_id)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id, email, display_name, subscription_tier,
                          neo4j_database_name, aws_external_id, created_at
                """,
                email.lower(), password_hash, display_name,
                "tenant_placeholder", aws_external_id,
            )
            real_db_name = f"tenant_{row['id']}"
            await conn.execute(
                "UPDATE users SET neo4j_database_name = $1 WHERE id = $2",
                real_db_name, row["id"],
            )
            return {**dict(row), "neo4j_database_name": real_db_name}
    finally:
        await conn.close()


async def get_user_by_email(email: str) -> dict | None:
    """Look up a user by email. Returns the row as a dict, or None."""
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            SELECT id, email, password_hash, display_name, subscription_tier,
                   neo4j_database_name, aws_external_id, created_at,
                   last_login_at, is_active,
                   lemonsqueezy_customer_id, lemonsqueezy_subscription_id,
                   tier_updated_at
            FROM users WHERE email = $1
            """,
            email.lower(),
        )
        return dict(row) if row else None
    finally:
        await conn.close()


async def get_user_by_id(user_id: int) -> dict | None:
    """Look up a user by id. Returns the row as a dict, or None.

    Phase Stripe/LemonSqueezy: also returns billing-related columns
    (lemonsqueezy_customer_id, lemonsqueezy_subscription_id, tier_updated_at)
    so the billing endpoints and templates have everything they need.
    """
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            SELECT id, email, display_name, subscription_tier,
                   neo4j_database_name, aws_external_id, created_at,
                   last_login_at, is_active,
                   lemonsqueezy_customer_id, lemonsqueezy_subscription_id,
                   tier_updated_at
            FROM users WHERE id = $1
            """,
            user_id,
        )
        return dict(row) if row else None
    finally:
        await conn.close()


async def update_last_login(user_id: int) -> None:
    """Stamp last_login_at = NOW() on login. Best-effort; failures are
    not surfaced to the caller (login should not fail because of a stat)."""
    conn = await _connect()
    try:
        await conn.execute(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1",
            user_id,
        )
    finally:
        await conn.close()


# ============================================================
# Cloud credential operations (async)
# ============================================================

async def upsert_cloud_credential(
    user_id: int,
    cloud: str,
    label: str,
    credential_dict: dict,
    aws_role_arn: str = None,
    aws_external_id: str = None,
    expires_at: datetime = None,
) -> int:
    """Insert or update a credential. Encrypts credential_dict before
    storing. Returns the credential row id.

    'credential_dict' shape depends on cloud:
      aws (static):    {"access_key_id": "...", "secret_access_key": "...",
                        "session_token": "..."}
      aws (assume):    {"source_access_key_id": "...", "source_secret_access_key": "..."}
                       Together with aws_role_arn and aws_external_id args.
      gcp:             {"service_account_json": "<full JSON content>"}
    """
    encrypted = encrypt_credential(credential_dict)
    conn = await _connect()
    try:
        # If expires_at is provided, the caller just performed a real
        # cloud-side authentication (e.g., eager AssumeRole in the
        # save-credential endpoint). In that case, stamp
        # last_refreshed_at = NOW() so downstream code (UI, refresh
        # worker) treats this row as just-refreshed rather than
        # "saved but stale". If expires_at is None (e.g., GCP keys
        # which don't expire) leave last_refreshed_at NULL.
        last_refreshed = "NOW()" if expires_at is not None else "NULL"
        row = await conn.fetchrow(
            f"""
            INSERT INTO cloud_credentials (
                user_id, cloud, label, encrypted_blob,
                aws_role_arn, aws_external_id, expires_at,
                last_refreshed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, {last_refreshed})
            ON CONFLICT (user_id, cloud, label) DO UPDATE SET
                encrypted_blob    = EXCLUDED.encrypted_blob,
                aws_role_arn      = EXCLUDED.aws_role_arn,
                aws_external_id   = EXCLUDED.aws_external_id,
                expires_at        = EXCLUDED.expires_at,
                last_refreshed_at = EXCLUDED.last_refreshed_at
            RETURNING id
            """,
            user_id, cloud, label, encrypted,
            aws_role_arn, aws_external_id, expires_at,
        )
        return row["id"]
    finally:
        await conn.close()


async def get_cloud_credentials_for_user(user_id: int, cloud: str = None) -> list[dict]:
    """List all credentials for a user, optionally filtered by cloud.
    The encrypted blob is DECRYPTED and returned as 'credential' key.

    Returns rows that include `user_id` so downstream code (e.g. the
    refresh logic in scan_credentials.py) doesn't need to know it out of
    band. Otherwise `cred_row["user_id"]` raises KeyError.
    """
    conn = await _connect()
    try:
        if cloud:
            rows = await conn.fetch(
                """
                SELECT id, user_id, cloud, label, encrypted_blob, aws_role_arn,
                       aws_external_id, last_refreshed_at, expires_at, created_at
                FROM cloud_credentials
                WHERE user_id = $1 AND cloud = $2
                ORDER BY created_at
                """,
                user_id, cloud,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT id, user_id, cloud, label, encrypted_blob, aws_role_arn,
                       aws_external_id, last_refreshed_at, expires_at, created_at
                FROM cloud_credentials
                WHERE user_id = $1
                ORDER BY cloud, created_at
                """,
                user_id,
            )
    finally:
        await conn.close()
    out = []
    for r in rows:
        d = dict(r)
        d["credential"] = decrypt_credential(d.pop("encrypted_blob"))
        out.append(d)
    return out


async def update_credential_refresh(
    credential_id: int,
    new_credential_dict: dict,
    expires_at: datetime,
) -> None:
    """Used by the STS auto-refresh worker to update an existing AWS
    credential row with freshly-assumed temporary credentials."""
    encrypted = encrypt_credential(new_credential_dict)
    conn = await _connect()
    try:
        await conn.execute(
            """
            UPDATE cloud_credentials
               SET encrypted_blob    = $1,
                   expires_at        = $2,
                   last_refreshed_at = NOW()
             WHERE id = $3
            """,
            encrypted, expires_at, credential_id,
        )
    finally:
        await conn.close()


async def get_credentials_expiring_soon(within_minutes: int = 10) -> list[dict]:
    """Return AWS credentials with an aws_role_arn that expire within the
    given window. Used by the auto-refresh worker."""
    cutoff = datetime.now(timezone.utc) + timedelta(minutes=within_minutes)
    conn = await _connect()
    try:
        rows = await conn.fetch(
            """
            SELECT id, user_id, cloud, label, encrypted_blob,
                   aws_role_arn, aws_external_id, expires_at
            FROM cloud_credentials
            WHERE cloud = 'aws'
              AND aws_role_arn IS NOT NULL
              AND expires_at IS NOT NULL
              AND expires_at <= $1
            """,
            cutoff,
        )
    finally:
        await conn.close()
    return [
        {**dict(r), "credential": decrypt_credential(r["encrypted_blob"])}
        for r in rows
    ]


async def delete_cloud_credential(user_id: int, credential_id: int) -> bool:
    """Delete a credential, scoped to the given user. The user_id
    filter is critical: it ensures one user can never delete another
    user's credential by guessing the id. Returns True if a row was
    deleted, False if nothing matched."""
    conn = await _connect()
    try:
        result = await conn.execute(
            "DELETE FROM cloud_credentials WHERE id = $1 AND user_id = $2",
            credential_id, user_id,
        )
        # asyncpg returns "DELETE n" where n is the rowcount as a string
        return result.endswith(" 1")
    finally:
        await conn.close()


# ============================================================
# Subscription billing (LemonSqueezy)
# ============================================================
async def get_user_by_subscription_id(subscription_id: str) -> dict | None:
    """Look up a user by their LemonSqueezy subscription ID.

    Used by the webhook handler when an event arrives that doesn't have
    custom_data (e.g. subscription_updated, subscription_cancelled).
    """
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            "SELECT id, email, subscription_tier FROM users "
            "WHERE lemonsqueezy_subscription_id = $1",
            subscription_id,
        )
        return dict(row) if row else None
    finally:
        await conn.close()


async def get_user_by_customer_id(customer_id: str) -> dict | None:
    """Look up a user by their LemonSqueezy customer ID.

    Useful when subscription_id has changed (e.g. user cancelled then
    resubscribed) but customer_id is stable.
    """
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            "SELECT id, email, subscription_tier FROM users "
            "WHERE lemonsqueezy_customer_id = $1",
            customer_id,
        )
        return dict(row) if row else None
    finally:
        await conn.close()


async def update_user_subscription(
    user_id: int,
    tier: str,
    customer_id: str | None,
    subscription_id: str | None,
) -> None:
    """Update a user's subscription state after a webhook event.

    `tier_updated_at` is bumped to NOW() so the dashboard can show how
    long the user has been on the current tier.

    Design choice: we always write `customer_id` if provided,
    even if the user already had one. If LemonSqueezy gave us a
    different ID it's because something changed on their end and we
    should track the new one.
    """
    if tier not in ("free", "plus", "max"):
        raise ValueError(f"Invalid tier {tier!r}")
    conn = await _connect()
    try:
        await conn.execute(
            """
            UPDATE users
            SET subscription_tier            = $1,
                lemonsqueezy_customer_id     = COALESCE($2, lemonsqueezy_customer_id),
                lemonsqueezy_subscription_id = $3,
                tier_updated_at              = NOW()
            WHERE id = $4
            """,
            tier, customer_id, subscription_id, user_id,
        )
    finally:
        await conn.close()


# ============================================================
# Scheduled scans (Plus tier feature)
# ============================================================
# All scheduled-scan times are conceptually MYT (UTC+8). They are
# stored in the database as timestamps with timezone (TIMESTAMPTZ for
# next_run_at/last_run_at) or as a naive TIME for time_of_day. The
# scheduler converts between MYT and UTC as needed.


def _calculate_next_run(frequency, day_of_week, time_of_day, from_time=None):
    """Pure function: compute next run timestamp (UTC).

    frequency:   'daily' | 'weekly'
    day_of_week: 0=Monday..6=Sunday (only used for weekly)
    time_of_day: datetime.time, interpreted as MYT
    from_time:   tz-aware datetime, default now

    Returns tz-aware datetime in UTC.
    """
    from datetime import datetime, timedelta, timezone
    MYT = timezone(timedelta(hours=8))

    if from_time is None:
        from_time = datetime.now(timezone.utc)
    now_myt = from_time.astimezone(MYT)
    today_run_myt = now_myt.replace(
        hour=time_of_day.hour, minute=time_of_day.minute,
        second=0, microsecond=0,
    )
    if frequency == "daily":
        if today_run_myt > now_myt:
            next_myt = today_run_myt
        else:
            next_myt = today_run_myt + timedelta(days=1)
    elif frequency == "weekly":
        current_dow = now_myt.weekday()
        days_ahead = (day_of_week - current_dow) % 7
        if days_ahead == 0 and today_run_myt <= now_myt:
            days_ahead = 7
        next_myt = today_run_myt + timedelta(days=days_ahead)
    else:
        raise ValueError(f"Unknown frequency {frequency!r}")
    return next_myt.astimezone(timezone.utc)


async def get_user_schedule(user_id: int) -> dict | None:
    """Return the user's scan_schedules row as a dict, or None."""
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            "SELECT * FROM scan_schedules WHERE user_id = $1",
            user_id,
        )
        return dict(row) if row else None
    finally:
        await conn.close()


async def upsert_user_schedule(
    user_id: int,
    frequency: str,
    day_of_week,
    time_of_day,
) -> int:
    """Create or update a user's scan schedule.

    Args:
        frequency:   'daily' or 'weekly'
        day_of_week: 0-6 (Monday=0) for weekly, None for daily
        time_of_day: datetime.time object

    Returns the schedule id.
    Recomputes next_run_at automatically.
    """
    if frequency not in ("daily", "weekly"):
        raise ValueError(f"Invalid frequency {frequency!r}")
    if frequency == "weekly" and day_of_week is None:
        raise ValueError("weekly schedule requires day_of_week")
    if frequency == "daily":
        day_of_week = None

    next_run = _calculate_next_run(frequency, day_of_week, time_of_day)
    conn = await _connect()
    try:
        # ON CONFLICT (user_id) ensures one schedule per user.
        row = await conn.fetchrow(
            """
            INSERT INTO scan_schedules
                (user_id, schedule_frequency, day_of_week, time_of_day,
                 is_paused, next_run_at, updated_at)
            VALUES ($1, $2, $3, $4, FALSE, $5, NOW())
            ON CONFLICT (user_id) DO UPDATE
              SET schedule_frequency = EXCLUDED.schedule_frequency,
                  day_of_week        = EXCLUDED.day_of_week,
                  time_of_day        = EXCLUDED.time_of_day,
                  is_paused          = FALSE,
                  next_run_at        = EXCLUDED.next_run_at,
                  updated_at         = NOW()
            RETURNING id
            """,
            user_id, frequency, day_of_week, time_of_day, next_run,
        )
        return row["id"]
    finally:
        await conn.close()


async def pause_user_schedule(user_id: int, paused: bool) -> bool:
    """Pause or resume a user's schedule. Returns True if a schedule existed."""
    conn = await _connect()
    try:
        result = await conn.execute(
            "UPDATE scan_schedules "
            "SET is_paused = $1, updated_at = NOW() "
            "WHERE user_id = $2",
            paused, user_id,
        )
        # asyncpg returns "UPDATE n" string; check it changed something
        return result.endswith(" 1")
    finally:
        await conn.close()


async def delete_user_schedule(user_id: int) -> bool:
    """Delete a user's schedule entirely. Returns True if one existed."""
    conn = await _connect()
    try:
        result = await conn.execute(
            "DELETE FROM scan_schedules WHERE user_id = $1",
            user_id,
        )
        return result.endswith(" 1")
    finally:
        await conn.close()


async def get_due_schedules() -> list[dict]:
    """Return all schedules where next_run_at has passed and not paused.

    Used by the scheduler thread on each wake-up to find work to do.
    """
    conn = await _connect()
    try:
        rows = await conn.fetch(
            """
            SELECT *
            FROM scan_schedules
            WHERE is_paused = FALSE
              AND next_run_at IS NOT NULL
              AND next_run_at <= NOW()
            ORDER BY next_run_at ASC
            """
        )
        return [dict(r) for r in rows]
    finally:
        await conn.close()


async def mark_schedule_ran(schedule_id: int, frequency: str,
                             day_of_week, time_of_day) -> None:
    """Update last_run_at = NOW() and recompute next_run_at."""
    next_run = _calculate_next_run(frequency, day_of_week, time_of_day)
    conn = await _connect()
    try:
        await conn.execute(
            """
            UPDATE scan_schedules
            SET last_run_at = NOW(),
                next_run_at = $1,
                updated_at  = NOW()
            WHERE id = $2
            """,
            next_run, schedule_id,
        )
    finally:
        await conn.close()


# ============================================================
# Scan history (audit trail for manual + scheduled runs)
# ============================================================
async def record_scan_started(user_id: int, triggered_by: str) -> int:
    """Insert a 'running' scan_history row. Returns id for later update."""
    if triggered_by not in ("manual", "scheduled"):
        raise ValueError(f"Invalid triggered_by {triggered_by!r}")
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            INSERT INTO scan_history (user_id, triggered_by, status)
            VALUES ($1, $2, 'running')
            RETURNING id
            """,
            user_id, triggered_by,
        )
        return row["id"]
    finally:
        await conn.close()


async def record_scan_completed(history_id: int, status: str,
                                 error_message=None, summary=None) -> None:
    """Update a scan_history row when the scan finishes.

    summary: dict with keys paths_found, critical_paths, high_paths,
             medium_paths, low_paths, detections_count (any may be None)
    """
    if status not in ("success", "failure"):
        raise ValueError(f"Invalid status {status!r}")
    s = summary or {}
    conn = await _connect()
    try:
        await conn.execute(
            """
            UPDATE scan_history
            SET completed_at      = NOW(),
                status            = $1,
                error_message     = $2,
                paths_found       = $3,
                critical_paths    = $4,
                high_paths        = $5,
                medium_paths      = $6,
                low_paths         = $7,
                detections_count  = $8
            WHERE id = $9
            """,
            status, error_message,
            s.get("paths_found"), s.get("critical_paths"),
            s.get("high_paths"), s.get("medium_paths"),
            s.get("low_paths"), s.get("detections_count"),
            history_id,
        )
    finally:
        await conn.close()


async def get_user_scan_history(user_id: int, limit: int = 50) -> list[dict]:
    """Return recent scan history rows for a user, newest first."""
    conn = await _connect()
    try:
        rows = await conn.fetch(
            """
            SELECT *
            FROM scan_history
            WHERE user_id = $1
            ORDER BY started_at DESC
            LIMIT $2
            """,
            user_id, limit,
        )
        return [dict(r) for r in rows]
    finally:
        await conn.close()


# ============================================================
# Sync wrappers for Flask handlers
# ============================================================
#
# Each async function above has a "_sync" counterpart that wraps it in
# asyncio.run(). These are what Flask endpoints actually call.
#
# Why this pattern: asyncio.run() creates a fresh event loop for each
# call.

def create_user_sync(email, password, display_name=None, aws_external_id=None):
    return asyncio.run(create_user(email, password, display_name, aws_external_id))


def get_user_by_email_sync(email):
    return asyncio.run(get_user_by_email(email))


def get_user_by_id_sync(user_id):
    return asyncio.run(get_user_by_id(user_id))


def update_last_login_sync(user_id):
    return asyncio.run(update_last_login(user_id))


def upsert_cloud_credential_sync(user_id, cloud, label, credential_dict,
                                  aws_role_arn=None, aws_external_id=None,
                                  expires_at=None):
    return asyncio.run(upsert_cloud_credential(
        user_id, cloud, label, credential_dict,
        aws_role_arn, aws_external_id, expires_at,
    ))


def get_cloud_credentials_for_user_sync(user_id, cloud=None):
    return asyncio.run(get_cloud_credentials_for_user(user_id, cloud))


def get_credentials_expiring_soon_sync(within_minutes=10):
    return asyncio.run(get_credentials_expiring_soon(within_minutes))


def delete_cloud_credential_sync(user_id, credential_id):
    return asyncio.run(delete_cloud_credential(user_id, credential_id))


# ---- Billing (LemonSqueezy) sync wrappers ----
def get_user_by_subscription_id_sync(subscription_id):
    return asyncio.run(get_user_by_subscription_id(subscription_id))


def get_user_by_customer_id_sync(customer_id):
    return asyncio.run(get_user_by_customer_id(customer_id))


def update_user_subscription_sync(user_id, tier, customer_id, subscription_id):
    return asyncio.run(update_user_subscription(
        user_id, tier, customer_id, subscription_id,
    ))


# ---- Scheduled scans + scan history sync wrappers ----
def get_user_schedule_sync(user_id):
    return asyncio.run(get_user_schedule(user_id))


def upsert_user_schedule_sync(user_id, frequency, day_of_week, time_of_day):
    return asyncio.run(upsert_user_schedule(
        user_id, frequency, day_of_week, time_of_day,
    ))


def pause_user_schedule_sync(user_id, paused):
    return asyncio.run(pause_user_schedule(user_id, paused))


def delete_user_schedule_sync(user_id):
    return asyncio.run(delete_user_schedule(user_id))


def get_due_schedules_sync():
    return asyncio.run(get_due_schedules())


def mark_schedule_ran_sync(schedule_id, frequency, day_of_week, time_of_day):
    return asyncio.run(mark_schedule_ran(
        schedule_id, frequency, day_of_week, time_of_day,
    ))


def record_scan_started_sync(user_id, triggered_by):
    return asyncio.run(record_scan_started(user_id, triggered_by))


def record_scan_completed_sync(history_id, status,
                                error_message=None, summary=None):
    return asyncio.run(record_scan_completed(
        history_id, status, error_message, summary,
    ))


def get_user_scan_history_sync(user_id, limit=50):
    return asyncio.run(get_user_scan_history(user_id, limit))


# ============================================================
# API keys (Max tier)
# ============================================================
# On create we generate a plaintext key with a `cpk_` prefix, return
# it once to the caller, then store only:
#   - SHA-256 hex hash for lookup at auth time
#   - the first 12 chars (the visible prefix, e.g. "cpk_a1b2c3d4")
# for display in the UI. The plaintext key is never persisted.

import hashlib
import secrets


def _hash_api_key(raw_key: str) -> str:
    """Return SHA-256 hex of the raw key. Constant-time comparable
    against `key_hash` column at auth time."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _generate_api_key() -> str:
    """Return a fresh random API key of the form `cpk_<32 hex chars>`.
    secrets.token_hex is cryptographically secure and URL-safe."""
    return "cpk_" + secrets.token_hex(16)


async def create_api_key(user_id: int, name: str) -> dict:
    """Create a new API key for the user. Returns dict with the
    plaintext `key` (shown once to the caller), plus the metadata
    saved to the DB (id, prefix, created_at)."""
    raw_key = _generate_api_key()
    key_hash = _hash_api_key(raw_key)
    key_prefix = raw_key[:12]  # "cpk_a1b2c3d4"
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            INSERT INTO api_keys (user_id, name, key_hash, key_prefix)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, key_prefix, created_at
            """,
            user_id, name.strip()[:100], key_hash, key_prefix,
        )
        return {
            "id":         row["id"],
            "name":       row["name"],
            "key":        raw_key,   # ONLY time we ever return this
            "key_prefix": row["key_prefix"],
            "created_at": row["created_at"],
        }
    finally:
        await conn.close()


async def list_api_keys(user_id: int) -> list[dict]:
    """Return all keys (active + revoked) for the user, newest first.
    Never includes the raw key or full hash."""
    conn = await _connect()
    try:
        rows = await conn.fetch(
            """
            SELECT id, name, key_prefix, created_at, last_used_at, revoked_at
            FROM api_keys
            WHERE user_id = $1
            ORDER BY created_at DESC
            """,
            user_id,
        )
        return [dict(r) for r in rows]
    finally:
        await conn.close()


async def revoke_api_key(user_id: int, key_id: int) -> bool:
    """Mark a key as revoked. Returns True if the key existed and
    belonged to the caller (soft-delete)."""
    conn = await _connect()
    try:
        result = await conn.execute(
            """
            UPDATE api_keys
            SET revoked_at = NOW()
            WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
            """,
            key_id, user_id,
        )
        # asyncpg returns "UPDATE N"; treat non-zero as success
        return result.endswith("1")
    finally:
        await conn.close()


async def lookup_api_key(raw_key: str) -> dict | None:
    """Auth-time lookup. Returns the owning user's row + key metadata
    if the key is valid (exists, not revoked). Also updates last_used_at
    as a side effect so keys show recent activity in the UI.

    Returns None if the key doesn't exist or is revoked. Constant-ish
    time — we always hash then do a single indexed lookup.
    """
    if not raw_key or not raw_key.startswith("cpk_"):
        return None
    key_hash = _hash_api_key(raw_key)
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            SELECT k.id AS key_id, k.name AS key_name, k.user_id,
                   u.email, u.subscription_tier
            FROM api_keys k
            JOIN users u ON u.id = k.user_id
            WHERE k.key_hash = $1 AND k.revoked_at IS NULL
            """,
            key_hash,
        )
        if row is None:
            return None
        # Bump last_used_at (best-effort — don't block auth on failure)
        try:
            await conn.execute(
                "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1",
                row["key_id"],
            )
        except Exception:
            pass
        return dict(row)
    finally:
        await conn.close()


def create_api_key_sync(user_id, name):
    return asyncio.run(create_api_key(user_id, name))


def list_api_keys_sync(user_id):
    return asyncio.run(list_api_keys(user_id))


def revoke_api_key_sync(user_id, key_id):
    return asyncio.run(revoke_api_key(user_id, key_id))


def lookup_api_key_sync(raw_key):
    return asyncio.run(lookup_api_key(raw_key))


# ============================================================
# Webhooks (Max tier)
# ============================================================

async def create_webhook(user_id: int, url: str, events: list[str],
                          secret: str | None = None) -> dict:
    """Register a new webhook. If secret is None we generate one; it's
    returned to the caller so they can set it in their receiving app."""
    if secret is None:
        secret = "whsec_" + secrets.token_urlsafe(24)
    if not events:
        events = ["scan.completed"]
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            INSERT INTO webhooks (user_id, url, secret, events, active)
            VALUES ($1, $2, $3, $4, TRUE)
            RETURNING id, url, events, secret, active, created_at
            """,
            user_id, url.strip()[:1000], secret, events,
        )
        return dict(row)
    finally:
        await conn.close()


async def list_webhooks(user_id: int) -> list[dict]:
    """All webhooks for a user, newest first. Includes secret so the
    UI can show/copy it. If you don't want to expose it in the UI,
    strip it at the endpoint layer."""
    conn = await _connect()
    try:
        rows = await conn.fetch(
            """
            SELECT id, url, events, active, secret,
                   created_at, last_success_at, last_failure_at,
                   last_error, failure_count
            FROM webhooks
            WHERE user_id = $1
            ORDER BY created_at DESC
            """,
            user_id,
        )
        return [dict(r) for r in rows]
    finally:
        await conn.close()


async def get_active_webhooks_for_user(user_id: int, event: str) -> list[dict]:
    """Return active webhooks that subscribe to `event` for a given
    user. Used by the delivery module at fire time."""
    conn = await _connect()
    try:
        rows = await conn.fetch(
            """
            SELECT id, url, secret, events
            FROM webhooks
            WHERE user_id = $1 AND active = TRUE AND $2 = ANY(events)
            """,
            user_id, event,
        )
        return [dict(r) for r in rows]
    finally:
        await conn.close()


async def delete_webhook(user_id: int, webhook_id: int) -> bool:
    """Delete a webhook. Returns True if the row existed and belonged
    to the user."""
    conn = await _connect()
    try:
        result = await conn.execute(
            "DELETE FROM webhooks WHERE id = $1 AND user_id = $2",
            webhook_id, user_id,
        )
        return result.endswith("1")
    finally:
        await conn.close()


async def record_webhook_delivery(webhook_id: int, success: bool,
                                   error: str | None = None) -> None:
    """Update delivery outcome stats. Called by webhook_sender after
    each POST attempt. failure_count is reset on success."""
    conn = await _connect()
    try:
        if success:
            await conn.execute(
                """
                UPDATE webhooks
                SET last_success_at = NOW(),
                    failure_count = 0,
                    last_error = NULL
                WHERE id = $1
                """,
                webhook_id,
            )
        else:
            await conn.execute(
                """
                UPDATE webhooks
                SET last_failure_at = NOW(),
                    failure_count = failure_count + 1,
                    last_error = $2
                WHERE id = $1
                """,
                webhook_id, (error or "")[:500],
            )
    finally:
        await conn.close()


def create_webhook_sync(user_id, url, events, secret=None):
    return asyncio.run(create_webhook(user_id, url, events, secret))


def list_webhooks_sync(user_id):
    return asyncio.run(list_webhooks(user_id))


def get_active_webhooks_for_user_sync(user_id, event):
    return asyncio.run(get_active_webhooks_for_user(user_id, event))


def delete_webhook_sync(user_id, webhook_id):
    return asyncio.run(delete_webhook(user_id, webhook_id))


def record_webhook_delivery_sync(webhook_id, success, error=None):
    return asyncio.run(record_webhook_delivery(webhook_id, success, error))


# ============================================================
# Custom detection rules (per-tenant Rule Manager)
# ============================================================
# Every query here is scoped by user_id — a user can only ever read,
# update, or delete their OWN rows. There is no "admin" path that
# skips this filter, so ownership is enforced at the SQL level, not
# just in the Flask route.

async def create_custom_rule(user_id: int, rule_key: str, mitre_name: str,
                              tactic: str, severity: str, cloud: str,
                              description: str, cypher: str) -> dict:
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            INSERT INTO custom_rules
                (user_id, rule_key, mitre_name, tactic, severity, cloud, description, cypher)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, user_id, rule_key, mitre_name, tactic, severity,
                      cloud, description, cypher, created_at, updated_at
            """,
            user_id, rule_key, mitre_name, tactic, severity, cloud,
            description, cypher,
        )
        return dict(row)
    finally:
        await conn.close()


async def list_custom_rules(user_id: int) -> list[dict]:
    conn = await _connect()
    try:
        rows = await conn.fetch(
            """
            SELECT id, user_id, rule_key, mitre_name, tactic, severity,
                   cloud, description, cypher, created_at, updated_at
            FROM custom_rules
            WHERE user_id = $1
            ORDER BY created_at ASC
            """,
            user_id,
        )
        return [dict(r) for r in rows]
    finally:
        await conn.close()


async def update_custom_rule(user_id: int, rule_id: int, rule_key: str,
                              mitre_name: str, tactic: str, severity: str,
                              cloud: str, description: str,
                              cypher: str) -> dict | None:
    """Update a rule. Returns the updated row, or None if no row matched
    (either the id doesn't exist or it belongs to a different user —
    both cases look identical to the caller, which is the point)."""
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            UPDATE custom_rules
            SET rule_key = $3, mitre_name = $4, tactic = $5, severity = $6,
                cloud = $7, description = $8, cypher = $9, updated_at = NOW()
            WHERE id = $1 AND user_id = $2
            RETURNING id, user_id, rule_key, mitre_name, tactic, severity,
                      cloud, description, cypher, created_at, updated_at
            """,
            rule_id, user_id, rule_key, mitre_name, tactic, severity,
            cloud, description, cypher,
        )
        return dict(row) if row else None
    finally:
        await conn.close()


async def delete_custom_rule(user_id: int, rule_id: int) -> bool:
    conn = await _connect()
    try:
        result = await conn.execute(
            "DELETE FROM custom_rules WHERE id = $1 AND user_id = $2",
            rule_id, user_id,
        )
        return result.endswith("1")
    finally:
        await conn.close()


def create_custom_rule_sync(user_id, rule_key, mitre_name, tactic, severity, cloud, description, cypher):
    return asyncio.run(create_custom_rule(user_id, rule_key, mitre_name, tactic, severity, cloud, description, cypher))


def list_custom_rules_sync(user_id):
    return asyncio.run(list_custom_rules(user_id))


def update_custom_rule_sync(user_id, rule_id, rule_key, mitre_name, tactic, severity, cloud, description, cypher):
    return asyncio.run(update_custom_rule(user_id, rule_id, rule_key, mitre_name, tactic, severity, cloud, description, cypher))


def delete_custom_rule_sync(user_id, rule_id):
    return asyncio.run(delete_custom_rule(user_id, rule_id))


# ============================================================
# CLI helper: schema-application smoke test
# ============================================================

if __name__ == "__main__":
    """Run `python db.py` to smoke-test the connection and basic CRUD.
    """
    import sys

    async def _smoke():
        # Direct connection for the connectivity check
        conn = await _connect()
        try:
            version = await conn.fetchval("SELECT version()")
            print(f"Connected to PostgreSQL: {version[:60]}...")
            table_count = await conn.fetchval(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema = 'public'"
            )
            print(f"Tables in public schema: {table_count}")
        finally:
            await conn.close()

        try:
            user = await create_user(
                email="smoketest@example.com",
                password="smoketest123",
                display_name="Smoke Test",
            )
            print(f"Created test user: id={user['id']}, "
                  f"neo4j_db={user['neo4j_database_name']}")
            looked_up = await get_user_by_email("smoketest@example.com")
            print(f"Looked up by email: id={looked_up['id']}")
            assert verify_password("smoketest123", looked_up["password_hash"])
            print("Password verification: OK")
        except asyncpg.UniqueViolationError:
            print("Test user already exists; that's fine.")

        # Clean up the test user
        conn = await _connect()
        try:
            deleted = await conn.execute(
                "DELETE FROM users WHERE email = 'smoketest@example.com'"
            )
            print(f"Cleanup: {deleted}")
        finally:
            await conn.close()

    if not _ENC_KEY:
        print("WARNING: CLOUDPATH_ENCRYPTION_KEY is not set; "
              "credential encryption smoke test will be skipped")
    asyncio.run(_smoke())
    print("\nSmoke test passed.")