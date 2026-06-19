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

Honest engineering caveats:
  - Single user-per-tenant model; team accounts = future work.
  - Encryption key in env var, not in KMS. Documented limitation.
  - Per-request connect is slower than pooling but is the correct
    pattern when bridging async asyncpg with sync Flask. A true
    production deployment would either go all-async (Quart/FastAPI)
    or use psycopg2 with a connection pool.

Usage from Flask:
  import db
  user = db.get_user_by_email_sync("alice@example.com")
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
                   last_login_at, is_active
            FROM users WHERE email = $1
            """,
            email.lower(),
        )
        return dict(row) if row else None
    finally:
        await conn.close()


async def get_user_by_id(user_id: int) -> dict | None:
    """Look up a user by id. Returns the row as a dict, or None."""
    conn = await _connect()
    try:
        row = await conn.fetchrow(
            """
            SELECT id, email, display_name, subscription_tier,
                   neo4j_database_name, aws_external_id, created_at,
                   last_login_at, is_active
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
    """
    conn = await _connect()
    try:
        if cloud:
            rows = await conn.fetch(
                """
                SELECT id, cloud, label, encrypted_blob, aws_role_arn,
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
                SELECT id, cloud, label, encrypted_blob, aws_role_arn,
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
# Sync wrappers for Flask handlers
# ============================================================
#
# Each async function above has a "_sync" counterpart that wraps it in
# asyncio.run(). These are what Flask endpoints actually call.
#
# Why this pattern: asyncio.run() creates a fresh event loop for each
# call. This is not the most efficient option at high concurrency, but
# at FYP scale (one or two users at most) it is simple and correct.
# Avoiding nested-loop bugs is more important than micro-optimisation.

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


# ============================================================
# CLI helper: schema-application smoke test
# ============================================================

if __name__ == "__main__":
    """Run `python db.py` to smoke-test the connection and basic CRUD.

    This is intentionally minimal — it just connects, inserts a test
    user, reads it back, and deletes. If this passes, the foundation
    is sound and you can proceed to Phase 2 (auth layer).
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