"""
CloudPath per-user credential context for scan pipelines.

Phase 5 of the database build: scan pipelines no longer read credentials
from Flask's environment variables. Instead, each scan loads the running
user's saved credentials from PostgreSQL (cloud_credentials table),
decrypts them, optionally refreshes expiring AWS STS tokens inline, and
provides a per-process environment for subprocess.run().

Why a context manager:
  - Temp files for GCP service account JSON are written on enter,
    securely deleted (with overwrite) on exit.
  - The caller never sees raw decrypted secrets in code; everything
    flows through env dicts.
  - Cleanup is guaranteed even if the scan raises.

Usage:
  with scan_credentials_for_user(user_id) as ctx:
      # ctx.env is a dict suitable for subprocess.run(env=...)
      # ctx.aws_present, ctx.gcp_present tell which clouds are usable
      # ctx.gcp_project_id is the project id discovered from the SA JSON
      subprocess.run(cmd, env=ctx.env, ...)
"""
import os
import sys
import json
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import db


# How close to expiry before we trigger an inline refresh on scan start
INLINE_REFRESH_THRESHOLD_MINUTES = 5


@dataclass
class ScanCredentialContext:
    """Bundle returned by the credential context manager."""
    env: dict = field(default_factory=dict)
    aws_present: bool = False
    gcp_present: bool = False
    gcp_project_id: str | None = None
    aws_account_id: str | None = None  # populated if we can derive it
    errors: list[str] = field(default_factory=list)
    # Internal — temp files to clean up on context exit
    _temp_files: list[str] = field(default_factory=list)


def _secure_delete(path: str) -> None:
    """Overwrite file with zeros then unlink. Best-effort on Windows."""
    if not path or not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass  # best effort
    try:
        os.remove(path)
    except OSError:
        pass


def _refresh_aws_credential_if_needed(cred_row: dict) -> dict | None:
    """If the credential's expires_at is within INLINE_REFRESH_THRESHOLD_MINUTES
    of NOW (or NULL), call sts:AssumeRole and update the row. Returns the
    UPDATED credential row dict, or None if refresh failed.
    """
    expires_at = cred_row.get("expires_at")
    cutoff = datetime.now(timezone.utc) + timedelta(
        minutes=INLINE_REFRESH_THRESHOLD_MINUTES
    )

    # Already fresh — no work needed
    if expires_at is not None and expires_at > cutoff:
        return cred_row

    # Otherwise refresh. We import locally to avoid a circular import
    # at module load time (refresh_worker imports db, db is fine,
    # but pulling refresh_worker here keeps the import tree clean).
    from refresh_worker import refresh_aws_credential
    ok, err = refresh_aws_credential(cred_row)
    if not ok:
        cred_row.setdefault("_refresh_error", err)
        return None

    # Re-read the row to get fresh encrypted_blob + new timestamps
    fresh = db.get_cloud_credentials_for_user_sync(
        cred_row["user_id"], cloud="aws",
    )
    for r in fresh:
        if r["id"] == cred_row["id"]:
            return r
    return None


def _load_aws_into_env(env: dict, ctx: ScanCredentialContext, cred_row: dict) -> None:
    """Inject decrypted AWS session credentials into env."""
    cred_dict = cred_row.get("credential") or {}
    access_key = cred_dict.get("access_key_id")
    secret_key = cred_dict.get("secret_access_key")
    session_token = cred_dict.get("session_token")

    if not (access_key and secret_key and session_token):
        ctx.errors.append(
            "AWS credential has no session token. Re-save the credential on "
            "the Connect page to trigger a fresh AssumeRole."
        )
        return

    env["AWS_ACCESS_KEY_ID"] = access_key
    env["AWS_SECRET_ACCESS_KEY"] = secret_key
    env["AWS_SESSION_TOKEN"] = session_token

    # Region is required by some SDKs. Default to the region your test
    # resources actually live in. Honest TODO: store region in the
    # credential row so users can pick their own.
    env.setdefault("AWS_DEFAULT_REGION", "ap-southeast-2")
    env.setdefault("AWS_REGION", "ap-southeast-2")

    ctx.aws_present = True


def _load_gcp_into_env(env: dict, ctx: ScanCredentialContext, cred_row: dict) -> None:
    """Write the GCP service-account JSON to a temp file and point
    GOOGLE_APPLICATION_CREDENTIALS at it.

    The file path is recorded on the context so it gets securely
    deleted when the context exits.
    """
    sa_dict = cred_row.get("credential") or {}
    if not sa_dict.get("private_key"):
        ctx.errors.append(
            "GCP credential is missing the service-account JSON. "
            "Re-save the credential on the Connect page."
        )
        return

    project_id = sa_dict.get("project_id")
    if not project_id:
        ctx.errors.append("GCP credential is missing project_id")
        return

    # Write to a NamedTemporaryFile with delete=False so we control
    # the cleanup ourselves (atomic overwrite + unlink on context exit).
    # Suffix .json so any tool looking at the extension is happy.
    fd, path = tempfile.mkstemp(suffix=".json", prefix="cloudpath-gcp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(sa_dict, f)
    except Exception as e:
        ctx.errors.append(f"failed to write GCP key file: {e}")
        _secure_delete(path)
        return

    env["GOOGLE_APPLICATION_CREDENTIALS"] = path
    # gcp_ingest_full.py and other GCP ingestion scripts expect
    # GCP_PROJECT_ID as env var. Set it here so subprocess picks it up.
    if project_id:
        env["GCP_PROJECT_ID"] = project_id
    ctx._temp_files.append(path)
    ctx.gcp_present = True
    ctx.gcp_project_id = project_id


@contextmanager
def scan_credentials_for_user(user_id: int):
    """Yield a ScanCredentialContext loaded with the user's saved
    credentials. AWS credentials are inline-refreshed if expiring soon.
    Cleanup of temp files happens automatically on context exit.

    The caller checks ctx.aws_present / ctx.gcp_present to see which
    clouds are usable. ctx.errors is a list of human-readable strings
    describing anything that went wrong. An empty ctx with errors
    means no scan should proceed.
    """
    ctx = ScanCredentialContext()
    # Start from the parent process env so subprocesses inherit PATH,
    # PYTHONHOME, NEO4J_PASSWORD, etc.
    ctx.env = os.environ.copy()
    ctx.env["PYTHONIOENCODING"] = "utf-8"
    ctx.env["PYTHONUTF8"] = "1"
    ctx.env["NO_COLOR"] = "1"
    ctx.env["TERM"] = "dumb"
    ctx.env["PYTHONUNBUFFERED"] = "1"
    ctx.env["FORCE_COLOR"] = "0"
    ctx.env["RICH_FORCE_TERMINAL"] = "false"
    ctx.env["COLUMNS"] = "200"
    ctx.env["LINES"] = "50"

    for var in (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_PROFILE", "GOOGLE_APPLICATION_CREDENTIALS",
    ):
        ctx.env.pop(var, None)

    try:
        # ----- AWS -----
        aws_creds = db.get_cloud_credentials_for_user_sync(user_id, cloud="aws")
        if aws_creds:
            # Multiple AWS creds per user is allowed (different labels);
            # for now we use the FIRST. A future enhancement is a
            # "default" flag in the schema.
            primary = aws_creds[0]
            refreshed = _refresh_aws_credential_if_needed(primary)
            if refreshed is None:
                ctx.errors.append(
                    "AWS credential refresh failed: "
                    + primary.get("_refresh_error", "unknown")
                )
            else:
                _load_aws_into_env(ctx.env, ctx, refreshed)

        # ----- GCP -----
        gcp_creds = db.get_cloud_credentials_for_user_sync(user_id, cloud="gcp")
        if gcp_creds:
            primary = gcp_creds[0]
            _load_gcp_into_env(ctx.env, ctx, primary)

        yield ctx
    finally:
        # Guaranteed cleanup of any temp key files we created.
        for path in ctx._temp_files:
            _secure_delete(path)