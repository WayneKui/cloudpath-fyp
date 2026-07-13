"""
CloudPath credentials module.

Owns the API endpoints for managing per-user cloud credentials:
  POST   /api/credentials/aws       Save (or update) an AWS assume-role
                                    config for the current user.
  POST   /api/credentials/gcp       Save (or update) a GCP service
                                    account JSON for the current user.
  GET    /api/credentials           List the current user's saved
                                    credentials (decrypted shape;
                                    sensitive fields redacted).
  DELETE /api/credentials/<id>      Delete one credential (must be
                                    owned by the current user).
  POST   /api/test-connection/aws   Attempt sts:AssumeRole + GetCallerIdentity
                                    using the saved AWS credential.
  POST   /api/test-connection/gcp   Attempt a lightweight GCP call
                                    using the saved GCP credential.

Design notes:
  - All endpoints are JSON-in, JSON-out, and require an authenticated
    session. flask-login's @login_required gate redirects unauthed
    requests; for JSON, the auth.py unauthorized_handler returns 401.
  - All endpoints scope by current_user.id. The DB layer also scopes
    by user_id in every WHERE clause, defense in depth.
  - AWS credentials are stored as an assume-role descriptor, NOT as
    long-lived access keys. The user supplies role_arn; we use OUR
    scanner-account credentials (env vars) to call sts:AssumeRole
    against their role with their external_id. The resulting short-
    lived token is stored encrypted with its expires_at.
  - The connection test does sts:GetCallerIdentity AFTER the assume.
    It's lightweight and unambiguous.
  - GCP credentials = the user's pasted service-account JSON. We
    parse it, validate the shape, then store it encrypted. The
    test-connection endpoint instantiates a Google client and lists
    one project to verify.
"""
import os
import json
from datetime import datetime, timezone, timedelta

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

import db


credentials_bp = Blueprint("credentials", __name__)


# ============================================================
# Helpers
# ============================================================

def _redact_credential(row: dict) -> dict:
    """Convert a credential row (with decrypted credential dict) into
    a safe-to-return shape. Sensitive fields are redacted; metadata
    stays.

    For the connect page UI we want to show 'an AWS credential exists,
    labelled X, role-ARN visible' but NOT the underlying secret/session
    token in case the page is screenshotted or logged.
    """
    cred = row.get("credential") or {}
    cloud = row.get("cloud")
    public_view = {
        "id": row["id"],
        "cloud": cloud,
        "label": row.get("label"),
        "created_at": row.get("created_at"),
        "last_refreshed_at": row.get("last_refreshed_at"),
        "expires_at": row.get("expires_at"),
        "aws_role_arn": row.get("aws_role_arn"),
        "aws_external_id": row.get("aws_external_id"),
    }
    if cloud == "gcp":
        # Surface enough of the service-account JSON to be recognisable
        # ("which SA email is this?") without exposing the private key.
        public_view["gcp_client_email"] = cred.get("client_email")
        public_view["gcp_project_id"] = cred.get("project_id")
    return public_view


# ============================================================
# AWS credential management
# ============================================================

@credentials_bp.route("/api/credentials/aws", methods=["POST"])
@login_required
def save_aws_credential():
    """Save (or update) an AWS assume-role credential, EAGERLY calling
    sts:AssumeRole to populate session credentials immediately.

    Expected JSON:
      {
        "label": "Production",        # required, user-friendly name
        "role_arn": "arn:aws:iam::123456789012:role/CloudPathScanRole",
                                       # required, the role TO assume
      }

    On success the row will have:
      - encrypted_blob: encrypted session credentials (access key,
        secret, session token)
      - expires_at: ~1 hour from now
      - last_refreshed_at: NOW
    The background refresh worker keeps these current going forward.

    On AssumeRole failure (bad trust policy, wrong external ID, role
    doesn't exist...) the credential is NOT saved — we return the AWS
    error so the user can fix their trust policy first.
    """
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    payload = request.get_json(silent=True) or {}
    label = (payload.get("label") or "").strip()
    role_arn = (payload.get("role_arn") or "").strip()

    if not label or len(label) > 100:
        return jsonify({"error": "label must be 1-100 characters"}), 400
    if not role_arn or not role_arn.startswith("arn:aws:iam::"):
        return jsonify({
            "error": "role_arn must be an AWS IAM role ARN "
                     "(arn:aws:iam::ACCOUNT:role/ROLENAME)",
        }), 400
    if len(role_arn) > 2048:
        return jsonify({"error": "role_arn is too long"}), 400

    # Verify the server has scanner-account credentials before attempting
    # AssumeRole — better to fail with a clear message than NoCredentialsError.
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        return jsonify({
            "error": "Server is missing scanner-account AWS credentials. "
                     "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY "
                     "before saving credentials.",
        }), 500

    external_id = current_user.aws_external_id

    # Eager assume-role: prove the trust policy works before we
    # persist anything. If this fails, the user fixes the policy
    # and tries again.
    try:
        sts = boto3.client("sts")
        assume_resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"cloudpath-save-{current_user.id}",
            ExternalId=external_id,
            DurationSeconds=3600,
        )
    except ClientError as e:
        # Pass the AWS error code/message through. These are safe to
        # show — same wording the AWS console shows.
        return jsonify({
            "ok": False,
            "error_code": e.response.get("Error", {}).get("Code"),
            "error": e.response.get("Error", {}).get("Message", str(e)),
            "hint": "Check that your role trust policy allows account "
                    f"{os.environ.get('CLOUDPATH_SCANNER_AWS_ACCOUNT_ID', '456375341368')} "
                    f"with external ID {external_id!r}.",
        }), 400
    except NoCredentialsError:
        return jsonify({
            "ok": False,
            "error": "Server scanner-account credentials are invalid",
        }), 500
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": f"unexpected: {type(e).__name__}: {e}",
        }), 500

    # AssumeRole succeeded — persist the session credentials.
    creds_block = assume_resp["Credentials"]
    credential_dict = {
        "type": "aws-assume-role-session",
        "role_arn": role_arn,
        "access_key_id": creds_block["AccessKeyId"],
        "secret_access_key": creds_block["SecretAccessKey"],
        "session_token": creds_block["SessionToken"],
    }
    expires_at = creds_block["Expiration"]

    try:
        new_id = db.upsert_cloud_credential_sync(
            user_id=current_user.id,
            cloud="aws",
            label=label,
            credential_dict=credential_dict,
            aws_role_arn=role_arn,
            aws_external_id=external_id,
            expires_at=expires_at,
        )
    except Exception as e:
        return jsonify({"error": f"storage failed: {type(e).__name__}"}), 500

    return jsonify({
        "ok": True,
        "credential_id": new_id,
        "expires_at": expires_at.isoformat(),
        "message": "Credential saved and authenticated. Auto-refresh "
                   "is enabled; the session token will be renewed before "
                   "expiry.",
    })


# ============================================================
# GCP credential management
# ============================================================

@credentials_bp.route("/api/credentials/gcp", methods=["POST"])
@login_required
def save_gcp_credential():
    """Save (or update) a GCP service-account credential.

    Expected JSON:
      {
        "label": "Production",                # required
        "service_account_json": "{...}",      # required, the full
                                              # JSON content of the
                                              # service-account key
      }
    """
    payload = request.get_json(silent=True) or {}
    label = (payload.get("label") or "").strip()
    sa_json_str = (payload.get("service_account_json") or "").strip()

    if not label or len(label) > 100:
        return jsonify({"error": "label must be 1-100 characters"}), 400
    if not sa_json_str:
        return jsonify({"error": "service_account_json is required"}), 400

    # Validate it's actually a service account JSON before storing.
    # Better to fail here than at scan time.
    try:
        sa_dict = json.loads(sa_json_str)
    except json.JSONDecodeError:
        return jsonify({"error": "service_account_json is not valid JSON"}), 400

    required_keys = {"type", "project_id", "client_email", "private_key"}
    missing = required_keys - set(sa_dict.keys())
    if missing:
        return jsonify({
            "error": f"service_account_json is missing required keys: "
                     f"{', '.join(sorted(missing))}",
        }), 400
    if sa_dict.get("type") != "service_account":
        return jsonify({
            "error": "JSON does not look like a service account "
                     f"(type='{sa_dict.get('type')}', expected 'service_account')",
        }), 400

    # Store the full JSON dict; the engine will reconstruct the JSON
    # string at use time and write it to a temp file for the SDK.
    try:
        new_id = db.upsert_cloud_credential_sync(
            user_id=current_user.id,
            cloud="gcp",
            label=label,
            credential_dict=sa_dict,
            expires_at=None,   # GCP SA keys don't expire by default
        )
    except Exception as e:
        return jsonify({"error": f"storage failed: {type(e).__name__}"}), 500

    return jsonify({"ok": True, "credential_id": new_id})


# ============================================================
# List + delete
# ============================================================

@credentials_bp.route("/api/credentials", methods=["GET"])
@login_required
def list_credentials():
    """Return the current user's saved credentials in safe-to-show form.

    Sensitive fields (AWS secret keys, GCP private key) are redacted.
    The connect page uses this to render the current connection state.
    """
    try:
        rows = db.get_cloud_credentials_for_user_sync(current_user.id)
    except Exception as e:
        return jsonify({"error": f"lookup failed: {type(e).__name__}"}), 500
    return jsonify({
        "credentials": [_redact_credential(r) for r in rows],
    })


@credentials_bp.route("/api/credentials/<int:credential_id>", methods=["DELETE"])
@login_required
def delete_credential(credential_id):
    """Delete one credential, scoped to current_user."""
    try:
        deleted = db.delete_cloud_credential_sync(current_user.id, credential_id)
    except Exception as e:
        return jsonify({"error": f"delete failed: {type(e).__name__}"}), 500
    if not deleted:
        return jsonify({"error": "credential not found"}), 404
    return jsonify({"ok": True})


# ============================================================
# Per-user connection status — for the Connect page badges
# ============================================================

@credentials_bp.route("/api/credentials/status", methods=["GET"])
@login_required
def credential_status():
    """Return the per-cloud connection state for the LOGGED-IN user.

    Returns shape:
      {
        "aws": {
          "connected": true | false,
          "verified": true | false,         # last_refreshed_at is set
          "label": "Production" | null,
          "account_id": "773280493073" | null,   # parsed from role_arn
          "expires_at": "..." | null,
        },
        "gcp": {
          "connected": true | false,
          "verified": true | false,
          "label": "Production" | null,
          "project_id": "cloudpath-fyp" | null,
        }
      }
    """
    try:
        rows = db.get_cloud_credentials_for_user_sync(current_user.id)
    except Exception as e:
        return jsonify({"error": f"lookup failed: {type(e).__name__}"}), 500

    aws_state = {"connected": False, "verified": False, "id": None,
                 "label": None, "account_id": None, "expires_at": None}
    gcp_state = {"connected": False, "verified": False, "id": None,
                 "label": None, "project_id": None}

    for row in rows:
        if row["cloud"] == "aws" and not aws_state["connected"]:
            aws_state["connected"] = True
            aws_state["verified"] = row.get("last_refreshed_at") is not None
            aws_state["id"] = row.get("id")
            aws_state["label"] = row.get("label")
            aws_state["expires_at"] = (
                row["expires_at"].isoformat() if row.get("expires_at") else None
            )
            # Parse account ID from the role ARN: arn:aws:iam::ACCOUNT:role/...
            arn = row.get("aws_role_arn") or ""
            parts = arn.split(":")
            if len(parts) >= 5 and parts[4].isdigit():
                aws_state["account_id"] = parts[4]

        elif row["cloud"] == "gcp" and not gcp_state["connected"]:
            gcp_state["connected"] = True
            # GCP keys don't expire by default — being "connected" means
            # we have the JSON. "verified" is unused for GCP but kept
            # for symmetry with AWS.
            gcp_state["verified"] = True
            gcp_state["id"] = row.get("id")
            gcp_state["label"] = row.get("label")
            cred = row.get("credential") or {}
            gcp_state["project_id"] = cred.get("project_id")

    return jsonify({"aws": aws_state, "gcp": gcp_state})


# ============================================================
# Test-connection endpoints
# ============================================================

@credentials_bp.route("/api/test-connection/aws", methods=["POST"])
@login_required
def test_aws_connection():
    """Attempt sts:AssumeRole using the user's saved role ARN + their
    external ID, with the server's scanner-account credentials as the
    caller. On success returns the assumed identity; on failure returns
    the AWS error message verbatim (so the user can debug their trust
    policy from the UI).

    Expected JSON:
      {"credential_id": 5}   # optional; if missing, tests the first
                              # AWS credential the user has.
    """
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    payload = request.get_json(silent=True) or {}
    requested_id = payload.get("credential_id")

    # Find the user's AWS credential(s) to test against
    try:
        creds = db.get_cloud_credentials_for_user_sync(
            current_user.id, cloud="aws",
        )
    except Exception as e:
        return jsonify({"error": f"lookup failed: {type(e).__name__}"}), 500

    if not creds:
        return jsonify({
            "ok": False,
            "error": "no AWS credentials saved yet",
        }), 404

    if requested_id is not None:
        creds = [c for c in creds if c["id"] == requested_id]
        if not creds:
            return jsonify({
                "ok": False,
                "error": f"credential {requested_id} not found",
            }), 404

    cred = creds[0]
    role_arn = cred.get("aws_role_arn")
    external_id = cred.get("aws_external_id") or current_user.aws_external_id
    if not role_arn:
        return jsonify({"ok": False, "error": "role_arn missing on this credential"}), 400

    # Use the SERVER'S credentials (env vars) to call STS. These are
    # the IAM user in the scanner account (456375341368). If they're
    # not configured we surface a clear error rather than a generic
    # NoCredentialsError later.
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        return jsonify({
            "ok": False,
            "error": "Server is missing scanner-account AWS credentials. "
                     "AWS_ACCESS_KEY_ID env var must be set.",
        }), 500

    try:
        sts = boto3.client("sts")
        assume_resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"cloudpath-test-{current_user.id}",
            ExternalId=external_id,
            DurationSeconds=900,   # 15 minutes (minimum)
        )
    except ClientError as e:
        # Surface the AWS error code/message so the user can debug
        # their trust policy. These messages are safe to show — they're
        # the SAME messages the AWS console shows.
        return jsonify({
            "ok": False,
            "error_code": e.response.get("Error", {}).get("Code"),
            "error": e.response.get("Error", {}).get("Message", str(e)),
        }), 400
    except NoCredentialsError:
        return jsonify({
            "ok": False,
            "error": "Server scanner-account credentials are invalid",
        }), 500
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": f"unexpected: {type(e).__name__}: {e}",
        }), 500

    # Successfully assumed; now verify the assumed identity.
    creds_block = assume_resp["Credentials"]
    sts_check = boto3.client(
        "sts",
        aws_access_key_id=creds_block["AccessKeyId"],
        aws_secret_access_key=creds_block["SecretAccessKey"],
        aws_session_token=creds_block["SessionToken"],
    )
    identity = sts_check.get_caller_identity()

    return jsonify({
        "ok": True,
        "assumed_arn": identity.get("Arn"),
        "assumed_account": identity.get("Account"),
        "expires_at": creds_block["Expiration"].isoformat(),
    })


@credentials_bp.route("/api/test-connection/gcp", methods=["POST"])
@login_required
def test_gcp_connection():
    """Attempt a lightweight GCP call (list-projects) using the saved
    service-account JSON. Surfaces the GCP error verbatim on failure.

    Expected JSON:
      {"credential_id": 5}   # optional
    """
    import tempfile
    from google.oauth2 import service_account
    from google.auth.exceptions import GoogleAuthError
    import googleapiclient.discovery

    payload = request.get_json(silent=True) or {}
    requested_id = payload.get("credential_id")

    try:
        creds = db.get_cloud_credentials_for_user_sync(
            current_user.id, cloud="gcp",
        )
    except Exception as e:
        return jsonify({"error": f"lookup failed: {type(e).__name__}"}), 500

    if not creds:
        return jsonify({
            "ok": False,
            "error": "no GCP credentials saved yet",
        }), 404

    if requested_id is not None:
        creds = [c for c in creds if c["id"] == requested_id]
        if not creds:
            return jsonify({
                "ok": False,
                "error": f"credential {requested_id} not found",
            }), 404

    cred = creds[0]
    sa_dict = cred.get("credential") or {}
    if not sa_dict.get("private_key"):
        return jsonify({
            "ok": False,
            "error": "credential is missing the service account JSON content",
        }), 400

    try:
        # Build credentials from the in-memory dict (no temp file needed)
        gcp_creds = service_account.Credentials.from_service_account_info(
            sa_dict,
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
        )
        # Lightweight call: list the project ID we authenticated against.
        # This proves the SA + key are valid and reachable.
        crm = googleapiclient.discovery.build(
            "cloudresourcemanager", "v1",
            credentials=gcp_creds,
            cache_discovery=False,
        )
        project_resp = crm.projects().get(
            projectId=sa_dict["project_id"],
        ).execute()
    except GoogleAuthError as e:
        return jsonify({"ok": False, "error": f"auth failed: {e}"}), 400
    except Exception as e:
        return jsonify({
            "ok": False,
            "error": f"{type(e).__name__}: {e}",
        }), 400

    return jsonify({
        "ok": True,
        "project_id": project_resp.get("projectId"),
        "project_name": project_resp.get("name"),
        "service_account_email": sa_dict.get("client_email"),
    })


# ============================================================
# Init
# ============================================================

def init_credentials(app):
    """Register the credentials blueprint on the Flask app."""
    app.register_blueprint(credentials_bp)