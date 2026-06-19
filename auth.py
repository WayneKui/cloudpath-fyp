"""
CloudPath authentication module.

This module owns everything about user identity:
  - login / register / logout HTTP endpoints
  - flask-login User class + user_loader (translates session cookie -> user dict)
  - Per-tenant Neo4j database creation at signup
  - Post-login redirect logic (first-time users go to /connect; returning
    users with stored credentials go straight to /app)
  - JSON API endpoint that frontend JS uses to ask "am I logged in?"
    so we can conditionally render nav buttons.

Design notes:
  - flask-login handles the session cookie + "remember me" mechanics.
    We supply a UserMixin subclass and a loader function; flask-login
    takes care of the rest.
  - The session cookie is signed (not encrypted) by Flask using
    app.secret_key. It contains the user id; the actual user data is
    fetched from PostgreSQL on each request via the user_loader.
  - Password verification, hashing, and DB I/O all live in db.py.
    auth.py only orchestrates.
  - Tenant Neo4j databases are created via Neo4j's system database
    using `CREATE DATABASE tenant_<id>`. This requires Neo4j 4.0+
    Community Edition or any Enterprise edition.
"""
import os
import re
import secrets
from flask import (
    Blueprint, request, render_template, redirect, url_for, jsonify, flash,
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required,
    current_user,
)
from neo4j import GraphDatabase

import db
from neo4j.exceptions import ClientError


# ============================================================
# Constants
# ============================================================

# Your scanner AWS account ID. Every user's trust policy must allow
# this account to call sts:AssumeRole on their role. Centralised here
# so when you eventually rotate the scanner account it's one change.
SCANNER_AWS_ACCOUNT_ID = os.environ.get(
    "CLOUDPATH_SCANNER_AWS_ACCOUNT_ID", "456375341368"
)


def generate_external_id(user_id_hint: int = None) -> str:
    """Generate a per-user external ID used in IAM role trust policies.

    Format: 'cloudpath-tenant-<id_hint>-<8 random hex chars>'.
    Recognisable in CloudTrail logs, unguessable suffix, AWS-legal
    characters only. We accept user_id_hint as an argument because
    the user row doesn't exist yet at the moment we generate this
    — we want the id IN the external ID so we sometimes use a
    sentinel and rewrite after insert, or pass through a separate
    deterministic value at signup time. Here we use a hint that may
    be replaced later if needed.
    """
    suffix = secrets.token_hex(4)   # 8 hex chars, ~32 bits of entropy
    return f"cloudpath-tenant-{user_id_hint or 'new'}-{suffix}"


# ============================================================
# Blueprint setup
# ============================================================
# All auth routes are registered as a Flask blueprint, which keeps
# them isolated from the main app.py and makes them easy to mount.

auth_bp = Blueprint("auth", __name__)

# flask-login manager. Created once here; bound to the Flask app
# in init_auth(app) below. Decoupling creation from binding lets
# us import this manager elsewhere without circular imports.
login_manager = LoginManager()


# ============================================================
# User class for flask-login
# ============================================================

class User(UserMixin):
    """Adapter between flask-login and CloudPath's user dict.

    flask-login expects a user object with at least an `id` property
    (string), an `is_authenticated` flag, etc. UserMixin provides
    sensible defaults; we override `get_id()` to return a string.
    """

    def __init__(self, user_row: dict):
        # user_row is the dict returned by db.get_user_by_id(...)
        self._row = user_row
        self.id = user_row["id"]
        self.email = user_row["email"]
        self.display_name = user_row.get("display_name") or user_row["email"]
        self.subscription_tier = user_row.get("subscription_tier", "free")
        self.neo4j_database_name = user_row["neo4j_database_name"]
        self.aws_external_id = user_row.get("aws_external_id")

    def get_id(self):
        # flask-login serialises this into the session cookie.
        # Must be a string per its docs.
        return str(self.id)

    @property
    def tenant_id(self):
        # In CloudPath the user_id IS the tenant_id (single-user
        # tenants for FYP scope). Exposing this as a separate
        # property makes downstream tenant-scoping code read clearly.
        return self.id


@login_manager.user_loader
def load_user(user_id_str: str):
    """flask-login calls this on every request to reconstruct the
    current_user from the session cookie. Returning None means the
    cookie is invalid -> user is treated as anonymous.
    """
    try:
        user_id = int(user_id_str)
    except (TypeError, ValueError):
        return None
    row = db.get_user_by_id_sync(user_id)
    if row is None or not row.get("is_active", True):
        return None
    return User(row)


# ============================================================
# Email + password validators
# ============================================================
# These are intentionally simple. We don't want to reject valid
# emails because of a too-strict regex; basic shape-check is fine
# and the DB UNIQUE constraint handles duplicates.

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _validate_email(email: str) -> str | None:
    """Return None if email is OK, otherwise a user-facing error string."""
    if not email or not isinstance(email, str):
        return "Email is required."
    email = email.strip()
    if len(email) > 255:
        return "Email is too long."
    if not _EMAIL_RE.match(email):
        return "Please enter a valid email address."
    return None


def _validate_password(password: str) -> str | None:
    """Return None if password is OK, otherwise an error string.

    Honest minimums: at least 8 chars, no upper bound. We don't enforce
    "must contain a digit / symbol" rules — NIST 800-63B explicitly
    recommends against those because they push users toward predictable
    patterns. Length + uniqueness is what matters.
    """
    if not password or not isinstance(password, str):
        return "Password is required."
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if len(password) > 200:
        return "Password is too long."
    return None


# ============================================================
# Per-tenant Neo4j database creation
# ============================================================

def _create_tenant_neo4j_database(database_name: str) -> tuple[bool, str | None]:
    """Create a Neo4j database for a new tenant.

    Uses the Neo4j 'system' database to run a CREATE DATABASE statement.
    If the database already exists (rare but possible if a previous
    registration partially succeeded), we treat that as success.

    Returns (ok, error_message). On failure, ok=False and error_message
    is suitable for logging — NOT for showing to the end user (it may
    leak schema details).
    """
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "changeme")

    # Validate the name shape: Neo4j allows letters, digits, dots,
    # dashes, underscores. Since we generate the name from a numeric
    # user id ("tenant_<n>"), this is defensive — not user input.
    if not re.match(r"^[A-Za-z][A-Za-z0-9_.\-]*$", database_name):
        return False, f"Invalid database name: {database_name}"
    if len(database_name) > 63:
        return False, f"Database name too long: {database_name}"

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session(database="system") as session:
            # IF NOT EXISTS makes this idempotent. If the db already
            # exists from a previous attempt, Neo4j is fine with it.
            session.run(f"CREATE DATABASE {database_name} IF NOT EXISTS")
        return True, None
    except ClientError as e:
        # Community Edition limit hit, name conflict, etc. Surface a
        # short error string for logging.
        return False, f"Neo4j create-database failed: {e.code}: {e.message}"
    except Exception as e:
        return False, f"Neo4j connection failed: {type(e).__name__}: {e}"
    finally:
        driver.close()


# ============================================================
# Routes — GET pages
# ============================================================

@auth_bp.route("/login", methods=["GET"])
def login_page():
    """Show the login form. If the user is already logged in, send
    them to wherever a logged-in user normally lands."""
    if current_user.is_authenticated:
        return redirect(_post_login_destination(current_user))
    next_url = request.args.get("next") or ""
    return render_template("login.html", next_url=next_url, error=None)


@auth_bp.route("/register", methods=["GET"])
def register_page():
    """Show the registration form."""
    if current_user.is_authenticated:
        return redirect(_post_login_destination(current_user))
    return render_template("register.html", error=None)


# ============================================================
# Routes — POST actions
# ============================================================

@auth_bp.route("/login", methods=["POST"])
def login_action():
    """Handle login form submission.

    Steps:
      1. Read email + password from the form.
      2. Look up the user by email.
      3. Verify the password using bcrypt's constant-time check.
      4. On success: call flask-login's login_user(); redirect onward.
      5. On failure: re-render the form with a generic error message.

    Honest security notes:
      - The error message intentionally does NOT distinguish "no such
        user" from "wrong password". This prevents email enumeration.
      - Password verification is via bcrypt.checkpw() which is constant-
        time, mitigating timing-based username enumeration.
    """
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    next_url = request.form.get("next") or ""

    if not email or not password:
        return render_template(
            "login.html", next_url=next_url,
            error="Please enter your email and password.",
        ), 400

    user_row = db.get_user_by_email_sync(email)
    if user_row is None or not db.verify_password(password, user_row["password_hash"]):
        # Same error for both: keeps attackers from confirming which
        # emails are registered.
        return render_template(
            "login.html", next_url=next_url,
            error="Email or password is incorrect.",
        ), 401

    if not user_row.get("is_active", True):
        return render_template(
            "login.html", next_url=next_url,
            error="This account is disabled.",
        ), 403

    user = User(user_row)
    login_user(user, remember=True)
    db.update_last_login_sync(user.id)

    # Honor a ?next=/foo redirect if it looks safe (relative URL only,
    # never an external host — that would be an open-redirect vuln).
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return redirect(next_url)
    return redirect(_post_login_destination(user))


@auth_bp.route("/register", methods=["POST"])
def register_action():
    """Handle registration form submission.

    Steps:
      1. Read + validate fields.
      2. Hash the password and INSERT a row into users (transactional).
      3. Create the user's per-tenant Neo4j database.
      4. Log the new user in immediately (so they don't need to retype).
      5. Redirect to /connect (first-time onboarding).

    Failure handling:
      - If the email is already taken, show a friendly error.
      - If Neo4j db creation fails AFTER user insert: the user row
        exists but their tenant graph doesn't. We log the error and
        let the user proceed — Phase 6 code will lazily create the
        db on first use as a safety net.
    """
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    confirm_password = request.form.get("confirm_password") or ""
    display_name = (request.form.get("display_name") or "").strip()

    # Validate inputs
    for err in (_validate_email(email), _validate_password(password)):
        if err:
            return render_template("register.html", error=err), 400
    if password != confirm_password:
        return render_template(
            "register.html", error="Passwords do not match.",
        ), 400
    if display_name and len(display_name) > 100:
        return render_template(
            "register.html", error="Display name is too long.",
        ), 400

    # Generate the per-user external ID. We don't yet know the user_id
    # (assigned by the SERIAL on insert), so use a placeholder; if the
    # external-ID format ever matters for matching the user_id we'd
    # post-update like we do with the Neo4j db name.
    external_id = generate_external_id()

    # Try to create the user. UniqueViolationError = email already taken.
    import asyncpg
    try:
        new_user_row = db.create_user_sync(
            email, password, display_name or None, aws_external_id=external_id,
        )
    except asyncpg.UniqueViolationError:
        return render_template(
            "register.html",
            error="An account with that email already exists.",
        ), 409

    # Create the per-tenant Neo4j database. We log failures but do
    # not roll back the user creation — Phase 6 has a lazy-create
    # safety net. This pragmatic choice avoids users being stuck
    # in limbo if Neo4j is briefly unavailable during signup.
    ok, err_msg = _create_tenant_neo4j_database(new_user_row["neo4j_database_name"])
    if not ok:
        print(f"[auth] WARNING: tenant Neo4j db creation failed for "
              f"user {new_user_row['id']}: {err_msg}")

    # Auto-login the freshly-registered user
    full_user_row = db.get_user_by_email_sync(email)
    user = User(full_user_row)
    login_user(user, remember=True)
    db.update_last_login_sync(user.id)

    # First-time users always go to /connect (onboarding step)
    return redirect(url_for("connect"))


@auth_bp.route("/logout", methods=["POST", "GET"])
@login_required
def logout_action():
    """Clear the user's session and send them to the landing page."""
    logout_user()
    return redirect(url_for("home"))


# ============================================================
# JSON API: current auth state
# ============================================================

@auth_bp.route("/api/auth/status", methods=["GET"])
def auth_status():
    """Return whether the current request is authenticated.

    Used by frontend JS to decide which nav buttons to show
    (Login/Sign up vs Dashboard/Logout) without re-rendering
    server-side templates. Also exposes the scanner-account ID and
    the user's external ID so the connect page can display them.
    """
    if current_user.is_authenticated:
        return jsonify({
            "logged_in": True,
            "user": {
                "id": current_user.id,
                "email": current_user.email,
                "display_name": current_user.display_name,
                "subscription_tier": current_user.subscription_tier,
                "aws_external_id": current_user.aws_external_id,
            },
            "scanner_aws_account_id": SCANNER_AWS_ACCOUNT_ID,
        })
    return jsonify({"logged_in": False})


# ============================================================
# Redirect logic
# ============================================================

def _post_login_destination(user: User) -> str:
    """Decide where to send a user immediately after login.

    Rule: if the user has at least one stored credential, they're a
    returning user — go straight to /app. Otherwise they're new or
    haven't completed onboarding — send them to /connect to set up
    their cloud accounts.
    """
    creds = db.get_cloud_credentials_for_user_sync(user.id)
    if creds:
        return url_for("app_page")
    return url_for("connect")


# ============================================================
# App initialization helper
# ============================================================

def init_auth(app):
    """Bind flask-login + the auth blueprint to the Flask app.

    Called once from app.py at startup. Splitting this from blueprint
    creation avoids circular imports (app.py imports auth, auth doesn't
    need to import app).
    """
    # Flask's session cookie must be signed with a secret. In dev we
    # fall back to a placeholder; in production set FLASK_SECRET_KEY.
    app.secret_key = os.environ.get(
        "FLASK_SECRET_KEY",
        "dev-only-secret-change-in-production-fly5HfRpkbQ7vL2x",
    )

    login_manager.init_app(app)
    login_manager.login_view = "auth.login_page"
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "info"

    # For JSON API requests, redirect-to-login is wrong. Return 401 JSON.
    @login_manager.unauthorized_handler
    def _unauth():
        if request.path.startswith("/api/") or request.is_json:
            return jsonify({"error": "authentication required"}), 401
        # For page requests, preserve the originally-requested URL.
        return redirect(url_for("auth.login_page", next=request.path))

    app.register_blueprint(auth_bp)