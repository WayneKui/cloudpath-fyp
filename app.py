"""
CloudPath Flask application.

Routes:
  /                          Home page (landing)
  /connect                   Connection setup page
  /app                       Dashboard (scanner + visualizations)
  /rules                     Rule manager
  /docs                      Documentation
  /scan                      JSON API: returns attack paths (runs detection)
  /dashboard-data            JSON API: runs detection + returns aggregations.
                             Called by the default Run Scan button.
  /dashboard-cache           JSON API: returns the LAST cached scan result with
                             NO new detection. Called silently on page load to
                             restore the previous dashboard state.
  /connection-status         JSON API: cheap Neo4j check (does AWS/GCP data exist).
  /env-status                JSON API: are AWS/GCP credentials loaded in the
                             Flask environment? Used by the dashboard to show
                             whether the full pipeline is runnable.
  /full-pipeline-scan        POST: triggers the full ingestion pipeline
                             (Cartography + custom ingestors + Prowler + merge
                             + detection) in a background thread. Returns
                             a job_id immediately for status polling.
  /pipeline-status/<job_id>  GET: returns the current status of a running
                             pipeline (current step, completed steps, errors,
                             final result if complete).

Pipeline execution model:
  - Threaded: pipeline runs in a background thread so HTTP requests don't
    block. The browser polls /pipeline-status for progress updates.
  - Single-pipeline lock: only one pipeline can run at a time. A second
    request returns the existing job_id (both browsers watch the same run).
  - Continue-on-error: if one step fails (e.g., Cartography crashes on an
    opt-in service), the pipeline records the failure and continues with
    remaining steps. Partial data is acceptable.
  - In-memory job tracking: job state is lost if Flask restarts. For a
    production deployment this would move to Redis or a database.
"""
import os
import sys
import time
import uuid
import threading
import subprocess
from collections import Counter, defaultdict

# Load environment variables from a `.env` file at project root (if
# present) BEFORE any module reads os.environ. This lets us keep secrets
# like LEMONSQUEEZY_API_KEY, NEO4J_PASSWORD, SMTP creds, etc. in a
# single file that survives PowerShell session restarts. On production
# hosts the env vars would be set by the platform (systemd, Docker,
# k8s Secrets, etc.) and .env would be absent — that's fine, load_dotenv
# is a no-op when the file doesn't exist.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv is optional. If missing, env must be set in the shell.
    pass

from flask import Flask, jsonify, render_template, request
from flask_login import login_required, current_user
from neo4j import GraphDatabase

from engine import (
    get_attack_paths_json, load_rules, detect_all, link_cross_cloud_credentials,
    load_custom_rules_for_tenant, validate_custom_rule_cypher, TACTIC_ORDER,
    load_builtin_rules_summary,
)
from auth import init_auth
from credentials import init_credentials
from refresh_worker import start_refresh_worker
from scan_credentials import scan_credentials_for_user
from tenant_scope import (
    scan_start_timestamp_ms, ensure_tenant_index, tag_tenant_nodes,
)


NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "changeme")


app = Flask(__name__)

# Initialize authentication: registers the auth blueprint
# (/login, /register, /logout, /api/auth/status) and the flask-login
# session machinery. Must happen before any @login_required route is
# accessed.
init_auth(app)

# Initialize credentials API: registers /api/credentials/* and
# /api/test-connection/* endpoints. Must run after init_auth.
init_credentials(app)

# Register the billing blueprint: /api/billing/* + /billing + /billing/success
# (LemonSqueezy subscription integration). Must run after init_auth.
from billing import billing_bp
app.register_blueprint(billing_bp)

# Register the scheduler blueprint: /api/schedule/* (Plus tier scheduled scans).
# Stage 1: CRUD endpoints only. Stage 2 will add the background thread.
from scheduler import scheduler_bp
app.register_blueprint(scheduler_bp)

# Register the v1 REST API blueprint: /api/v1/* (Max tier only, API key
# auth). Endpoints for scans, attack paths, and compliance exports.
from api_v1 import api_v1_bp
app.register_blueprint(api_v1_bp)


# ---- Jinja filter: friendly timestamp formatting ----
# Both PostgreSQL (`datetime` with `+00:00`) and LemonSqueezy (ISO 8601
# with `Z`) give us UTC timestamps. We display them in Malaysia Time
# (UTC+8) since that's where CloudPath is built and where the primary
# users / examiner are. Format: "29 Jul 2026, 22:41 MYT"
#
# This is registered globally so any template (billing.html, billing_success.html,
# dashboard.html, etc.) can use {{ some_timestamp|friendly_time }}.
def _friendly_time(value):
    """Format a timestamp (datetime, ISO string, or None) as Malaysia time."""
    if value is None or value == "" or value == "None":
        return ""
    from datetime import datetime, timezone, timedelta
    MYT = timezone(timedelta(hours=8))
    try:
        if isinstance(value, str):
            # Strip trailing 'Z' and parse as ISO 8601
            cleaned = value.rstrip("Z")
            # Handle microsecond precision variations
            if "." in cleaned and cleaned.endswith("000000"):
                cleaned = cleaned[:-7]   # strip ".000000"
            # Add UTC if no offset present
            if "+" not in cleaned and "-" not in cleaned[10:]:
                cleaned = cleaned + "+00:00"
            dt = datetime.fromisoformat(cleaned)
        else:
            dt = value
        # Ensure timezone-aware
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        # Convert to MYT
        local = dt.astimezone(MYT)
        return local.strftime("%d %b %Y, %H:%M MYT")
    except (ValueError, TypeError, AttributeError):
        # Fallback: render whatever it is as string so the user sees
        # something rather than nothing
        return str(value)

app.jinja_env.filters["friendly_time"] = _friendly_time

# In-memory cache of the last dashboard payload PER USER.
# Populated by /dashboard-data; read by /dashboard-cache.
# Phase 7: keyed by user_id so user A's cache never bleeds into user B's
# dashboard. Survives across requests, reset when Flask restarts.
LAST_DASHBOARD = {}   # {user_id: payload_dict}
LAST_DASHBOARD_TIMESTAMP = {}  # {user_id: scanned_at_epoch}

# ---- Pipeline job tracking (in-memory) ----
# A job represents one full-pipeline-scan execution. Multiple browsers can
# watch the same job by polling /pipeline-status/<job_id>. The lock ensures
# only one pipeline runs at a time across the whole server.
PIPELINE_LOCK = threading.Lock()
PIPELINE_JOB = {
    "job_id": None,         # uuid string, or None if no job running
    "started_at": None,
    "finished_at": None,
    "status": "idle",       # 'idle' | 'running' | 'complete' | 'failed'
    "current_step": None,
    "steps": [],            # list of {name, status, returncode, error}
    "result": None,         # the /dashboard-data payload when complete
    "error": None,          # global error message if pipeline aborted
}


# ----------------------------- pages -----------------------------
# Home is public — it's the landing/marketing page. Everything else
# requires authentication.

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/connect")
@login_required
def connect():
    return render_template("connect.html")


@app.route("/app")
@login_required
def app_page():
    return render_template("index.html")


@app.route("/rules")
@login_required
def rules():
    return render_template("rules.html")


@app.route("/docs")
@login_required
def docs():
    return render_template("docs.html")


@app.route("/history")
@login_required
def history():
    """Scan history page (Plus tier feature). Displays past scan runs
    for the current user with KPIs and status."""
    return render_template("history.html")


@app.route("/api/history")
@login_required
def api_history():
    """Return the current user's scan history as JSON. Consumed by the
    history page (client-side render, so we can add sorting/filtering
    later without touching the server)."""
    try:
        import db as _db
        rows = _db.get_user_scan_history_sync(current_user.id, limit=100)
        # Convert datetime objects to ISO strings for JSON safety
        out = []
        for r in rows:
            item = dict(r)
            for k in ("started_at", "completed_at"):
                v = item.get(k)
                if v is not None and hasattr(v, "isoformat"):
                    item[k] = v.isoformat()
            out.append(item)
        return jsonify({"status": "ok", "history": out})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ---------------------------------------------------------------------
# API management page (Max tier) — API keys + webhooks CRUD
# ---------------------------------------------------------------------
# These endpoints power the /api-management page. The v1 REST endpoints
# themselves live in api_v1.py; these are the *administrative*
# endpoints (session-authenticated, not API-key-authenticated).
def _require_max_tier():
    """Session-side tier guard. Returns None if OK, or a Flask response
    to short-circuit with 403."""
    if (current_user.subscription_tier or "free").lower() != "max":
        return jsonify({
            "status":  "error",
            "message": "API access requires the Max subscription tier.",
        }), 403
    return None


@app.route("/api-management")
@login_required
def api_management_page():
    """Render the API management page (keys, webhooks, docs).
    Free/Plus users see an upgrade prompt; Max users see the full UI."""
    return render_template("api_management.html")


@app.route("/api/keys", methods=["GET"])
@login_required
def api_keys_list():
    guard = _require_max_tier()
    if guard is not None:
        return guard
    import db as _db
    try:
        rows = _db.list_api_keys_sync(current_user.id)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    # ISO datetimes for the client
    for r in rows:
        for k in ("created_at", "last_used_at", "revoked_at"):
            v = r.get(k)
            if v is not None and hasattr(v, "isoformat"):
                r[k] = v.isoformat()
    return jsonify({"status": "ok", "keys": rows})


@app.route("/api/keys", methods=["POST"])
@login_required
def api_keys_create():
    guard = _require_max_tier()
    if guard is not None:
        return guard
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip() or "Untitled key"
    import db as _db
    try:
        row = _db.create_api_key_sync(current_user.id, name)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    # Only response that ever includes the raw key
    return jsonify({"status": "ok", "key": row})


@app.route("/api/keys/<int:key_id>", methods=["DELETE"])
@login_required
def api_keys_revoke(key_id):
    guard = _require_max_tier()
    if guard is not None:
        return guard
    import db as _db
    try:
        ok = _db.revoke_api_key_sync(current_user.id, key_id)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    if not ok:
        return jsonify({"status": "error", "message": "Key not found."}), 404
    return jsonify({"status": "ok"})


@app.route("/api/webhooks", methods=["GET"])
@login_required
def api_webhooks_list():
    guard = _require_max_tier()
    if guard is not None:
        return guard
    import db as _db
    try:
        rows = _db.list_webhooks_sync(current_user.id)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    for r in rows:
        for k in ("created_at", "last_success_at", "last_failure_at"):
            v = r.get(k)
            if v is not None and hasattr(v, "isoformat"):
                r[k] = v.isoformat()
    return jsonify({"status": "ok", "webhooks": rows})


@app.route("/api/webhooks", methods=["POST"])
@login_required
def api_webhooks_create():
    guard = _require_max_tier()
    if guard is not None:
        return guard
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return jsonify({
            "status":  "error",
            "message": "URL must start with http:// or https://",
        }), 400
    events = data.get("events") or ["scan.completed"]
    if not isinstance(events, list) or not events:
        events = ["scan.completed"]
    # Whitelist known event names to avoid junk in the DB
    known = {"scan.completed", "finding.critical"}
    events = [e for e in events if e in known] or ["scan.completed"]
    import db as _db
    try:
        row = _db.create_webhook_sync(current_user.id, url, events)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    for k in ("created_at",):
        v = row.get(k)
        if v is not None and hasattr(v, "isoformat"):
            row[k] = v.isoformat()
    return jsonify({"status": "ok", "webhook": row})


@app.route("/api/webhooks/<int:webhook_id>", methods=["DELETE"])
@login_required
def api_webhooks_delete(webhook_id):
    guard = _require_max_tier()
    if guard is not None:
        return guard
    import db as _db
    try:
        ok = _db.delete_webhook_sync(current_user.id, webhook_id)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    if not ok:
        return jsonify({"status": "error", "message": "Webhook not found."}), 404
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------
# Custom detection rules (Rule Manager — /rules page)
# ---------------------------------------------------------------------
# Available to every tier (the /rules page itself has no tier gate).
# Every route below is scoped to current_user.id at the SQL layer
# (see db.py) — there is no code path that lets one user touch
# another user's custom rule, by id-guessing or otherwise.
_VALID_RULE_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_RULE_CLOUDS = {"aws", "gcp", "multi"}


def _parse_rule_payload(data):
    """Validate + normalize a rule create/update payload from the client.

    Returns (fields_dict, None) on success, or (None, error_message) on
    the first validation failure. Cypher safety (blocklist, MATCH/RETURN
    shape) is delegated to engine.validate_custom_rule_cypher — the
    single source of truth also used again at execution time.
    """
    rule_key = (data.get("rule_key") or data.get("id") or "").strip()
    mitre_name = (data.get("mitre_name") or data.get("name") or "").strip()
    tactic = (data.get("tactic") or "").strip()
    severity = (data.get("severity") or "medium").strip().lower()
    cloud = (data.get("cloud") or "aws").strip().lower()
    description = (data.get("description") or data.get("desc") or "").strip()
    cypher = data.get("cypher") or ""

    if not rule_key or len(rule_key) > 50:
        return None, "Rule ID is required (max 50 characters)."
    if not mitre_name:
        return None, "MITRE name is required."
    if tactic not in TACTIC_ORDER:
        return None, f"Tactic must be one of: {', '.join(TACTIC_ORDER)}"
    if severity not in _VALID_RULE_SEVERITIES:
        return None, f"Severity must be one of: {', '.join(sorted(_VALID_RULE_SEVERITIES))}"
    if cloud not in _VALID_RULE_CLOUDS:
        return None, f"Cloud must be one of: {', '.join(sorted(_VALID_RULE_CLOUDS))}"
    cypher_err = validate_custom_rule_cypher(cypher)
    if cypher_err:
        return None, cypher_err
    return {
        "rule_key": rule_key, "mitre_name": mitre_name, "tactic": tactic,
        "severity": severity, "cloud": cloud, "description": description,
        "cypher": cypher,
    }, None


def _rule_row_for_json(row):
    for k in ("created_at", "updated_at"):
        v = row.get(k)
        if v is not None and hasattr(v, "isoformat"):
            row[k] = v.isoformat()
    return row


@app.route("/api/rules/builtin", methods=["GET"])
@login_required
def api_rules_builtin():
    """The 4 built-in rules, read directly from rules/*.yaml — one row
    per technique, not per (technique, cloud) detection. Same for every
    tenant, read-only; not to be confused with /api/rules (custom)."""
    try:
        rows = load_builtin_rules_summary()
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "ok", "rules": rows})


@app.route("/api/rules/validate", methods=["POST"])
@login_required
def api_rules_validate():
    """Live safety check for the Cypher body only — called as the user
    types in the rule builder, debounced client-side. Deliberately
    lightweight: takes just {cypher}, not the full rule payload (tactic/
    severity/etc aren't relevant to whether the query is SAFE). Reuses
    validate_custom_rule_cypher — the exact same function POST/PUT
    /api/rules runs at save time — so "looks safe while typing" and
    "actually gets saved" can never disagree."""
    data = request.get_json(silent=True) or {}
    cypher = data.get("cypher") or ""
    error = validate_custom_rule_cypher(cypher)
    if error:
        return jsonify({"status": "ok", "safe": False, "message": error})
    return jsonify({
        "status": "ok", "safe": True,
        "message": "Cypher query is safe to save",
    })


@app.route("/api/rules", methods=["GET"])
@login_required
def api_rules_list():
    import db as _db
    try:
        rows = _db.list_custom_rules_sync(current_user.id)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "ok", "rules": [_rule_row_for_json(r) for r in rows]})


@app.route("/api/rules", methods=["POST"])
@login_required
def api_rules_create():
    data = request.get_json(silent=True) or {}
    fields, err = _parse_rule_payload(data)
    if err:
        return jsonify({"status": "error", "message": err}), 400
    import db as _db
    import asyncpg
    try:
        row = _db.create_custom_rule_sync(
            current_user.id, fields["rule_key"], fields["mitre_name"],
            fields["tactic"], fields["severity"], fields["cloud"],
            fields["description"], fields["cypher"],
        )
    except asyncpg.UniqueViolationError:
        return jsonify({
            "status": "error",
            "message": f"You already have a rule with ID '{fields['rule_key']}'. "
                       f"Choose a different ID or edit the existing one.",
        }), 409
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "ok", "rule": _rule_row_for_json(row)}), 201


@app.route("/api/rules/<int:rule_id>", methods=["PUT"])
@login_required
def api_rules_update(rule_id):
    data = request.get_json(silent=True) or {}
    fields, err = _parse_rule_payload(data)
    if err:
        return jsonify({"status": "error", "message": err}), 400
    import db as _db
    import asyncpg
    try:
        row = _db.update_custom_rule_sync(
            current_user.id, rule_id, fields["rule_key"], fields["mitre_name"],
            fields["tactic"], fields["severity"], fields["cloud"],
            fields["description"], fields["cypher"],
        )
    except asyncpg.UniqueViolationError:
        return jsonify({
            "status": "error",
            "message": f"You already have a rule with ID '{fields['rule_key']}'.",
        }), 409
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    if row is None:
        return jsonify({"status": "error", "message": "Rule not found."}), 404
    return jsonify({"status": "ok", "rule": _rule_row_for_json(row)})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@login_required
def api_rules_delete(rule_id):
    import db as _db
    try:
        ok = _db.delete_custom_rule_sync(current_user.id, rule_id)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    if not ok:
        return jsonify({"status": "error", "message": "Rule not found."}), 404
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------
# Compliance exports (session-authenticated — for browser download)
# ---------------------------------------------------------------------
# These mirror /api/v1/exports/* but authenticate via Flask-Login
# session cookie rather than API key. That way the "Download CSV/JSON"
# buttons on /api-management work directly from the browser without
# the user having to paste a key.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe_row(row: dict) -> dict:
    """Neutralize CSV/formula injection before writing a row.

    Node names/ids in these exports ultimately come from cloud
    resources (bucket names, IAM principal names, etc.), which an
    attacker with write access to the target account could name to
    execute a formula when the CSV is opened in Excel/Sheets. Prefix
    any string value starting with =, +, -, @, tab, or CR with a
    single quote so it renders as literal text instead.
    """
    def _safe(v):
        if isinstance(v, str) and v.startswith(_CSV_FORMULA_PREFIXES):
            return "'" + v
        return v
    return {k: _safe(v) for k, v in row.items()}


@app.route("/exports/paths.csv")
@login_required
def exports_paths_csv():
    guard = _require_max_tier()
    if guard is not None:
        return guard
    import csv as _csv
    import io as _io
    from flask import Response as _Resp
    try:
        from engine import get_attack_paths_json
        paths = get_attack_paths_json(current_user.id)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    def _row_for_path(p):
        """Flatten a path (which has an id/score/severity + a list of
        steps) into a single CSV row. Steps get compact string encodings:
          - technique_chain: 'T1190 -> T1078 -> T1530'
          - tactic_chain:    'Initial Access -> ... -> Impact'
          - entry_node:      'AWSPrincipal:iamRole-misconfiguration'
          - target_node:     'S3Bucket:s3-misconfiguration'
          - cloud:           'aws' or 'gcp' or 'aws+gcp' if the path
                             crosses providers
        """
        steps = p.get("steps") or []
        clouds = sorted({s.get("cloud", "unknown") for s in steps if s.get("cloud")})
        cloud_str = "+".join(clouds) if clouds else "unknown"
        technique_chain = " -> ".join(s.get("technique_id", "") for s in steps)
        mitre_chain     = " -> ".join(s.get("mitre_name", "") for s in steps)
        tactic_chain    = " -> ".join(s.get("tactic", "") for s in steps)
        entry_node  = (
            f"{steps[0].get('node_type','')}:{steps[0].get('node_id','')}"
            if steps else ""
        )
        target_node = (
            f"{steps[-1].get('node_type','')}:{steps[-1].get('node_id','')}"
            if steps else ""
        )
        title = mitre_chain or f"Attack path #{p.get('id')}"
        return {
            "id":                p.get("id"),
            "title":              title,
            "severity":           p.get("severity"),
            "score":              p.get("score"),
            "cloud":              cloud_str,
            "hops":               len(steps),
            "tactic_chain":       tactic_chain,
            "technique_chain":    technique_chain,
            "entry_node":         entry_node,
            "target_node":        target_node,
        }

    buf = _io.StringIO()
    fields = ["id", "title", "severity", "score", "cloud", "hops",
              "tactic_chain", "technique_chain", "entry_node", "target_node"]
    writer = _csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for p in paths:
        writer.writerow(_csv_safe_row(_row_for_path(p)))
    filename = f"cloudpath-attack-paths-{int(time.time())}.csv"
    return _Resp(
        buf.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@app.route("/exports/paths.json")
@login_required
def exports_paths_json():
    guard = _require_max_tier()
    if guard is not None:
        return guard
    try:
        from engine import get_attack_paths_json
        paths = get_attack_paths_json(current_user.id)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    filename = f"cloudpath-attack-paths-{int(time.time())}.json"
    resp = jsonify({
        "exported_at":  int(time.time()),
        "user_id":      current_user.id,
        "attack_paths": paths,
        "count":        len(paths),
    })
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


# ----------------------------- APIs -----------------------------
@app.route("/scan")
@login_required
def scan():
    """Return current attack paths as JSON (used by the scanner graph).

    Phase 7: scoped to current_user.id so each tenant sees only their own
    attack paths.
    """
    try:
        paths = get_attack_paths_json(current_user.id)
        return jsonify({"status": "ok", "paths": paths})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/dashboard-data")
@login_required
def dashboard_data():
    """Return aggregated dashboard data for the logged-in tenant:

    - kpi: counts by severity band (Critical/High/Medium/Low) + path count
    - tactic_counts: number of detections per MITRE tactic
    - cloud_resource_matrix: 2D grid of (cloud, resource_category) -> count
    - paths: full attack-path objects (same as /scan)
    - clouds: list of clouds with at least one detection
    """
    result = compute_dashboard_data(current_user.id)
    if result.get("status") == "error":
        return jsonify(result), 500
    return jsonify(result)


def compute_dashboard_data(tenant_id):
    driver = None
    try:
        rules = load_rules() + load_custom_rules_for_tenant(tenant_id)
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session() as session:
            # --- Detect which clouds are "connected" for THIS tenant ---
            # A cloud is connected if at least one anchor node belonging
            # to this tenant exists in Neo4j.
            connected = {}
            aws_check = session.run(
                "MATCH (a:AWSAccount {tenant_id: $tid}) RETURN a.id AS id, count(a) AS c LIMIT 1",
                tid=tenant_id,
            ).single()
            if aws_check and aws_check["c"] > 0:
                connected["aws"] = {"connected": True, "account_id": aws_check["id"]}
            else:
                connected["aws"] = {"connected": False, "account_id": None}

            gcp_check = session.run(
                "MATCH (p:GCPProject {tenant_id: $tid}) RETURN p.id AS id, count(p) AS c LIMIT 1",
                tid=tenant_id,
            ).single()
            if gcp_check and gcp_check["c"] > 0:
                connected["gcp"] = {"connected": True, "project_id": gcp_check["id"]}
            else:
                connected["gcp"] = {"connected": False, "project_id": None}

            # Re-establish cross-cloud bridge edges then detect — both scoped.
            link_cross_cloud_credentials(session, tenant_id)
            detections = detect_all(session, rules, tenant_id)

        # Reuse the canonical attack-path computation for this tenant.
        paths = get_attack_paths_json(tenant_id)

        # --- KPI counts by severity (from path scores, not raw detections) ---
        severity_counts = Counter()
        for p in paths:
            severity_counts[p["severity"]] += 1

        # --- Tactic counts (from detections) ---
        tactic_counts = Counter()
        for d in detections:
            tactic_counts[d["tactic"]] += 1

        # --- Cloud x resource category matrix ---
        # Map node types to higher-level categories for the heatmap.
        # The mapping follows the standard CNAPP taxonomy (Compute / Storage /
        # Identity / Network / Secret). Unknown node types fall into "Other"
        # which is only displayed as a column when at least one detection
        # lands there. This makes the heatmap honest about coverage: users
        # writing custom rules for new resource types see them surfaced
        # under Other rather than silently dropped.
        category_map = {
            "EC2Instance": "Compute",
            "GCPInstance": "Compute",
            "S3Bucket": "Storage",
            "GCPBucket": "Storage",
            "SecretsManagerSecret": "Secret",
            "GCPServiceAccount": "Identity",
            "AWSRole": "Identity",
            "GCPRole": "Identity",
            "EC2SecurityGroup": "Network",
            "GCPFirewall": "Network",
        }
        matrix = defaultdict(lambda: defaultdict(int))
        other_node_types = set()  # track which node_types fell into Other
        for d in detections:
            cat = category_map.get(d["node_type"])
            if cat is None:
                cat = "Other"
                other_node_types.add(d["node_type"])
            cloud = (d.get("cloud") or "unknown").lower()
            matrix[cloud][cat] += 1

        # Standard category columns, always shown
        STANDARD_CATEGORIES = ["Compute", "Storage", "Identity", "Network", "Secret"]
        all_categories = list(STANDARD_CATEGORIES)
        # Only add "Other" column if at least one detection actually fell there
        has_other = any(matrix[c]["Other"] > 0 for c in matrix)
        if has_other:
            all_categories.append("Other")

        # Flatten matrix to a list of {cloud, category, count} cells
        matrix_cells = []
        clouds_seen = sorted(matrix.keys())
        for cloud in clouds_seen:
            for cat in all_categories:
                matrix_cells.append(
                    {
                        "cloud": cloud,
                        "category": cat,
                        "count": matrix[cloud][cat],
                    }
                )

        # --- KPI block ---
        kpi = {
            "critical": severity_counts.get("Critical", 0),
            "high": severity_counts.get("High", 0),
            "medium": severity_counts.get("Medium", 0),
            "low": severity_counts.get("Low", 0),
            "total_paths": len(paths),
            "cross_cloud_paths": sum(1 for p in paths if p["breakdown"]["cross_cloud"]),
        }

        # --- Top tactics for the chart (ordered by MITRE kill-chain progression) ---
        TACTIC_ORDER_REF = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery",
            "Lateral Movement", "Collection", "Exfiltration", "Impact",
        ]
        tactic_series = [
            {"tactic": t, "count": tactic_counts.get(t, 0)}
            for t in TACTIC_ORDER_REF
            if tactic_counts.get(t, 0) > 0  # omit zero-count tactics
        ]

        result = {
            "status": "ok",
            "connected": connected,
            "kpi": kpi,
            "tactic_series": tactic_series,
            "matrix_cells": matrix_cells,
            "clouds": clouds_seen,
            "categories": all_categories,
            "other_node_types": sorted(other_node_types),
            "paths": paths,
            "detection_count": len(detections),
            "scanned_at": int(time.time()),
        }

        # Cache the result so /dashboard-cache can serve it on page reloads
        # without re-running the engine. Keyed by tenant so users see
        # only their own cached scan.
        LAST_DASHBOARD[tenant_id] = result
        LAST_DASHBOARD_TIMESTAMP[tenant_id] = result["scanned_at"]

        return result
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if driver is not None:
            driver.close()


def _check_aws_live_credentials():
    """Test whether AWS credentials are valid and reachable RIGHT NOW.

    Calls STS get-caller-identity (a free, instantaneous call) using the
    same credential chain Cartography/Prowler would use. Returns a tuple
    (ok, identity_or_error) where ok is True if credentials work.
    """
    if not os.environ.get("AWS_ACCESS_KEY_ID"):
        return False, "no AWS credentials in environment"
    try:
        import boto3
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        return True, identity.get("Arn", "unknown")
    except Exception as e:
        return False, str(e)[:120]  # truncate long boto error messages


def _check_gcp_live_credentials():
    """Test whether GCP service account credentials are valid RIGHT NOW.

    Loads the service account JSON pointed to by GOOGLE_APPLICATION_CREDENTIALS
    and asks Google for an access token. Returns (ok, email_or_error).
    """
    path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    if not path:
        return False, "GOOGLE_APPLICATION_CREDENTIALS not set"
    if not os.path.exists(path):
        return False, f"key file not found: {path}"
    try:
        from google.oauth2 import service_account
        import google.auth.transport.requests
        creds = service_account.Credentials.from_service_account_file(
            path, scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        # Refresh forces an actual API call to Google's auth server, which
        # would fail if the key is revoked or the SA was deleted.
        creds.refresh(google.auth.transport.requests.Request())
        return True, creds.service_account_email
    except Exception as e:
        return False, str(e)[:120]


@app.route("/connection-status")
@login_required
def connection_status():
    """Report cloud status for the connect page and dashboard banners.

    Returns TWO independent signals per cloud:
      - data_ingested: does Neo4j contain data from this cloud? (cheap check)
      - credentials_live: can we currently authenticate to this cloud? (slow check)
    """
    driver = None
    tenant_id = current_user.id
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session() as session:
            aws_row = session.run(
                "MATCH (a:AWSAccount {tenant_id: $tid}) RETURN a.id AS id LIMIT 1",
                tid=tenant_id,
            ).single()
            gcp_row = session.run(
                "MATCH (p:GCPProject {tenant_id: $tid}) RETURN p.id AS id LIMIT 1",
                tid=tenant_id,
            ).single()

        # Live-credential checks. These can take 1-2 seconds each.
        aws_live_ok, aws_live_detail = _check_aws_live_credentials()
        gcp_live_ok, gcp_live_detail = _check_gcp_live_credentials()

        # 'connected' kept for backwards compatibility with existing UI code.
        # New fields data_ingested + credentials_live give the honest picture.
        return jsonify({
            "status": "ok",
            "aws": {
                "connected": aws_row is not None,            # legacy field
                "data_ingested": aws_row is not None,
                "credentials_live": aws_live_ok,
                "account_id": aws_row["id"] if aws_row else None,
                "credentials_detail": aws_live_detail,
            },
            "gcp": {
                "connected": gcp_row is not None,            # legacy field
                "data_ingested": gcp_row is not None,
                "credentials_live": gcp_live_ok,
                "project_id": gcp_row["id"] if gcp_row else None,
                "credentials_detail": gcp_live_detail,
            },
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if driver is not None:
            driver.close()


@app.route("/dashboard-cache")
@login_required
def dashboard_cache():
    """Return the LAST cached dashboard payload for the LOGGED-IN tenant,
    WITHOUT running a new scan.
    """
    cached = LAST_DASHBOARD.get(current_user.id)
    if cached is None:
        return jsonify({"status": "empty"})
    return jsonify(cached)


# ============================================================
# Full pipeline (Cartography + ingestors + Prowler + detection)
# ============================================================

# Definition of the full pipeline. Each entry is (step_name, command_args,
# description). The command_args is a list passed to subprocess.run() so we
# avoid shell injection.
def build_pipeline_steps(ctx, tenant_id):
    """Build the list of (step_name, cmd, description) tuples for one
    scan, based on which clouds the user has credentials for.
    """
    steps = []
    if ctx.aws_present:
        aws_syncs = ",".join([
            # Identity + access (required for all chains)
            "iam", "iaminstanceprofiles", "permission_relationships",
            # Compute (T1078 overprivileged compute, T1190 public entry)
            "ec2:instance", "ec2:security_group",
            "ec2:vpc", "ec2:subnet",
            "ec2:network_interface",
            "ec2:internet_gateway", "ec2:route_table",
            "lambda_function",
            # Storage (T1530 public cloud storage)
            "s3", "s3accountpublicaccessblock",
            # Secrets + keys (T1552 cross-cloud credential)
            "secretsmanager", "kms",
        ])
        steps.append((
            "cartography_aws",
            ["cartography",
             "--neo4j-uri", NEO4J_URI,
             "--neo4j-user", NEO4J_USER,
             "--neo4j-password-env-var", "NEO4J_PASSWORD",
             "--selected-modules", "aws",
             "--aws-requested-syncs", aws_syncs,
             "--aws-best-effort-mode",
             "--permission-relationships-file", "permission_relationships.yaml"],
            "Ingest AWS via Cartography (best-effort mode)",
        ))
        steps.append((
            "aws_secret_ingest",
            [sys.executable, "aws_secret_ingest.py"],
            "Ingest AWS Secrets (focused)",
        ))
    if ctx.gcp_present:
        steps.append((
            "gcp_ingest_full",
            [sys.executable, "gcp_ingest_full.py", "--skip-optional"],
            "Ingest GCP via custom ingestor",
        ))
    if ctx.aws_present:
        steps.append((
            "prowler_aws",
            ["prowler", "aws",
             "--output-formats", "json-ocsf",
             "--output-directory", "prowler-output",
             "--status", "FAIL"],
            "Run Prowler AWS compliance scan",
        ))
    if ctx.gcp_present and ctx.gcp_project_id:
        steps.append((
            "prowler_gcp",
            ["prowler", "gcp",
             "--project-id", ctx.gcp_project_id,   # from user's saved cred
             "--output-formats", "json-ocsf",
             "--output-directory", "prowler-output",
             "--status", "FAIL"],
            "Run Prowler GCP compliance scan",
        ))
    steps.append((
        "merge_findings",
        [sys.executable, "merge_findings.py", "--tenant-id", str(tenant_id)],
        "Merge Prowler findings into Neo4j (tenant-scoped)",
    ))
    return steps

# Hard cap per step. Cartography in particular can take a long time when
# scanning all regions (18+ regions × 30+ services). 90 minutes is a
# defensive upper bound: in practice Cartography on a small account
# completes in 30-60 minutes, but Redshift opt-in crashes can add backoff
# delays. The pipeline continues to the next step after timeout (F2 mode).
STEP_TIMEOUT_SECONDS = 5400  # 90 minutes


def _check_aws_creds_present():
    """Quick check: are AWS credential env vars present?

    NOTE: this only checks env-var presence, NOT validity. For a real
    credential test (which catches expired STS tokens) use
    _check_aws_live_credentials() in /connection-status.
    """
    return bool(os.environ.get("AWS_ACCESS_KEY_ID"))


def _check_gcp_creds_present():
    """Quick check: does the GCP key file env var point to an existing file?
    """
    p = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    return bool(p) and os.path.exists(p)


@app.route("/env-status")
@login_required
def env_status():
    """Quick credential-status check for the dashboard tick indicators.
    """
    aws_live_ok, aws_live_detail = _check_aws_live_credentials()
    gcp_live_ok, gcp_live_detail = _check_gcp_live_credentials()
    return jsonify({
        "status": "ok",
        "aws_creds_loaded": _check_aws_creds_present(),    # legacy field
        "gcp_creds_loaded": _check_gcp_creds_present(),    # legacy field
        "aws_creds_live": aws_live_ok,
        "gcp_creds_live": gcp_live_ok,
        "aws_detail": aws_live_detail,
        "gcp_detail": gcp_live_detail,
        "neo4j_password_set": bool(NEO4J_PASSWORD),
    })


def _run_pipeline_thread(job_id, user_id):
    """Background-thread worker that runs the full pipeline for one user.
    """
    global PIPELINE_JOB
    try:
        with scan_credentials_for_user(user_id) as ctx:
            if not (ctx.aws_present or ctx.gcp_present):
                PIPELINE_JOB["status"] = "failed"
                PIPELINE_JOB["error"] = (
                    "No cloud credentials configured for this user. "
                    "Visit the Connect page to save AWS and/or GCP credentials, "
                    "then try again."
                )
                PIPELINE_JOB["finished_at"] = int(time.time())
                return

            if ctx.errors:
                PIPELINE_JOB.setdefault("warnings", []).extend(ctx.errors)

            # PHASE 6 — capture scan-start time fence BEFORE any ingest
            # runs. Cartography stamps lastupdated = timestamp() (ms
            # since epoch) on every MERGE; we compare against this.
            scan_started_ms = scan_start_timestamp_ms()
            PIPELINE_JOB["scan_started_ms"] = scan_started_ms

            steps = build_pipeline_steps(ctx, user_id)
            for step_name, cmd, description in steps:
                PIPELINE_JOB["current_step"] = step_name
                step_record = {
                    "name": step_name,
                    "description": description,
                    "status": "running",
                    "returncode": None,
                    "error": None,
                }
                PIPELINE_JOB["steps"].append(step_record)

                try:
                    # Route subprocess stdout/stderr to temp files instead
                    # of PIPE. This is the real fix for rich's
                    # `term.write(join_cells(fragment))` crash on Windows
                    # when Prowler/Cartography try to detect terminal size
                    # against a subprocess.PIPE (which has none).
                    import tempfile
                    stdout_file = tempfile.NamedTemporaryFile(
                        mode="w+", delete=False, suffix=".stdout.log",
                        encoding="utf-8", errors="replace",
                    )
                    stderr_file = tempfile.NamedTemporaryFile(
                        mode="w+", delete=False, suffix=".stderr.log",
                        encoding="utf-8", errors="replace",
                    )
                    try:
                        proc = subprocess.run(
                            cmd,
                            stdout=stdout_file,
                            stderr=stderr_file,
                            timeout=STEP_TIMEOUT_SECONDS,
                            env=ctx.env,
                        )
                        # Read the outputs back for logging/error reporting
                        stdout_file.seek(0)
                        stderr_file.seek(0)
                        stdout_text = stdout_file.read()
                        stderr_text = stderr_file.read()
                    finally:
                        stdout_file.close()
                        stderr_file.close()
                        try:
                            os.unlink(stdout_file.name)
                            os.unlink(stderr_file.name)
                        except OSError:
                            pass

                    step_record["returncode"] = proc.returncode
                    # Prowler returns non-zero exit codes to signal scan
                    # results, not error conditions:
                    #   0 = scan complete, no findings
                    #   3 = scan complete, findings exist 
                    # See: https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/miscellaneous/#exit-codes
                    prowler_success_codes = {0, 3}
                    is_prowler_step = step_name.startswith("prowler_")
                    if proc.returncode == 0 or (is_prowler_step and proc.returncode in prowler_success_codes):
                        step_record["status"] = "ok"
                        if proc.returncode != 0:
                            # Log the non-zero exit but keep status ok.
                            step_record["note"] = f"exit code {proc.returncode} (findings present)"
                    else:
                        step_record["status"] = "failed"
                        stderr_tail = (stderr_text or "").strip().splitlines()[-5:]
                        step_record["error"] = " | ".join(stderr_tail) or "non-zero exit"
                        # DEBUG: also persist full stdout+stderr to a
                        # named log file so we can inspect the real
                        # traceback (the tail-only error above is often
                        # useless — e.g. `return func(*args, **kwargs)`).
                        try:
                            debug_dir = os.path.join(
                                os.path.dirname(os.path.abspath(__file__)),
                                "pipeline_errors",
                            )
                            os.makedirs(debug_dir, exist_ok=True)
                            debug_path = os.path.join(
                                debug_dir,
                                f"{step_name}_{int(time.time())}.log",
                            )
                            with open(debug_path, "w", encoding="utf-8", errors="replace") as fh:
                                fh.write(f"=== STEP: {step_name} ===\n")
                                fh.write(f"=== CMD: {cmd} ===\n")
                                fh.write(f"=== RETURNCODE: {proc.returncode} ===\n\n")
                                fh.write("=== STDOUT ===\n")
                                fh.write(stdout_text or "(empty)")
                                fh.write("\n\n=== STDERR ===\n")
                                fh.write(stderr_text or "(empty)")
                            step_record["debug_log"] = debug_path
                            print(f"[pipeline] FAILED step '{step_name}' — full log at: {debug_path}")
                        except Exception as _e:
                            print(f"[pipeline] could not persist debug log: {_e}")
                except subprocess.TimeoutExpired:
                    step_record["status"] = "timeout"
                    step_record["error"] = f"exceeded {STEP_TIMEOUT_SECONDS}s hard timeout"
                except FileNotFoundError as e:
                    step_record["status"] = "not_found"
                    step_record["error"] = f"executable not found: {e}"
                except Exception as e:
                    step_record["status"] = "error"
                    step_record["error"] = str(e)
                # F2 — continue regardless of failure

            # PHASE 6 — tag every node touched by this scan with the
            # user's tenant_id. This runs even if some ingestion steps
            # failed; partially-ingested data still belongs to this
            # tenant. Failures here are reported as a warning but
            # don't fail the job.
            PIPELINE_JOB["current_step"] = "tenant_tag"
            try:
                tag_summary = tag_tenant_nodes(user_id, scan_started_ms)
                PIPELINE_JOB["tenant_tag_summary"] = tag_summary
            except Exception as e:
                PIPELINE_JOB.setdefault("warnings", []).append(
                    f"tenant tagging failed: {type(e).__name__}: {e}"
                )

            # Re-run detection to get the latest dashboard payload.
            # We call compute_dashboard_data(user_id) directly rather than
            # going through the /dashboard-data HTTP endpoint. This is
            # essential for background threads (scheduler) which have no
            # session context — current_user would be anonymous.
            PIPELINE_JOB["current_step"] = "engine_detection"
            PIPELINE_JOB["result"] = compute_dashboard_data(user_id)

            PIPELINE_JOB["status"] = "complete"
    except Exception as e:
        PIPELINE_JOB["status"] = "failed"
        PIPELINE_JOB["error"] = f"pipeline thread crashed: {e}"
    finally:
        PIPELINE_JOB["finished_at"] = int(time.time())
        PIPELINE_JOB["current_step"] = None

        # Record completion in scan_history if this scan was tracked.
        # The scheduler tracks its own scans separately, so we only do
        # this for runs that came through the manual /full-pipeline-scan
        # endpoint (which set PIPELINE_JOB["history_id"]).
        history_id = PIPELINE_JOB.get("history_id")
        if history_id is not None:
            try:
                import db as _db
                status_str = "success" if PIPELINE_JOB.get("status") == "complete" else "failure"
                error_msg = PIPELINE_JOB.get("error")
                result_payload = PIPELINE_JOB.get("result") or {}
                kpi = result_payload.get("kpi", {}) if isinstance(result_payload, dict) else {}
                summary = {
                    "paths_found":      kpi.get("total_paths"),
                    "critical_paths":   kpi.get("critical"),
                    "high_paths":       kpi.get("high"),
                    "medium_paths":     kpi.get("medium"),
                    "low_paths":        kpi.get("low"),
                    "detections_count": result_payload.get("detection_count") if isinstance(result_payload, dict) else None,
                }
                _db.record_scan_completed_sync(
                    history_id, status_str,
                    error_message=error_msg, summary=summary,
                )
            except Exception as _hist_err:
                print(f"[history] could not record manual scan completion: {_hist_err}")

        # ---- Webhook delivery (Max tier) ----------------------------
        # fire_scan_completed is a no-op for users with no active
        # webhooks (Free/Plus users don't register any, and Max users
        # with no webhooks configured don't either). Delivery is
        # async/threaded so this never blocks the pipeline.
        try:
            if PIPELINE_JOB.get("status") == "complete":
                _wh_result = PIPELINE_JOB.get("result") or {}
                _wh_scan_type = "scheduled" if str(
                    PIPELINE_JOB.get("job_id", "")
                ).startswith("sched-") else "manual"
                import webhook_sender
                webhook_sender.fire_scan_completed(
                    user_id, _wh_result, scan_type=_wh_scan_type,
                )
        except Exception as _wh_err:
            print(f"[webhook] outer guard caught: {_wh_err}", flush=True)
        # -------------------------------------------------------------

        try:
            PIPELINE_LOCK.release()
        except RuntimeError:
            pass


@app.route("/full-pipeline-scan", methods=["POST"])
@login_required
def full_pipeline_scan():
    """Start the full ingestion pipeline in a background thread, scoped
    to the logged-in user.

    Returns the job_id immediately so the browser can poll for status.
    If a pipeline is already running, returns the existing job_id (both
    browsers watch the same run rather than starting a duplicate).
    """
    global PIPELINE_JOB

    # Pre-flight: any credentials at all?
    from db import get_cloud_credentials_for_user_sync
    user_creds = get_cloud_credentials_for_user_sync(current_user.id)
    if not user_creds:
        return jsonify({
            "status": "no_credentials",
            "error": "No cloud credentials configured. "
                     "Save AWS or GCP credentials on the Connect page first.",
            "redirect_to": "/connect",
        }), 400

    if not PIPELINE_LOCK.acquire(blocking=False):
        return jsonify({
            "status": "already_running",
            "job_id": PIPELINE_JOB.get("job_id"),
            "message": "A pipeline is already running. Polling its status.",
        })

    job_id = uuid.uuid4().hex[:12]

    # Record this scan in scan_history (manual trigger). Best-effort:
    # if the insert fails we still launch the scan — history is an
    # audit trail, not a precondition.
    history_id = None
    try:
        import db as _db
        history_id = _db.record_scan_started_sync(current_user.id, "manual")
    except Exception as _hist_err:
        print(f"[history] could not record manual scan start: {_hist_err}")

    PIPELINE_JOB = {
        "job_id": job_id,
        "user_id": current_user.id,
        "history_id": history_id,
        "started_at": int(time.time()),
        "finished_at": None,
        "status": "running",
        "current_step": None,
        "steps": [],
        "result": None,
        "error": None,
    }
    thread = threading.Thread(
        target=_run_pipeline_thread,
        args=(job_id, current_user.id),
        daemon=True,
    )
    thread.start()
    return jsonify({"status": "started", "job_id": job_id})


@app.route("/pipeline-status/<job_id>")
@login_required
def pipeline_status(job_id):
    """Return the current state of a pipeline job.

    The frontend polls this every few seconds while a pipeline is running.
    Includes per-step status so the UI can show 'Cartography: ok',
    'Prowler GCP: running', etc. When status is 'complete', `result`
    contains the full dashboard payload ready for rendering.
    """
    if PIPELINE_JOB.get("job_id") != job_id:
        return jsonify({"status": "unknown_job"}), 404
    return jsonify(PIPELINE_JOB)


if __name__ == "__main__":
    # Ensure the tenant_id index exists in Neo4j. Idempotent — does
    # nothing if it already exists. Without the index, the post-pass
    # tagger does a full graph scan; with it, the tagger is fast.
    try:
        ensure_tenant_index()
    except Exception as e:
        print(f"[startup] tenant_id index check failed: {e}")
        print("[startup] continuing anyway; tagger will be slower")

    # Start the STS auto-refresh worker. Runs as a daemon thread inside
    # this Flask process. Refreshes any AWS credentials whose STS tokens
    # are within ~10 minutes of expiring, on a 5-minute cadence.
    # The worker is a no-op until at least one AWS credential exists in
    # the database.
    start_refresh_worker()

    # Start the scheduled-scans background thread. Wakes every 60s,
    # finds schedules whose next_run_at has passed, fires scans for
    # those users. Plus tier feature — see scheduler.py.
    from scheduler import start_scheduler
    start_scheduler(_run_pipeline_thread, PIPELINE_JOB)

    # threaded=True is essential: it lets Flask serve other requests
    # (page reloads, status polling) while a pipeline runs in the background.
    # Without this, the entire website freezes for the duration of the pipeline.
    app.run(debug=True, port=5000, threaded=True)