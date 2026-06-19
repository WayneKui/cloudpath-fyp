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
from flask import Flask, jsonify, render_template, request
from flask_login import login_required, current_user
from neo4j import GraphDatabase

from engine import get_attack_paths_json, load_rules, detect_all, link_cross_cloud_credentials
from auth import init_auth
from credentials import init_credentials
from refresh_worker import start_refresh_worker
from scan_credentials import scan_credentials_for_user
from tenant_scope import (
    scan_start_timestamp_ms, ensure_tenant_index, tag_tenant_nodes,
)


NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "YourPassword123")


app = Flask(__name__)

# Initialize authentication: registers the auth blueprint
# (/login, /register, /logout, /api/auth/status) and the flask-login
# session machinery. Must happen before any @login_required route is
# accessed.
init_auth(app)

# Initialize credentials API: registers /api/credentials/* and
# /api/test-connection/* endpoints. Must run after init_auth.
init_credentials(app)

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

    Phase 7: every Neo4j query is scoped to current_user.id so the
    dashboard reflects only this tenant's resources and findings.
    """
    driver = None
    tenant_id = current_user.id
    try:
        rules = load_rules()
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

        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if driver is not None:
            driver.close()


def _check_aws_live_credentials():
    """Test whether AWS credentials are valid and reachable RIGHT NOW.

    Calls STS get-caller-identity (a free, instantaneous call) using the
    same credential chain Cartography/Prowler would use. Returns a tuple
    (ok, identity_or_error) where ok is True if credentials work.

    This is more honest than just checking environment variables: env vars
    can be set but expired (STS tokens last 1 hour by default), in which
    case AWS API calls would fail even though the variables exist.

    Slow path (~1-2 sec) — called only on connect page load, not the
    dashboard, to keep dashboard cheap.
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

    Distinguishes between:
      - env var unset → no key configured
      - env var set but file missing → wrong path
      - file exists but invalid → expired/revoked key
      - file valid → all good
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

    This separation is important and viva-defensible:
      data_ingested=True alone means "we have historical data to show"
      credentials_live=True alone means "we can run a new ingestion right now"
      Both True = fully connected
      Only data_ingested = read-only mode (data persisted from prior session)
      Only credentials_live = first-run state, ready to ingest
      Neither = nothing connected
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

    Used by the dashboard page on initial load and reload. Each user has
    their own cache entry; user A never sees user B's cached scan.
    The detection engine is NOT called here. If this user hasn't scanned
    since the server started, returns {status: "empty"} so the page can
    show a clean empty state.

    This is what makes "open page = no scan, click Run Scan = scan" work.
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
# avoid shell injection. Steps run sequentially. F2 mode: if a step fails,
# the pipeline continues with the next step (see _run_pipeline_thread).
def build_pipeline_steps(ctx, tenant_id):
    """Build the list of (step_name, cmd, description) tuples for one
    scan, based on which clouds the user has credentials for.

    Phase 7: tenant_id is passed into merge_findings.py via CLI arg
    so finding-to-resource attachment is scoped to this tenant.

    Honest behavior:
      - AWS-related steps are only included if ctx.aws_present is True.
      - GCP-related steps are only included if ctx.gcp_present is True.
      - merge_findings is always included (it reads JSON files from
        prowler-output/ and writes Finding nodes to Neo4j scoped to
        this tenant; harmless to run with no JSON files present).
    """
    steps = []
    if ctx.aws_present:
        steps.append((
            "cartography_aws",
            ["cartography",
             "--neo4j-uri", NEO4J_URI,
             "--neo4j-user", NEO4J_USER,
             "--neo4j-password-env-var", "NEO4J_PASSWORD",
             "--selected-modules", "aws"],
            "Ingest AWS via Cartography (all regions)",
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

    Like _check_aws_creds_present, this is structural only and doesn't
    verify the key is still valid with Google. Use _check_gcp_live_credentials
    for that.
    """
    p = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
    return bool(p) and os.path.exists(p)


@app.route("/env-status")
@login_required
def env_status():
    """Quick credential-status check for the dashboard tick indicators.

    Reports two levels for each cloud:
      - present: env vars are set / key file exists (instant check)
      - live: credentials work against the cloud API right now (slower)

    The dashboard's tick pills next to the full-pipeline checkbox use the
    `live` field so the user knows whether the pipeline will actually
    succeed before clicking, rather than discovering an auth error 5
    minutes into a Cartography run.
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

    Each step is executed via subprocess.run with a hard timeout. Failures
    are recorded but do NOT abort the pipeline (F2: continue-on-error).
    After all steps complete, detection is re-run and the result is stored
    in PIPELINE_JOB['result'] for the frontend to consume.

    Credentials handling (Phase 5):
      - We open a scan_credentials_for_user(user_id) context.
      - The context inline-refreshes AWS STS tokens if they're near expiry.
      - The context writes the GCP service-account JSON to a temp file
        and points GOOGLE_APPLICATION_CREDENTIALS at it.
      - Each subprocess receives ctx.env (a per-user env dict). We DO NOT
        modify os.environ globally, so two concurrent scans for two
        different users do not interfere.
      - The temp GCP file is securely deleted on context exit.

    Tenant tagging (Phase 6):
      - We capture scan_started_ms BEFORE the first ingestion subprocess
        runs. All Cartography and custom-ingestor MERGE statements set
        n.lastupdated = timestamp(), so any node with
        lastupdated >= scan_started_ms was created or updated during
        this scan.
      - AFTER all subprocesses finish, we call tag_tenant_nodes(user_id,
        scan_started_ms). This stamps tenant_id on every node touched
        by this scan that doesn't already have one — guaranteeing
        ownership without overwriting prior tenants.
      - PIPELINE_LOCK serialises scans so no two run concurrently;
        the time-fence approach is correct under that lock.
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
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=STEP_TIMEOUT_SECONDS,
                        env=ctx.env,   # per-user credentials, not os.environ
                    )
                    step_record["returncode"] = proc.returncode
                    if proc.returncode == 0:
                        step_record["status"] = "ok"
                    else:
                        step_record["status"] = "failed"
                        stderr_tail = (proc.stderr or "").strip().splitlines()[-5:]
                        step_record["error"] = " | ".join(stderr_tail) or "non-zero exit"
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

            # Re-run detection to get the latest dashboard payload
            PIPELINE_JOB["current_step"] = "engine_detection"
            with app.test_request_context("/dashboard-data"):
                response = dashboard_data()
                if hasattr(response, "get_json"):
                    PIPELINE_JOB["result"] = response.get_json()
                else:
                    PIPELINE_JOB["result"] = response[0].get_json() if isinstance(response, tuple) else None

            PIPELINE_JOB["status"] = "complete"
    except Exception as e:
        PIPELINE_JOB["status"] = "failed"
        PIPELINE_JOB["error"] = f"pipeline thread crashed: {e}"
    finally:
        PIPELINE_JOB["finished_at"] = int(time.time())
        PIPELINE_JOB["current_step"] = None
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

    Phase 5 changes:
      - Pre-flight check: if the user has NO saved credentials, return
        a 400 with redirect_to=/connect so the UI can guide them.
        Better UX than letting the pipeline start and immediately fail.
      - The user_id is passed into the pipeline thread, which loads
        per-user credentials inside scan_credentials_for_user().
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
    PIPELINE_JOB = {
        "job_id": job_id,
        "user_id": current_user.id,
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

    # threaded=True is essential: it lets Flask serve other requests
    # (page reloads, status polling) while a pipeline runs in the background.
    # Without this, the entire website freezes for the duration of the pipeline.
    app.run(debug=True, port=5000, threaded=True)