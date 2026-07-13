"""REST API v1 for Max-tier customers.

Endpoints
---------
All under /api/v1/, authenticated via `Authorization: Bearer cpk_...`.
The bearer token is an API key issued from the /api-management page.

  GET  /api/v1/whoami                 - identity + tier check
  GET  /api/v1/scans                  - past scan runs (paginated)
  GET  /api/v1/scans/latest           - most recent scan
  GET  /api/v1/attack-paths           - current attack paths from Neo4j
  POST /api/v1/scans                  - trigger a new pipeline scan
  GET  /api/v1/exports/paths.csv      - attack paths as CSV
  GET  /api/v1/exports/paths.json     - attack paths as JSON

Auth model
----------
1. Client sends `Authorization: Bearer cpk_...`.
2. `require_api_key` decorator hashes the raw key and looks it up
   in the `api_keys` table.
3. Row must be non-revoked and belong to a user whose
   subscription_tier == 'max'. Anything else returns 401 or 403.
4. On success, `g.api_user = {id, email, tier}` is set for the handler.

Error format
------------
All errors return JSON of the form:
    { "error": { "code": "<slug>", "message": "<human-readable>" } }
"""
from __future__ import annotations

import csv
import io
import time
import uuid
import threading

from flask import Blueprint, jsonify, request, g, Response
from functools import wraps

import db

api_v1_bp = Blueprint("api_v1", __name__)


# ---------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------
def _err(code: str, message: str, status: int):
    """Uniform JSON error response."""
    return jsonify({"error": {"code": code, "message": message}}), status


def require_api_key(f):
    """Decorator: enforce Bearer API key auth AND Max tier."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "").strip()
        if not auth.lower().startswith("bearer "):
            return _err(
                "missing_auth",
                "Missing Authorization: Bearer <key> header.",
                401,
            )
        raw_key = auth.split(" ", 1)[1].strip()
        try:
            user_row = db.lookup_api_key_sync(raw_key)
        except Exception as e:
            return _err("auth_lookup_failed", str(e), 500)
        if not user_row:
            return _err(
                "invalid_key",
                "The API key is invalid or has been revoked.",
                401,
            )
        tier = (user_row.get("subscription_tier") or "free").lower()
        if tier != "max":
            return _err(
                "tier_required",
                f"REST API access requires the Max subscription tier. "
                f"Your current tier is {tier}.",
                403,
            )
        g.api_user = {
            "id":    user_row["user_id"],
            "email": user_row["email"],
            "tier":  tier,
            "key_id":   user_row["key_id"],
            "key_name": user_row["key_name"],
        }
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------
@api_v1_bp.route("/api/v1/whoami", methods=["GET"])
@require_api_key
def whoami():
    """Identity + tier smoke test. Useful for SDK bootstrapping."""
    return jsonify({
        "user_id":           g.api_user["id"],
        "email":             g.api_user["email"],
        "subscription_tier": g.api_user["tier"],
        "authenticated_via": {
            "key_id":   g.api_user["key_id"],
            "key_name": g.api_user["key_name"],
        },
    })


@api_v1_bp.route("/api/v1/scans", methods=["GET"])
@require_api_key
def list_scans():
    """List the caller's past scan runs (newest first)."""
    try:
        limit = min(int(request.args.get("limit", 20)), 100)
    except ValueError:
        limit = 20
    try:
        rows = db.get_user_scan_history_sync(g.api_user["id"], limit=limit)
    except Exception as e:
        return _err("db_error", str(e), 500)
    # Serialise datetimes
    out = []
    for r in rows:
        item = dict(r)
        for k in ("started_at", "completed_at"):
            v = item.get(k)
            if v is not None and hasattr(v, "isoformat"):
                item[k] = v.isoformat()
        out.append(item)
    return jsonify({"scans": out, "count": len(out)})


@api_v1_bp.route("/api/v1/scans/latest", methods=["GET"])
@require_api_key
def latest_scan():
    """Convenience: most recent scan for the caller."""
    try:
        rows = db.get_user_scan_history_sync(g.api_user["id"], limit=1)
    except Exception as e:
        return _err("db_error", str(e), 500)
    if not rows:
        return _err("not_found", "You have no scans on record.", 404)
    r = dict(rows[0])
    for k in ("started_at", "completed_at"):
        v = r.get(k)
        if v is not None and hasattr(v, "isoformat"):
            r[k] = v.isoformat()
    return jsonify(r)


@api_v1_bp.route("/api/v1/attack-paths", methods=["GET"])
@require_api_key
def list_attack_paths():
    """Return the caller's current attack paths from Neo4j. This is
    the same data as the dashboard graph, filtered to the calling
    user's tenant."""
    try:
        # Local import: engine has heavy imports (Neo4j driver)
        from engine import get_attack_paths_json
        paths = get_attack_paths_json(g.api_user["id"])
    except Exception as e:
        return _err("engine_error", str(e), 500)
    return jsonify({
        "attack_paths": paths,
        "count":        len(paths),
    })


@api_v1_bp.route("/api/v1/scans", methods=["POST"])
@require_api_key
def trigger_scan():
    """Trigger a new full-pipeline scan asynchronously. Returns
    202 with a job_id the caller can poll via /api/v1/scans/latest
    or the standard /pipeline-status/<job_id> endpoint."""
    try:
        # Local import: app.py has its own heavy dependencies
        import app as _app

        if not _app.PIPELINE_LOCK.acquire(blocking=False):
            return _err(
                "scan_already_running",
                "A scan is already in progress for this account.",
                409,
            )

        job_id = f"api-{uuid.uuid4().hex[:12]}"
        history_id = None
        try:
            history_id = db.record_scan_started_sync(
                g.api_user["id"], "api",
            )
        except Exception as e:
            print(f"[api_v1] could not record history for API scan: {e}", flush=True)

        # Rebind PIPELINE_JOB for the API-triggered run, same pattern
        # as the scheduler fix.
        _app.PIPELINE_JOB = {
            "job_id":       job_id,
            "user_id":      g.api_user["id"],
            "history_id":   history_id,
            "started_at":   int(time.time()),
            "finished_at":  None,
            "status":       "running",
            "current_step": None,
            "steps":        [],
            "result":       None,
            "error":        None,
        }
        t = threading.Thread(
            target=_app._run_pipeline_thread,
            args=(job_id, g.api_user["id"]),
            daemon=True,
            name=f"api-scan-{job_id}",
        )
        t.start()
    except Exception as e:
        return _err("scan_spawn_failed", str(e), 500)

    return jsonify({
        "status":       "accepted",
        "job_id":       job_id,
        "history_id":   history_id,
        "poll_url":     f"/pipeline-status/{job_id}",
        "message":      "Scan started. Poll for status.",
    }), 202


# ---------------------------------------------------------------------
# Compliance exports (attack paths as CSV / JSON)
# ---------------------------------------------------------------------
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value):
    """Neutralize CSV/formula injection.

    Excel/Sheets treat a cell starting with =, +, -, @ (or a leading
    tab/CR) as a formula. Node names/ids here ultimately come from
    cloud resources (bucket names, IAM principal names, etc.) which
    an attacker with write access to the target account could name
    e.g. "=cmd|'/c calc'!A1" — that would execute when an analyst
    opens the exported CSV. Prefixing with a single quote forces
    spreadsheet apps to render it as literal text instead.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _csv_safe_row(row: dict) -> dict:
    return {k: _csv_safe(v) for k, v in row.items()}


def _flatten_path_for_export(p: dict) -> dict:
    """Reduce a nested attack path dict to a flat row for CSV output.

    Column order matters here — this defines the CSV column order.
    A path in the engine has the shape:
      {"id":..., "score":..., "severity":..., "steps": [ {...}, ... ]}
    Each step has technique_id, mitre_name, tactic, cloud, node_type,
    node_id, severity, detail. We compact steps into pipe/arrow-joined
    strings so one row per path stays readable in Excel.
    """
    steps = p.get("steps") or []
    clouds = sorted({s.get("cloud", "unknown") for s in steps if s.get("cloud")})
    cloud_str = "+".join(clouds) if clouds else "unknown"
    entry_node = (
        f"{steps[0].get('node_type','')}:{steps[0].get('node_id','')}"
        if steps else ""
    )
    target_node = (
        f"{steps[-1].get('node_type','')}:{steps[-1].get('node_id','')}"
        if steps else ""
    )
    mitre_chain = " -> ".join(s.get("mitre_name", "") for s in steps)
    return {
        "id":              p.get("id"),
        "title":           mitre_chain or f"Attack path #{p.get('id')}",
        "severity":        p.get("severity"),
        "score":           p.get("score"),
        "cloud":           cloud_str,
        "hops":            len(steps),
        "tactic_chain":    " -> ".join(s.get("tactic", "") for s in steps),
        "technique_chain": " -> ".join(s.get("technique_id", "") for s in steps),
        "entry_node":      entry_node,
        "target_node":     target_node,
    }


@api_v1_bp.route("/api/v1/exports/paths.csv", methods=["GET"])
@require_api_key
def export_paths_csv():
    """Compliance-friendly CSV export of the caller's current attack
    paths. One row per path, plus a header row."""
    try:
        from engine import get_attack_paths_json
        paths = get_attack_paths_json(g.api_user["id"])
    except Exception as e:
        return _err("engine_error", str(e), 500)

    buf = io.StringIO()
    fields = ["id", "title", "severity", "score", "cloud", "hops",
              "tactic_chain", "technique_chain", "entry_node", "target_node"]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for p in paths:
        writer.writerow(_csv_safe_row(_flatten_path_for_export(p)))
    csv_body = buf.getvalue()
    filename = f"cloudpath-attack-paths-{int(time.time())}.csv"
    return Response(
        csv_body,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@api_v1_bp.route("/api/v1/exports/paths.json", methods=["GET"])
@require_api_key
def export_paths_json():
    """Full-fidelity JSON export — same shape as `list_attack_paths`
    but delivered as a downloadable file."""
    try:
        from engine import get_attack_paths_json
        paths = get_attack_paths_json(g.api_user["id"])
    except Exception as e:
        return _err("engine_error", str(e), 500)
    filename = f"cloudpath-attack-paths-{int(time.time())}.json"
    from flask import jsonify as _jsonify
    resp = _jsonify({
        "exported_at":  int(time.time()),
        "user_id":      g.api_user["id"],
        "attack_paths": paths,
        "count":        len(paths),
    })
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


# ---------------------------------------------------------------------
# Root discovery (no auth) — helpful for SDK bootstrapping
# ---------------------------------------------------------------------
@api_v1_bp.route("/api/v1/", methods=["GET"])
def api_root():
    return jsonify({
        "name":    "CloudPath API",
        "version": "v1",
        "auth":    "Bearer token (API key with 'cpk_' prefix)",
        "endpoints": [
            "GET  /api/v1/whoami",
            "GET  /api/v1/scans?limit=N",
            "GET  /api/v1/scans/latest",
            "POST /api/v1/scans",
            "GET  /api/v1/attack-paths",
            "GET  /api/v1/exports/paths.csv",
            "GET  /api/v1/exports/paths.json",
        ],
        "docs": "/docs",
    })