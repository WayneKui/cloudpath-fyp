"""Webhook delivery for Max tier customers.

Fire-and-forget POSTs to customer-registered URLs when interesting
events happen (currently: scan.completed, finding.critical). Each
delivery is signed with HMAC-SHA256 using the per-webhook secret so
the receiver can verify authenticity.

Design notes:
- Delivery runs in a background thread. We never block the caller
  (typically the pipeline finally block) on network I/O.
- No retry queue. If a POST fails we bump failure_count in the DB;
  after a threshold we mark the webhook inactive. A production
  implementation would use a queue (SQS, Celery) with exponential
  backoff; for the FYP demo the failure_count field is enough.
- Signature scheme mirrors GitHub / Stripe conventions: a
  `X-CloudPath-Signature` header of the form `sha256=<hex>` where
  <hex> is HMAC-SHA256(secret, raw_body_bytes).
- We include an idempotency-friendly event_id (UUID) so receivers
  can deduplicate if we ever add retries later.

Verification example (for docs / SDK use):

    import hmac, hashlib
    def verify(body_bytes, header_sig, secret):
        expected = "sha256=" + hmac.new(
            secret.encode(), body_bytes, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, header_sig)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
import uuid
from typing import Any

import requests

logger = logging.getLogger(__name__)

# After this many consecutive failures we auto-disable the webhook.
# Reset to 0 on any success. Chosen to survive brief customer outages
# but stop hammering permanently-broken URLs.
AUTO_DISABLE_THRESHOLD = 10

REQUEST_TIMEOUT_SECONDS = 10


def _sign(body_bytes: bytes, secret: str) -> str:
    """Compute the `X-CloudPath-Signature` header value."""
    mac = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _deliver_one(webhook: dict, event: str, payload: dict) -> None:
    """Best-effort POST to a single webhook URL. Records outcome in
    the DB via record_webhook_delivery_sync. Never raises."""
    # Local import to avoid a circular dep at module load
    import db

    event_id = str(uuid.uuid4())
    envelope = {
        "event":      event,
        "event_id":   event_id,
        "created_at": int(time.time()),
        "data":       payload,
    }
    body_bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type":            "application/json",
        "User-Agent":              "CloudPath-Webhook/1.0",
        "X-CloudPath-Event":       event,
        "X-CloudPath-Event-Id":    event_id,
        "X-CloudPath-Signature":   _sign(body_bytes, webhook["secret"]),
    }

    success = False
    error_text: str | None = None
    try:
        resp = requests.post(
            webhook["url"], data=body_bytes, headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if 200 <= resp.status_code < 300:
            success = True
        else:
            error_text = f"HTTP {resp.status_code}: {resp.text[:200]}"
    except requests.RequestException as e:
        error_text = f"network error: {e}"
    except Exception as e:
        error_text = f"unexpected: {e}"

    try:
        db.record_webhook_delivery_sync(
            webhook["id"], success=success, error=error_text,
        )
    except Exception as e:
        # Metrics update is best-effort; don't crash the thread on it
        logger.warning("could not record webhook outcome: %s", e)

    if success:
        print(
            f"[webhook] delivered {event} to hook {webhook['id']} "
            f"(url={webhook['url']})",
            flush=True,
        )
    else:
        print(
            f"[webhook] FAILED {event} to hook {webhook['id']} "
            f"(url={webhook['url']}): {error_text}",
            flush=True,
        )


def _fire_thread(user_id: int, event: str, payload: dict) -> None:
    """Background thread body: look up matching webhooks and deliver."""
    try:
        import db
        hooks = db.get_active_webhooks_for_user_sync(user_id, event)
    except Exception as e:
        print(f"[webhook] could not load webhooks for user {user_id}: {e}", flush=True)
        return
    if not hooks:
        return
    for hook in hooks:
        _deliver_one(hook, event, payload)


def fire_event(user_id: int, event: str, payload: dict) -> None:
    """Public API: schedule webhook delivery for `event` to all of a
    user's matching, active webhooks. Non-blocking — returns immediately
    while a background thread handles the network I/O.

    Args:
        user_id: CloudPath user id
        event: event name, e.g. "scan.completed"
        payload: JSON-serialisable dict; goes under `data` in envelope
    """
    if not isinstance(payload, dict):
        payload = {"value": payload}
    try:
        t = threading.Thread(
            target=_fire_thread,
            args=(user_id, event, payload),
            daemon=True,
            name=f"webhook-{event}-{user_id}",
        )
        t.start()
    except Exception as e:
        print(f"[webhook] could not spawn delivery thread: {e}", flush=True)


def fire_scan_completed(user_id: int, result: dict, scan_type: str = "manual") -> None:
    """Convenience wrapper — fires `scan.completed` for any scan and
    additionally `finding.critical` if there are critical / high paths.
    Called from the pipeline finally block."""
    if not isinstance(result, dict):
        return
    kpi = result.get("kpi") if isinstance(result.get("kpi"), dict) else {}
    paths = result.get("paths") or []

    scan_payload = {
        "scan_type":       scan_type,
        "total_paths":     kpi.get("total_paths", 0),
        "critical":        kpi.get("critical", 0),
        "high":            kpi.get("high", 0),
        "medium":          kpi.get("medium", 0),
        "low":             kpi.get("low", 0),
        "detection_count": result.get("detection_count", 0),
        # Include a small preview of the attack paths so receivers
        # can act without a follow-up API call. Uses the engine's
        # actual path shape: id/score/severity + steps array.
        "paths_preview": [
            {
                "id":       p.get("id"),
                "severity": p.get("severity"),
                "score":    p.get("score"),
                "title":    " -> ".join(
                    s.get("mitre_name", "") for s in (p.get("steps") or [])
                ) or f"Attack path #{p.get('id')}",
                "hops":     len(p.get("steps") or []),
            } for p in paths[:5]
        ],
    }
    fire_event(user_id, "scan.completed", scan_payload)

    crit = int(kpi.get("critical", 0) or 0)
    high = int(kpi.get("high", 0) or 0)
    if (crit + high) > 0:
        fire_event(user_id, "finding.critical", {
            "critical_paths": crit,
            "high_paths":     high,
            "scan_type":      scan_type,
        })