"""
billing.py — LemonSqueezy subscription integration for CloudPath.

Responsibilities:
  1. POST /api/billing/create-checkout/<tier>
     Creates a LemonSqueezy hosted-checkout session for the requested tier
     and returns its URL. The user's id is embedded as `custom_data.user_id`
     so the webhook can identify which user paid.

  2. POST /api/billing/webhook
     Receives subscription lifecycle events from LemonSqueezy. Verifies
     the request signature (HMAC-SHA256 against the shared secret), then
     updates the user's tier accordingly.

  3. GET /api/billing/check-status
     Polled by the success page after checkout. Returns the user's current
     tier so the UI can detect when the webhook has finished updating it.

  4. GET /billing
     Renders the manage-subscription page (current plan + cancel button).

  5. GET /billing/success
     Renders the "processing..." page shown after the user returns from
     LemonSqueezy checkout.

Required environment variables (set in PowerShell or systemd):
  LEMONSQUEEZY_API_KEY        - Test mode API key from Lemon Squeezy dashboard
  LEMONSQUEEZY_WEBHOOK_SECRET - Shared secret you set when creating the webhook
  LEMONSQUEEZY_STORE_ID       - Your store ID (418766 for this project)
"""
import os
import json
import hmac
import hashlib
import time
import logging
from urllib.parse import urlencode

import requests
from flask import (
    Blueprint, request, jsonify, render_template,
    redirect, url_for, abort,
)
from flask_login import login_required, current_user

import db


logger = logging.getLogger(__name__)
billing_bp = Blueprint("billing", __name__)


# ---------------------------------------------------------------------------
# Configuration loaded from env
# ---------------------------------------------------------------------------
LEMONSQUEEZY_API_KEY        = os.environ.get("LEMONSQUEEZY_API_KEY", "")
LEMONSQUEEZY_WEBHOOK_SECRET = os.environ.get("LEMONSQUEEZY_WEBHOOK_SECRET", "")
LEMONSQUEEZY_STORE_ID       = os.environ.get("LEMONSQUEEZY_STORE_ID", "")

# Map from CloudPath tier name -> LemonSqueezy variant ID.
# Variant IDs come from the LemonSqueezy dashboard (three-dot menu -> Copy ID
# on each product/variant). These values are for this account specifically.
TIER_TO_VARIANT = {
    "plus": "1841877",
    "max":  "1841906",
}

# Reverse lookup so the webhook handler can translate a variant ID back to
# our tier name. Built at import so a typo above fails immediately.
VARIANT_TO_TIER = {v: k for k, v in TIER_TO_VARIANT.items()}

# Base URL for LemonSqueezy API. Same for test mode and production —
# test-mode is determined by which API key you use, not which URL.
LS_API_BASE = "https://api.lemonsqueezy.com/v1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ls_headers():
    """Standard headers for LemonSqueezy API calls."""
    return {
        "Accept":        "application/vnd.api+json",
        "Content-Type":  "application/vnd.api+json",
        "Authorization": f"Bearer {LEMONSQUEEZY_API_KEY}",
    }


def _config_ok():
    """True if all 3 LemonSqueezy env vars are set; False otherwise.

    Used by every endpoint as a soft pre-check. Returning a friendly
    error here is more helpful than a 500 from a missing-env-var
    AttributeError further down.
    """
    return all([
        LEMONSQUEEZY_API_KEY,
        LEMONSQUEEZY_WEBHOOK_SECRET,
        LEMONSQUEEZY_STORE_ID,
    ])


# ===========================================================================
# 1. Create checkout session
# ===========================================================================
@billing_bp.route("/api/billing/create-checkout/<tier>", methods=["POST"])
@login_required
def create_checkout(tier):
    """Create a LemonSqueezy hosted-checkout session for the given tier.

    URL parameter `tier` is 'plus' or 'max'. We don't allow 'free' here —
    downgrading to free is handled through subscription cancellation, not
    a new checkout.
    """
    if not _config_ok():
        return jsonify({
            "status": "error",
            "message": (
                "Billing is not configured on the server. "
                "LEMONSQUEEZY_API_KEY / WEBHOOK_SECRET / STORE_ID env "
                "vars are required."
            ),
        }), 500

    if tier not in TIER_TO_VARIANT:
        return jsonify({
            "status": "error",
            "message": f"Unknown tier '{tier}'. Valid tiers: {list(TIER_TO_VARIANT)}",
        }), 400

    variant_id = TIER_TO_VARIANT[tier]
    user_id = current_user.id

    # Build the checkout request body. LemonSqueezy uses JSON:API format
    #   - store_id and variant_id identify what's being sold
    #   - checkout_data.email pre-fills the buyer's email
    #   - checkout_data.custom is OUR opaque payload — webhook returns it
    #     back to us, letting us match the payment to a user
    #   - product_options.redirect_url is where LS sends the user after
    #     checkout completes (our success page)
    body = {
        "data": {
            "type": "checkouts",
            "attributes": {
                "checkout_data": {
                    "email": current_user.email,
                    "custom": {
                        # Stringify user_id — LemonSqueezy returns custom
                        # as-is in the webhook, and webhook code reads it
                        # back as a string.
                        "user_id": str(user_id),
                        "tier":    tier,
                    },
                },
                "product_options": {
                    # After successful checkout, send the user back to our
                    # processing page where polling will detect tier change.
                    "redirect_url": url_for(
                        "billing.success_page", _external=True
                    ),
                    "receipt_button_text": "Return to CloudPath",
                    "receipt_link_url": url_for(
                        "billing.success_page", _external=True
                    ),
                },
                # Test mode flag — only applies when using a test API key.
                # Setting this on a live key is ignored.
                "test_mode": True,
            },
            "relationships": {
                "store": {
                    "data": {"type": "stores", "id": LEMONSQUEEZY_STORE_ID},
                },
                "variant": {
                    "data": {"type": "variants", "id": variant_id},
                },
            },
        }
    }

    try:
        resp = requests.post(
            f"{LS_API_BASE}/checkouts",
            headers=_ls_headers(),
            json=body,
            timeout=15,
        )
    except requests.RequestException as e:
        logger.exception("LemonSqueezy API request failed")
        return jsonify({
            "status": "error",
            "message": f"Could not reach LemonSqueezy: {e}",
        }), 502

    if resp.status_code >= 400:
        # Return the LemonSqueezy error body verbatim — usually it's
        # JSON:API formatted and tells you exactly what's wrong.
        try:
            err = resp.json()
        except ValueError:
            err = {"raw": resp.text}
        logger.error("LemonSqueezy returned %d: %s", resp.status_code, err)
        return jsonify({
            "status": "error",
            "message": (
                f"LemonSqueezy rejected the checkout (HTTP {resp.status_code}). "
                "Check server logs for details."
            ),
            "lemonsqueezy_error": err,
        }), 502

    data = resp.json()
    checkout_url = data.get("data", {}).get("attributes", {}).get("url")
    if not checkout_url:
        logger.error("LemonSqueezy response missing checkout URL: %s", data)
        return jsonify({
            "status": "error",
            "message": "LemonSqueezy returned an unexpected response.",
        }), 502

    logger.info(
        "Created LemonSqueezy checkout for user %s, tier %s",
        user_id, tier,
    )
    return jsonify({
        "status":       "ok",
        "checkout_url": checkout_url,
        "tier":         tier,
    })


# ===========================================================================
# 2. Webhook receiver
# ===========================================================================
@billing_bp.route("/api/billing/webhook", methods=["POST"])
def webhook():
    """Receive subscription lifecycle events from LemonSqueezy.

    LemonSqueezy signs each request with HMAC-SHA256 using a secret we
    chose when creating the webhook. We verify the signature before
    trusting any data — without this check anyone could POST a fake
    "subscription_created" and get themselves upgraded for free.

    Events we handle:
      subscription_created   -> upgrade user to the new tier
      subscription_updated   -> tier change (plus->max or similar)
      subscription_cancelled -> downgrade to free
      subscription_resumed   -> re-enable previously cancelled subscription
      subscription_expired   -> same as cancelled (paid period ended)
    """
    if not _config_ok():
        return jsonify({"status": "error", "message": "Billing not configured"}), 500

    # ---- Signature verification (mandatory) ----
    signature = request.headers.get("X-Signature", "")
    body_bytes = request.get_data()
    expected = hmac.new(
        LEMONSQUEEZY_WEBHOOK_SECRET.encode("utf-8"),
        body_bytes,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signature):
        logger.warning(
            "Webhook signature mismatch. "
            "Got %s..., expected %s...",
            signature[:8], expected[:8],
        )
        return jsonify({"status": "error", "message": "Invalid signature"}), 401

    # ---- Parse payload ----
    try:
        payload = json.loads(body_bytes)
    except json.JSONDecodeError:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    event_name = payload.get("meta", {}).get("event_name", "")
    custom = payload.get("meta", {}).get("custom_data", {}) or {}
    attributes = payload.get("data", {}).get("attributes", {}) or {}
    subscription_id = str(payload.get("data", {}).get("id", "") or "")
    customer_id = str(attributes.get("customer_id", "") or "")
    variant_id = str(attributes.get("variant_id", "") or "")

    logger.info(
        "Webhook received: event=%s subscription_id=%s customer_id=%s variant_id=%s",
        event_name, subscription_id, customer_id, variant_id,
    )

    # Find the user. Two strategies:
    #   1. custom_data.user_id (set during checkout) — most reliable for the
    #      first event (subscription_created).
    #   2. lemonsqueezy_subscription_id lookup — for follow-up events
    #      (updated, cancelled) where custom_data may be absent.
    user_id = None
    if custom.get("user_id"):
        try:
            user_id = int(custom["user_id"])
        except (TypeError, ValueError):
            user_id = None

    if user_id is None and subscription_id:
        user_row = db.get_user_by_subscription_id_sync(subscription_id)
        if user_row:
            user_id = user_row["id"]

    if user_id is None and customer_id:
        user_row = db.get_user_by_customer_id_sync(customer_id)
        if user_row:
            user_id = user_row["id"]

    if user_id is None:
        logger.error(
            "Cannot match webhook %s to any user. "
            "subscription_id=%s customer_id=%s custom=%s",
            event_name, subscription_id, customer_id, custom,
        )
        # Acknowledge with 200 anyway — returning error would make
        # LemonSqueezy retry forever for a fundamentally unrouteable event.
        return jsonify({
            "status": "ignored",
            "reason": "no matching user",
        }), 200

    # ---- Dispatch on event_name ----
    if event_name in ("subscription_created", "subscription_updated",
                      "subscription_resumed"):
        tier = VARIANT_TO_TIER.get(variant_id)
        if tier is None:
            logger.error(
                "Unknown variant_id %s in webhook for user %s",
                variant_id, user_id,
            )
            return jsonify({
                "status": "ignored",
                "reason": "unknown variant",
            }), 200
        db.update_user_subscription_sync(
            user_id=user_id,
            tier=tier,
            customer_id=customer_id or None,
            subscription_id=subscription_id or None,
        )
        logger.info(
            "User %s upgraded to %s (subscription %s)",
            user_id, tier, subscription_id,
        )

    elif event_name == "subscription_cancelled":
        # User clicked Cancel. Subscription is "cancelled" in LemonSqueezy
        # terms — they won't be billed next cycle — but they still have
        # paid access until the end of their current billing period.
        # We do NOT downgrade them here. The actual downgrade fires later
        # via the `subscription_expired` event at period end.
        #
        # We still log + return 200 to acknowledge the event.
        logger.info(
            "User %s cancelled subscription %s (access continues until period end)",
            user_id, subscription_id,
        )

    elif event_name == "subscription_expired":
        # Period ended; actually downgrade to free now.
        # Keep customer_id for future re-subscribe convenience,
        # but clear subscription_id since it's no longer active.
        db.update_user_subscription_sync(
            user_id=user_id,
            tier="free",
            customer_id=customer_id or None,
            subscription_id=None,
        )
        logger.info("User %s downgraded to free (subscription expired)", user_id)

    else:
        # Unhandled event — acknowledge but don't act
        logger.info("Webhook event %s acknowledged but not handled", event_name)

    return jsonify({"status": "ok", "event": event_name, "user_id": user_id}), 200


# ===========================================================================
# 3. Polling endpoint for success page
# ===========================================================================
@billing_bp.route("/api/billing/check-status")
@login_required
def check_status():
    """Return the current user's tier so the success page can detect when
    the webhook finishes updating the DB.

    Returns:
        {
          "status": "ok",
          "tier":   "plus" | "max" | "free",
          "subscription_id": "12345" or null
        }
    """
    user_row = db.get_user_by_id_sync(current_user.id)
    if not user_row:
        return jsonify({"status": "error", "message": "user not found"}), 404
    return jsonify({
        "status":          "ok",
        "tier":            user_row.get("subscription_tier", "free"),
        "subscription_id": user_row.get("lemonsqueezy_subscription_id"),
        "tier_updated_at": str(user_row.get("tier_updated_at", "")),
    })


# ===========================================================================
# 4. Manage subscription page
# ===========================================================================
@billing_bp.route("/billing")
@login_required
def billing_page():
    """Render the billing/manage page.

    Shows current tier plus, if there's an active subscription, the live
    state from LemonSqueezy (whether it's cancelled, when it ends/renews,
    payment card details).

    LemonSqueezy's customer portal would normally handle cancel/upgrade,
    but it requires store activation (live mode) which we haven't done.
    So we render our own controls and call the LemonSqueezy API directly
    for cancel/upgrade operations.
    """
    user_row = db.get_user_by_id_sync(current_user.id)
    tier = user_row.get("subscription_tier", "free")
    subscription_id = user_row.get("lemonsqueezy_subscription_id")
    customer_id = user_row.get("lemonsqueezy_customer_id")
    tier_updated_at = user_row.get("tier_updated_at")

    # Fetch live subscription state from LemonSqueezy. This gives us
    # the cancel-but-active-until-X information that the DB doesn't
    # store. Falls back gracefully if LemonSqueezy is unreachable.
    subscription_status = None
    if subscription_id:
        subscription_status = fetch_subscription_status(subscription_id)

    return render_template(
        "billing.html",
        tier=tier,
        subscription_id=subscription_id,
        customer_id=customer_id,
        tier_updated_at=tier_updated_at,
        subscription_status=subscription_status,
    )


# ===========================================================================
# 5. Success page (redirected to from LemonSqueezy after checkout)
# ===========================================================================
@billing_bp.route("/billing/success")
@login_required
def success_page():
    """Page the user lands on AFTER paying on LemonSqueezy.

    The webhook may not have arrived yet, so this page shows a 'Processing
    your subscription...' state and polls /api/billing/check-status until
    the tier changes from free to plus/max.
    """
    return render_template("billing_success.html")


# ===========================================================================
# 6. Cancel subscription
# ===========================================================================
@billing_bp.route("/api/billing/cancel-subscription", methods=["POST"])
@login_required
def cancel_subscription():
    """Cancel the user's active subscription.

    LemonSqueezy semantics: 'cancellation' means 'do not renew at next
    billing date'. The user retains paid access until the end of their
    current period. The DB tier is NOT changed here; it changes when the
    `subscription_expired` webhook arrives at period end.

    Idempotent: cancelling an already-cancelled subscription returns
    success (LemonSqueezy responds with the existing cancelled state).
    """
    if not _config_ok():
        return jsonify({
            "status": "error",
            "message": "Billing not configured",
        }), 500

    user_row = db.get_user_by_id_sync(current_user.id)
    if not user_row:
        return jsonify({"status": "error", "message": "User not found"}), 404

    subscription_id = user_row.get("lemonsqueezy_subscription_id")
    if not subscription_id:
        return jsonify({
            "status": "error",
            "message": "No active subscription to cancel",
        }), 400

    # Call LemonSqueezy DELETE /subscriptions/{id}.
    # The response body confirms cancellation state. Per LemonSqueezy API:
    #   { data: { attributes: { cancelled: true,
    #                            renews_at: null,
    #                            ends_at: "2026-07-21T...Z" } } }
    try:
        resp = requests.delete(
            f"{LS_API_BASE}/subscriptions/{subscription_id}",
            headers=_ls_headers(),
            timeout=15,
        )
    except requests.RequestException as e:
        logger.exception("LemonSqueezy cancel API call failed")
        return jsonify({
            "status": "error",
            "message": f"Could not reach LemonSqueezy: {e}",
        }), 502

    if resp.status_code >= 400:
        try:
            err = resp.json()
        except ValueError:
            err = {"raw": resp.text}
        logger.error(
            "LemonSqueezy cancel returned %d: %s", resp.status_code, err,
        )
        return jsonify({
            "status": "error",
            "message": (
                f"LemonSqueezy rejected the cancellation "
                f"(HTTP {resp.status_code})."
            ),
            "lemonsqueezy_error": err,
        }), 502

    data = resp.json().get("data", {}).get("attributes", {})
    ends_at = data.get("ends_at")

    logger.info(
        "User %s cancelled subscription %s; ends_at=%s",
        current_user.id, subscription_id, ends_at,
    )

    return jsonify({
        "status": "ok",
        "message": "Subscription cancelled. Paid access continues until period end.",
        "ends_at": ends_at,
    })


def fetch_subscription_status(subscription_id):
    """Fetch live subscription status from LemonSqueezy.

    Used by the billing page to show whether the subscription is still
    active, cancelled-but-active-until-X, or fully ended. The DB only
    knows the tier — for the "cancelled but renewing on X" nuance we
    need to ask LemonSqueezy directly.

    Returns a dict with keys: status, cancelled, ends_at, renews_at,
    or None on failure (caller treats as "unknown, fall back to DB").
    """
    if not subscription_id or not _config_ok():
        return None
    try:
        resp = requests.get(
            f"{LS_API_BASE}/subscriptions/{subscription_id}",
            headers=_ls_headers(),
            timeout=10,
        )
        if resp.status_code != 200:
            logger.warning(
                "LemonSqueezy GET subscription returned %d",
                resp.status_code,
            )
            return None
        attrs = resp.json().get("data", {}).get("attributes", {})
        return {
            "status":     attrs.get("status"),
            "cancelled":  bool(attrs.get("cancelled", False)),
            "ends_at":    attrs.get("ends_at"),
            "renews_at":  attrs.get("renews_at"),
            "card_brand": attrs.get("card_brand"),
            "card_last_four": attrs.get("card_last_four"),
        }
    except requests.RequestException:
        logger.exception("Failed to fetch subscription status")
        return None