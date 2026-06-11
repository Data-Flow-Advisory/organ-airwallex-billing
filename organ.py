"""Airwallex Billing Webhook Decision Organ — pure organ per orchestrator CONTRACT.

This organ decides what a single inbound Airwallex billing webhook authorises:
whether to **process**, **reject** (bad signature → HTTP 401), or **skip** the
event; whether the signature was verified or the event is being processed on the
unverified fall-through path (and so a `security_review` audit row must be
recorded); and, for subscription lifecycle events, which tenant action the
caller should take (`activate` with a resolved plan / `cancel` / `none`).

It is the extracted decision core of discovery-engine's
``app/services/airwallex_billing.py::handle_webhook`` (plus its private helpers
``_verify_signature``, ``_resolve_plan_from_price`` and the
``_handle_subscription_*`` routers). That module mixes the decision with heavy
I/O — reading ``AIRWALLEX_WEBHOOK_SECRET`` / price-id env vars, writing
``PlatformEvent`` audit rows, querying ``Tenant`` by customer id and committing
plan changes to the DB. None of that belongs in a composable decision.

**The organ consumes the raw webhook (payload bytes/str + signature + timestamp)
plus the already-resolved config (secret + price→plan map) and returns the
decision; the caller performs the DB writes / audit the decision authorises.**

The HMAC-SHA256 verification is reproduced here verbatim — ``hmac`` and
``hashlib`` are stdlib, so the organ stays pure while remaining self-contained
and deterministic. The signing string is ``<timestamp><raw_payload>`` per the
Airwallex webhook spec.

Signature: decide(state: dict, context: dict) -> dict
Returns: {output, rationale, self_metric} with self_metric.confidence required.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, Optional

# Default plan used when an activation event carries a price_id we cannot map
# back to a configured plan. Mirrors ``_resolve_plan_from_price``'s fallback.
_DEFAULT_PLAN = "pro"

# Plan set on a subscription.cancelled event (mirrors
# ``_handle_subscription_cancelled`` which sets ``tenant.plan = 'free'``).
_CANCELLED_PLAN = "free"

# Event names that map to a concrete tenant lifecycle action.
_ACTIVATE_EVENTS = ("subscription.activated",)
_CANCEL_EVENTS = ("subscription.cancelled",)
# Payment confirmations are logged only — no tenant mutation in the source.
_PAYMENT_EVENTS = ("payment.succeeded", "payment_intent.succeeded")


def decide(state: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Decide how to handle an inbound Airwallex billing webhook.

    Args:
        state: The raw inbound webhook::

                {
                  "payload":   "<raw JSON body as str or bytes>"  # or...
                  "event":     {...},   # ...an already-parsed event dict
                  "signature": "<X-Signature header>",
                  "timestamp": "<X-Timestamp header>",
                }

            Provide EITHER ``payload`` (the raw body, which the organ parses
            and signature-verifies) OR a pre-parsed ``event`` dict. When
            ``event`` is given, signature verification is skipped (the caller
            asserts it already verified). Empty dict ``{}`` is valid
            (fail-safe → skip).
        context: Already-resolved billing config::

                {
                  "webhook_secret": "<AIRWALLEX_WEBHOOK_SECRET or ''>",
                  "price_ids": {"starter": "px_..", "pro": "px_..",
                                "enterprise": "px_.."},
                }

            All keys optional. An empty / missing ``webhook_secret`` selects
            the verified-but-disabled fall-through path (process the event but
            flag it for a security_review audit row).

    Returns:
        {
            "output": {
                "action":                 "process" | "reject" | "skip",
                "verified":               bool,   # signature matched
                "secret_configured":      bool,
                "record_unverified_audit":bool,   # caller must write the audit row
                "event_type":             str,    # '' when unparseable / skipped
                "event_id":               str | None,
                "customer_id":            str | None,
                "tenant_action":          "activate" | "cancel" | "none",
                "resolved_plan":          str | None,
                "http_status_hint":       int,    # 200 | 401 | 400
            },
            "rationale": str,
            "self_metric": {"confidence": 0.0-1.0},
        }
    """
    if not state:
        return {
            "output": _skip_output(),
            "rationale": "No webhook provided; nothing to process.",
            "self_metric": {"confidence": 0.3},
        }

    secret = _clean_str(context.get("webhook_secret")) or ""
    secret_configured = bool(secret)
    price_ids = context.get("price_ids") if isinstance(context.get("price_ids"), dict) else {}

    pre_parsed = state.get("event")
    raw_payload = state.get("payload")

    # --- Signature verification --------------------------------------------
    # Only meaningful when we have the raw payload AND a configured secret.
    # A pre-parsed ``event`` means the caller already verified.
    if pre_parsed is not None and isinstance(pre_parsed, dict):
        verified = True
        event: Optional[Dict[str, Any]] = pre_parsed
    else:
        signature = _clean_str(state.get("signature")) or ""
        timestamp = _clean_str(state.get("timestamp")) or ""
        verified = _verify_signature(raw_payload, signature, timestamp, secret)

        # Fail-closed: a configured secret with a missing/mismatched signature
        # is rejected (the route maps this to HTTP 401).
        if secret_configured and not verified:
            out = _skip_output()
            out["action"] = "reject"
            out["secret_configured"] = True
            out["verified"] = False
            out["http_status_hint"] = 401
            return {
                "output": out,
                "rationale": "Webhook secret is configured but the signature did "
                             "not verify; reject the event (HTTP 401) — do not "
                             "process an unauthenticated billing mutation.",
                "self_metric": {"confidence": 0.95},
            }

        event = _parse_payload(raw_payload)
        if event is None:
            out = _skip_output()
            out["action"] = "reject"
            out["secret_configured"] = secret_configured
            out["verified"] = verified
            out["http_status_hint"] = 400
            return {
                "output": out,
                "rationale": "Webhook payload is missing or not valid JSON; reject "
                             "with HTTP 400 (malformed request).",
                "self_metric": {"confidence": 0.85},
            }

    # --- Unverified fall-through path --------------------------------------
    # Secret not configured → process anyway (so the integration can be
    # exercised during rollout) but flag for a security_review audit row.
    record_unverified_audit = not secret_configured

    event_type = _clean_str(event.get("name")) or ""
    event_id = _clean_str(event.get("id"))
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    customer_id = _clean_str(data.get("customer_id"))

    tenant_action, resolved_plan = _route_event(event_type, data, price_ids)

    output = {
        "action": "process",
        "verified": verified,
        "secret_configured": secret_configured,
        "record_unverified_audit": record_unverified_audit,
        "event_type": event_type,
        "event_id": event_id,
        "customer_id": customer_id,
        "tenant_action": tenant_action,
        "resolved_plan": resolved_plan,
        "http_status_hint": 200,
    }

    rationale = _build_rationale(
        verified, secret_configured, event_type, tenant_action, resolved_plan
    )
    confidence = _compute_confidence(
        verified, secret_configured, event_type, tenant_action
    )

    return {
        "output": output,
        "rationale": rationale,
        "self_metric": {"confidence": confidence},
    }


# ---------------------------------------------------------------------------
# Helpers (all pure)
# ---------------------------------------------------------------------------

def _skip_output() -> Dict[str, Any]:
    """The 'do nothing' output shape (also the base for reject)."""
    return {
        "action": "skip",
        "verified": False,
        "secret_configured": False,
        "record_unverified_audit": False,
        "event_type": "",
        "event_id": None,
        "customer_id": None,
        "tenant_action": "none",
        "resolved_plan": None,
        "http_status_hint": 200,
    }


def _verify_signature(
    payload: Any, signature: str, timestamp: str, secret: str
) -> bool:
    """Constant-time HMAC-SHA256 check (mirrors ``_verify_signature``).

    The signing string is ``<timestamp><raw_payload>`` and the digest is the
    hex-encoded HMAC-SHA256 using the webhook secret as the key. Returns
    ``False`` when the secret/signature/timestamp are blank or the payload is
    not bytes/str.
    """
    if not secret or not signature or not timestamp:
        return False
    if isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        payload_bytes = bytes(payload)
    else:
        return False

    signing_string = timestamp.encode("utf-8") + payload_bytes
    expected = hmac.new(
        secret.encode("utf-8"),
        signing_string,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _parse_payload(payload: Any) -> Optional[Dict[str, Any]]:
    """Parse the raw webhook body into an event dict, or None if malformed."""
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = bytes(payload).decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return None
    if not isinstance(payload, str) or not payload.strip():
        return None
    try:
        parsed = json.loads(payload)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _route_event(
    event_type: str, data: Dict[str, Any], price_ids: Dict[str, Any]
) -> tuple[str, Optional[str]]:
    """Map an event type to (tenant_action, resolved_plan).

    Mirrors ``handle_webhook``'s dispatch + the ``_handle_subscription_*``
    routers. Payment confirmations and unknown events are no-ops.
    """
    if event_type in _ACTIVATE_EVENTS:
        return "activate", _resolve_plan_from_price(data, price_ids)
    if event_type in _CANCEL_EVENTS:
        return "cancel", _CANCELLED_PLAN
    # payment.succeeded / payment_intent.succeeded / anything else → log only.
    return "none", None


def _resolve_plan_from_price(
    data: Dict[str, Any], price_ids: Dict[str, Any]
) -> str:
    """Map an Airwallex price_id back to a plan name (mirrors source helper).

    Reads ``data.items[0].price_id`` and matches it against the configured
    ``price_ids`` map. Falls back to ``_DEFAULT_PLAN`` ('pro') when no match.
    """
    items = data.get("items") if isinstance(data.get("items"), list) else []
    price_id = None
    if items and isinstance(items[0], dict):
        price_id = items[0].get("price_id")
    if price_id:
        for plan, pid in price_ids.items():
            if pid == price_id:
                return plan
    return _DEFAULT_PLAN


def _clean_str(val: Any) -> Optional[str]:
    """Return a stripped non-empty string, else None."""
    if isinstance(val, str):
        s = val.strip()
        if s:
            return s
    return None


def _build_rationale(
    verified: bool,
    secret_configured: bool,
    event_type: str,
    tenant_action: str,
    resolved_plan: Optional[str],
) -> str:
    if secret_configured:
        auth = "verified via HMAC-SHA256 signature"
    else:
        auth = ("processed UNVERIFIED (AIRWALLEX_WEBHOOK_SECRET not configured) "
                "— record a security_review audit row")
    et = event_type or "<unknown>"
    if tenant_action == "activate":
        return ("Webhook %s %s; activate the tenant on plan '%s'."
                % (et, auth, resolved_plan))
    if tenant_action == "cancel":
        return ("Webhook %s %s; cancel the tenant subscription and set plan "
                "'%s'." % (et, auth, resolved_plan))
    return ("Webhook %s %s; no tenant mutation (payment confirmation or "
            "unhandled event type)." % (et, auth))


def _compute_confidence(
    verified: bool,
    secret_configured: bool,
    event_type: str,
    tenant_action: str,
) -> float:
    """Confidence reflects authentication trust plus how actionable the event is.

    - A signature-verified webhook is fully trusted (0.95).
    - The unverified fall-through path is correct per spec but is a security
      gap, so the decision to mutate state off it is held at moderate
      confidence (0.6).
    - An unknown / no-op event type trims a little — the route is a confident
      no-op but the event itself is unrecognised.
    """
    base = 0.95 if verified else 0.6
    if not event_type:
        base -= 0.15
    elif tenant_action == "none" and event_type not in _PAYMENT_EVENTS:
        # Recognised dispatch table did not match — confident no-op but the
        # event is unfamiliar.
        base -= 0.05
    return round(max(0.1, min(1.0, base)), 2)
