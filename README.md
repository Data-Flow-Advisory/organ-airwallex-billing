# organ-airwallex-billing

A pure decision organ that decides what a single inbound **Airwallex billing
webhook** authorises: whether to **process**, **reject** (bad signature →
HTTP 401) or **skip** the event; whether it was signature-**verified** or is
being processed on the **unverified fall-through** path (so a `security_review`
audit row must be recorded); and, for subscription lifecycle events, which
tenant action the caller should take (`activate` with a resolved plan /
`cancel` / `none`).

## Overview

This organ implements the **pure organ contract** from the Data-Flow-Advisory
orchestrator. It is the extracted decision core of discovery-engine's
[`app/services/airwallex_billing.py`](https://github.com/Data-Flow-Advisory/discovery-engine)
— specifically `handle_webhook` plus its private helpers `_verify_signature`,
`_resolve_plan_from_price` and the `_handle_subscription_*` routers.

That module mixes the decision with heavy I/O:

- reading `AIRWALLEX_WEBHOOK_SECRET` and the `AIRWALLEX_PRICE_*` env vars,
- writing a `security_review` `PlatformEvent` row when the secret is unset,
- querying `Tenant` by Airwallex `customer_id` and committing plan changes.

None of that belongs in a composable decision. **The organ consumes the raw
webhook (payload + signature + timestamp) plus the already-resolved config
(secret + price→plan map) and returns the decision; the caller performs the
DB writes / audit the decision authorises.** It is:

- **Pure** — no env reads, no DB, no file I/O, no globals.
- **Deterministic** — same input → same output.
- **Stdlib-only** — `hmac`, `hashlib`, `json`, `typing` only (Python 3.7+).
- **Fail-safe** — empty / malformed input returns a valid `skip` / `reject`.

The HMAC-SHA256 verification is reproduced **verbatim** from the source
(`hmac` + `hashlib` are stdlib), so the organ stays pure while remaining
self-contained. The signing string is `<timestamp><raw_payload>` per the
[Airwallex webhook spec](https://www.airwallex.com/docs/billing/subscriptions).

## Signature

```python
def decide(state: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    ...
```

### `state` — the raw inbound webhook

Provide **either** `payload` (the raw body, which the organ parses *and*
signature-verifies) **or** a pre-parsed `event` dict (when the caller asserts
it already verified). All keys optional; `{}` is valid.

```json
{
  "payload":   "{\"id\":\"evt_1\",\"name\":\"subscription.activated\",\"data\":{...}}",
  "signature": "<X-Signature header (hex HMAC-SHA256)>",
  "timestamp": "<X-Timestamp header>"
}
```

### `context` — already-resolved billing config

```json
{
  "webhook_secret": "whsec_...",
  "price_ids": { "starter": "px_..", "pro": "px_..", "enterprise": "px_.." }
}
```

An empty / missing `webhook_secret` selects the **verified-but-disabled**
fall-through path: the event is processed (so the integration can be exercised
during rollout) but flagged for a `security_review` audit row.

## Return value

```json
{
  "output": {
    "action":                  "process | reject | skip",
    "verified":                true,
    "secret_configured":       true,
    "record_unverified_audit": false,
    "event_type":              "subscription.activated",
    "event_id":                "evt_1",
    "customer_id":             "cus_42",
    "tenant_action":           "activate | cancel | none",
    "resolved_plan":           "pro",
    "http_status_hint":        200
  },
  "rationale": "Webhook subscription.activated verified via HMAC-SHA256 signature; activate the tenant on plan 'pro'.",
  "self_metric": { "confidence": 0.95 }
}
```

### Decision table

| Condition | `action` | `http_status_hint` | notes |
|-----------|----------|:------------------:|-------|
| `state == {}` | `skip` | 200 | fail-safe, nothing to do |
| Secret configured **and** signature mismatched/missing | `reject` | 401 | fail-closed — never mutate off an unauthenticated event |
| Payload missing / not valid JSON / not an object | `reject` | 400 | malformed request |
| Secret **not** configured | `process` | 200 | `record_unverified_audit = true` |
| Signature verified (or pre-parsed `event`) | `process` | 200 | full trust |

### Event routing (when `action == process`)

| `event_type` | `tenant_action` | `resolved_plan` |
|--------------|-----------------|-----------------|
| `subscription.activated` | `activate` | mapped from `data.items[0].price_id` via `price_ids`, else `pro` |
| `subscription.cancelled` | `cancel` | `free` |
| `payment.succeeded` / `payment_intent.succeeded` | `none` | `null` (log only) |
| anything else | `none` | `null` |

This mirrors `handle_webhook`'s dispatch and the `_handle_subscription_*`
routers exactly, including `_resolve_plan_from_price`'s fallback to `pro`.

## Usage

```python
from organ import decide

result = decide(
    {"payload": raw_body, "signature": sig_header, "timestamp": ts_header},
    {"webhook_secret": os.environ["AIRWALLEX_WEBHOOK_SECRET"],
     "price_ids": price_ids_map},
)
out = result["output"]

if out["action"] == "reject":
    return "", out["http_status_hint"]          # 401 bad sig / 400 malformed
if out["record_unverified_audit"]:
    record_security_review_event(out["event_type"], out["event_id"])  # caller I/O
if out["tenant_action"] == "activate":
    tenant = Tenant.query.filter_by(stripe_customer_id=out["customer_id"]).first()
    tenant.plan = out["resolved_plan"]; db.session.commit()
elif out["tenant_action"] == "cancel":
    tenant.plan = "free"; tenant.stripe_subscription_id = None; db.session.commit()
```

### Empty state (fail-safe)

```python
result = decide({}, {})
assert result["output"]["action"] == "skip"
assert result["self_metric"]["confidence"] <= 0.5
```

## Confidence

`self_metric.confidence` reflects authentication trust plus how actionable the
event is:

- Signature-verified webhook → **0.95** (fully trusted).
- Unverified fall-through (no secret) → **0.6** (correct per spec, but a
  security gap, so mutating off it is held at moderate confidence).
- Bad-signature reject → **0.95** (a certain rejection).
- Malformed payload → **0.85**.
- Unrecognised / unknown event type → trimmed slightly.
- Floor 0.1, ceiling 1.0.

## Examples

See `samples/`:

- `verified_activation.json` — valid HMAC, `subscription.activated` → `process` / `activate`
- `unverified_cancellation.json` — no secret, `subscription.cancelled` → `process` / `cancel` + audit
- `bad_signature.json` — configured secret, mismatched signature → `reject` (401)

```bash
python samples/usage_example.py
```

## Tests

```bash
python -m pytest test_organ.py -v
```

Coverage: return shape, empty/malformed state, HMAC verification (valid /
mismatched / missing / tampered), unverified fall-through + audit flag,
event routing (activate / cancel / payment no-op / unknown), price→plan
resolution + `pro` fallback, pre-parsed event, bytes payload, determinism,
and input non-mutation.

## Integration with the orchestrator

1. The HTTP route receives the Airwallex webhook (raw body + headers).
2. It resolves config (`AIRWALLEX_WEBHOOK_SECRET`, price-id map) and feeds
   `state` + `context` to this organ.
3. The organ returns whether to reject / process, the audit flag, and the
   tenant action + resolved plan.
4. The caller maps `http_status_hint` to the response and performs the DB
   writes / audit the decision authorises.

Keeping the decision pure lets it run in CI, be unit-tested without Flask or a
database, and compose with other billing organs.

## License

Part of the Data-Flow-Advisory platform. See parent repo for license.

---

**Organ format**: Pure orchestrator contract · **Python**: 3.7+
