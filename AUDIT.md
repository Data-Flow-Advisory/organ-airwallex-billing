# Corpus + OSS audit — organ-airwallex-billing

**Date:** 2026-06-11 · **Auditor:** fleet worker (item 19883)

## (A) Corpus — is this a duplicate? → **NO. Verdict: KEEP.**

There are three billing-related organs in the corpus and they are
**complementary, not overlapping** — each extracts the decision core of a
distinct discovery-engine source module:

| Organ | Source module | Decides |
|-------|---------------|---------|
| **organ-airwallex-billing** (this) | `airwallex_billing.py::handle_webhook` | how to handle one inbound Airwallex **webhook** (verify / reject / process; tenant activate / cancel; price→plan) |
| organ-billing-provider | `billing_provider.py` | which **provider** (Stripe vs Airwallex) is active + usable |
| organ-airwallex-client | `airwallex_client.py` | what to do with bytes from the Airwallex **REST API** (token refresh, balance, transactions) |

No Stripe-side webhook organ exists that would overlap. No duplicate found.

**Corpus faithfulness (no drift):** verified against the live source on
2026-06-11. The signing string (`<timestamp><payload>`), HMAC-SHA256 +
`compare_digest`, the activate/cancel/payment dispatch, the `subscription.cancelled
→ "free"` plan, and `_resolve_plan_from_price`'s fallback to `"pro"` all match
`app/services/airwallex_billing.py` verbatim. `test_organ.py` — 25/25 pass.

## (B) OSS — adopt a library instead? → **NO. Verdict: KEEP (maintain in-house).**

No permissive open-source library supersedes this organ:

- Airwallex ships **no** webhook-verification SDK. Its own docs
  ([Listen for webhook events](https://www.airwallex.com/docs/developer-tools__listen-for-webhook-events))
  tell integrators to implement verification with Python's stdlib `hmac` +
  `hashlib` and `compare_digest()` — which is **exactly** what this organ does.
  There is nothing to adopt; the verification is ~15 lines of stdlib.
- The actionable part — mapping an event to a DFA **`tenant_action` + resolved
  plan** — is bespoke business logic tied to our `Tenant`/plan model. No generic
  library encodes it.

Adopting a dependency here would add surface area without removing any
maintained logic. Keep.

## Sources

- [Listen for webhook events — Airwallex Docs](https://www.airwallex.com/docs/developer-tools__listen-for-webhook-events)
- [Webhook signature validation — Airwallex REST API](https://developer.token.io/airwallex_rest_api_doc/content/e-rest/webhook_signature_validation.htm)
