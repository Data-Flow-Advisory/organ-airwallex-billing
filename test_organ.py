"""Test suite for the Airwallex billing webhook decision organ.

Verifies the pure-function contract: deterministic, no side effects, handles
empty state, returns the required {output, rationale, self_metric} shape with a
confidence in [0, 1]. Also covers the signature-verification, unverified
fall-through, event-routing and price→plan resolution branches.
"""
import copy
import hashlib
import hmac
import json
import unittest

from organ import decide

_SECRET = "whsec_test_airwallex_abc123"
_PRICE_IDS = {"starter": "px_starter", "pro": "px_pro", "enterprise": "px_ent"}


def _sign(payload: str, timestamp: str, secret: str = _SECRET) -> str:
    signing_string = timestamp.encode("utf-8") + payload.encode("utf-8")
    return hmac.new(secret.encode("utf-8"), signing_string, hashlib.sha256).hexdigest()


def _webhook(event: dict, timestamp: str = "1718064000", secret: str = _SECRET,
             price_ids: dict = None):
    payload = json.dumps(event)
    state = {"payload": payload, "signature": _sign(payload, timestamp, secret),
             "timestamp": timestamp}
    context = {"webhook_secret": secret,
               "price_ids": _PRICE_IDS if price_ids is None else price_ids}
    return state, context


_ACTIVATION = {
    "id": "evt_1", "name": "subscription.activated",
    "data": {"customer_id": "cus_42", "items": [{"price_id": "px_pro"}]},
}


class TestSignatureAndShape(unittest.TestCase):
    def test_returns_three_top_level_keys(self):
        result = decide(*_webhook(_ACTIVATION))
        self.assertIn("output", result)
        self.assertIn("rationale", result)
        self.assertIn("self_metric", result)
        self.assertIsInstance(result["output"], dict)
        self.assertIsInstance(result["rationale"], str)
        self.assertIsInstance(result["self_metric"], dict)

    def test_self_metric_confidence_in_range(self):
        conf = decide(*_webhook(_ACTIVATION))["self_metric"]["confidence"]
        self.assertIsInstance(conf, (int, float))
        self.assertGreaterEqual(conf, 0.0)
        self.assertLessEqual(conf, 1.0)

    def test_output_required_fields(self):
        out = decide(*_webhook(_ACTIVATION))["output"]
        for field in ("action", "verified", "secret_configured",
                      "record_unverified_audit", "event_type", "event_id",
                      "customer_id", "tenant_action", "resolved_plan",
                      "http_status_hint"):
            self.assertIn(field, out, "missing output field: %s" % field)
        self.assertIn(out["action"], ("process", "reject", "skip"))
        self.assertIn(out["tenant_action"], ("activate", "cancel", "none"))


class TestEmptyState(unittest.TestCase):
    def test_empty_state_skips(self):
        result = decide({}, {})
        self.assertEqual(result["output"]["action"], "skip")
        self.assertEqual(result["output"]["tenant_action"], "none")
        self.assertGreaterEqual(result["self_metric"]["confidence"], 0.1)
        self.assertLessEqual(result["self_metric"]["confidence"], 0.5)

    def test_empty_context_still_valid(self):
        # No secret, no price_ids — unverified fall-through.
        state = {"payload": json.dumps(_ACTIVATION)}
        result = decide(state, {})
        self.assertEqual(result["output"]["action"], "process")
        self.assertTrue(result["output"]["record_unverified_audit"])


class TestSignatureVerification(unittest.TestCase):
    def test_valid_signature_verifies(self):
        out = decide(*_webhook(_ACTIVATION))["output"]
        self.assertTrue(out["verified"])
        self.assertTrue(out["secret_configured"])
        self.assertEqual(out["action"], "process")
        self.assertEqual(out["http_status_hint"], 200)
        self.assertFalse(out["record_unverified_audit"])

    def test_bad_signature_rejects_401(self):
        state, context = _webhook(_ACTIVATION)
        state["signature"] = "deadbeef" * 8
        result = decide(state, context)
        out = result["output"]
        self.assertEqual(out["action"], "reject")
        self.assertEqual(out["http_status_hint"], 401)
        self.assertFalse(out["verified"])
        self.assertEqual(out["tenant_action"], "none")
        self.assertGreaterEqual(result["self_metric"]["confidence"], 0.9)

    def test_missing_signature_with_secret_rejects(self):
        state, context = _webhook(_ACTIVATION)
        state["signature"] = ""
        self.assertEqual(decide(state, context)["output"]["action"], "reject")

    def test_tampered_payload_rejects(self):
        state, context = _webhook(_ACTIVATION)
        # Signature was computed over the original payload; change the body.
        state["payload"] = json.dumps({"id": "evt_x", "name": "subscription.cancelled"})
        self.assertEqual(decide(state, context)["output"]["action"], "reject")


class TestUnverifiedFallThrough(unittest.TestCase):
    def test_no_secret_processes_with_audit(self):
        state = {"payload": json.dumps(_ACTIVATION)}
        result = decide(state, {"webhook_secret": "", "price_ids": _PRICE_IDS})
        out = result["output"]
        self.assertEqual(out["action"], "process")
        self.assertFalse(out["secret_configured"])
        self.assertTrue(out["record_unverified_audit"])
        self.assertEqual(out["tenant_action"], "activate")
        # Moderate confidence — correct per spec but a security gap.
        self.assertLessEqual(result["self_metric"]["confidence"], 0.8)

    def test_no_secret_bad_signature_irrelevant(self):
        # With no secret, signature is not checked — still processes.
        state = {"payload": json.dumps(_ACTIVATION), "signature": "garbage"}
        self.assertEqual(decide(state, {})["output"]["action"], "process")


class TestMalformedPayload(unittest.TestCase):
    def test_unparseable_json_rejects_400(self):
        state = {"payload": "{not valid json", "signature": "", "timestamp": ""}
        result = decide(state, {})  # no secret → goes to parse step
        self.assertEqual(result["output"]["action"], "reject")
        self.assertEqual(result["output"]["http_status_hint"], 400)

    def test_non_dict_json_rejects(self):
        state = {"payload": json.dumps([1, 2, 3])}
        self.assertEqual(decide(state, {})["output"]["action"], "reject")

    def test_empty_payload_rejects(self):
        state = {"payload": "   "}
        self.assertEqual(decide(state, {})["output"]["action"], "reject")


class TestEventRouting(unittest.TestCase):
    def test_activation_resolves_plan_from_price(self):
        ev = {"id": "e", "name": "subscription.activated",
              "data": {"customer_id": "c", "items": [{"price_id": "px_ent"}]}}
        out = decide(*_webhook(ev))["output"]
        self.assertEqual(out["tenant_action"], "activate")
        self.assertEqual(out["resolved_plan"], "enterprise")
        self.assertEqual(out["customer_id"], "c")

    def test_activation_unknown_price_falls_back_to_pro(self):
        ev = {"id": "e", "name": "subscription.activated",
              "data": {"items": [{"price_id": "px_unmapped"}]}}
        self.assertEqual(decide(*_webhook(ev))["output"]["resolved_plan"], "pro")

    def test_activation_no_items_falls_back_to_pro(self):
        ev = {"id": "e", "name": "subscription.activated", "data": {}}
        self.assertEqual(decide(*_webhook(ev))["output"]["resolved_plan"], "pro")

    def test_cancellation_sets_free(self):
        ev = {"id": "e", "name": "subscription.cancelled",
              "data": {"customer_id": "c"}}
        out = decide(*_webhook(ev))["output"]
        self.assertEqual(out["tenant_action"], "cancel")
        self.assertEqual(out["resolved_plan"], "free")

    def test_payment_succeeded_is_noop(self):
        ev = {"id": "e", "name": "payment.succeeded", "data": {"id": "pay_1"}}
        out = decide(*_webhook(ev))["output"]
        self.assertEqual(out["action"], "process")
        self.assertEqual(out["tenant_action"], "none")
        self.assertIsNone(out["resolved_plan"])

    def test_payment_intent_succeeded_is_noop(self):
        ev = {"id": "e", "name": "payment_intent.succeeded", "data": {}}
        self.assertEqual(decide(*_webhook(ev))["output"]["tenant_action"], "none")

    def test_unknown_event_is_noop(self):
        ev = {"id": "e", "name": "invoice.created", "data": {}}
        out = decide(*_webhook(ev))["output"]
        self.assertEqual(out["action"], "process")
        self.assertEqual(out["tenant_action"], "none")


class TestPreParsedEvent(unittest.TestCase):
    def test_pre_parsed_event_skips_verification(self):
        # Caller asserts it already verified — pass the event dict directly.
        state = {"event": _ACTIVATION}
        out = decide(state, {"webhook_secret": _SECRET, "price_ids": _PRICE_IDS})["output"]
        self.assertTrue(out["verified"])
        self.assertEqual(out["action"], "process")
        self.assertEqual(out["tenant_action"], "activate")


class TestPurity(unittest.TestCase):
    def test_deterministic(self):
        state, context = _webhook(_ACTIVATION)
        self.assertEqual(decide(state, context), decide(state, context))

    def test_does_not_mutate_inputs(self):
        state, context = _webhook(_ACTIVATION)
        state_copy = copy.deepcopy(state)
        context_copy = copy.deepcopy(context)
        decide(state, context)
        self.assertEqual(state, state_copy)
        self.assertEqual(context, context_copy)

    def test_bytes_payload_supported(self):
        ts = "1718064000"
        payload = json.dumps(_ACTIVATION)
        sig = _sign(payload, ts)
        state = {"payload": payload.encode("utf-8"), "signature": sig, "timestamp": ts}
        out = decide(state, {"webhook_secret": _SECRET, "price_ids": _PRICE_IDS})["output"]
        self.assertTrue(out["verified"])


class TestBillingStateOutput(unittest.TestCase):
    """The additive `billing_state` output port (vocab type BillingState).

    Pins that the organ emits the spine-connectable {tier,status,features}
    state the vocabulary assigns it (BillingState.produced_by_eg lists this
    organ → consumed by organ-feature-gates) — non-null on processed
    activate/cancel events, None when no tenant mutation is authorised.
    """

    def test_billing_state_key_always_present(self):
        # Present on every path so a typed consumer can always read the port.
        for state, context in (
            ({}, {}),  # skip
            _webhook(_ACTIVATION),  # activate
        ):
            self.assertIn("billing_state", decide(state, context)["output"])

    def test_activate_emits_active_billing_state(self):
        out = decide(*_webhook(_ACTIVATION))["output"]
        self.assertEqual(out["tenant_action"], "activate")
        bs = out["billing_state"]
        self.assertIsInstance(bs, dict)
        self.assertEqual(bs["tier"], "pro")  # px_pro → pro
        self.assertEqual(bs["status"], "active")
        self.assertEqual(bs["features"], [])
        # billing_state.tier tracks the decision's resolved_plan.
        self.assertEqual(bs["tier"], out["resolved_plan"])

    def test_cancel_emits_cancelled_billing_state(self):
        cancel = {"id": "evt_c", "name": "subscription.cancelled",
                  "data": {"customer_id": "cus_42"}}
        out = decide(*_webhook(cancel))["output"]
        self.assertEqual(out["tenant_action"], "cancel")
        bs = out["billing_state"]
        self.assertEqual(bs["tier"], "free")
        self.assertEqual(bs["status"], "cancelled")
        self.assertEqual(bs["features"], [])

    def test_no_mutation_events_emit_null_billing_state(self):
        # Payment confirmation → process but no tenant state change.
        payment = {"id": "evt_p", "name": "payment.succeeded",
                   "data": {"customer_id": "cus_42"}}
        out = decide(*_webhook(payment))["output"]
        self.assertEqual(out["tenant_action"], "none")
        self.assertIsNone(out["billing_state"])

    def test_reject_and_skip_emit_null_billing_state(self):
        # Bad signature → reject; empty state → skip. Neither mutates a tenant.
        state, context = _webhook(_ACTIVATION)
        state["signature"] = "deadbeef" * 8
        self.assertIsNone(decide(state, context)["output"]["billing_state"])
        self.assertIsNone(decide({}, {})["output"]["billing_state"])

    def test_billing_state_conforms_to_vocab_schema(self):
        # Whenever non-null, billing_state matches the BillingState schema keys.
        import json as _json
        from pathlib import Path

        vocab = _json.loads(
            (Path(__file__).resolve().parent / "types.json").read_text()
        )["types"]
        schema_keys = set(vocab["BillingState"]["schema"].keys())
        out = decide(*_webhook(_ACTIVATION))["output"]
        self.assertEqual(set(out["billing_state"].keys()), schema_keys)


class TestPortManifest(unittest.TestCase):
    """The connection-standard port manifest (ports.json) conforms.

    Mirrors check_ports.py so the manifest is validated under the standard
    ``pytest test_organ.py`` run, not only the dedicated CI step: ports.json
    parses and is well-formed, every declared type exists in the vocabulary
    (types.json), and decide() reads each declared input name and writes each
    declared output name against the organ's own samples.
    """

    def test_ports_manifest_conforms(self):
        import check_ports

        check_ports.main()  # raises AssertionError on any violation


if __name__ == "__main__":
    unittest.main()
