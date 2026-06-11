#!/usr/bin/env python3
"""Example usage of the Airwallex billing webhook decision organ.

Loads each sample (a {state, context} pair) and prints the decision the organ
returns. Each sample exercises a different branch:

  - verified_activation.json     valid HMAC signature, subscription.activated → process / activate
  - unverified_cancellation.json no secret configured, subscription.cancelled → process / cancel + audit
  - bad_signature.json           configured secret, mismatched signature      → reject (HTTP 401)
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from organ import decide  # noqa: E402

SAMPLES = ["verified_activation.json", "unverified_cancellation.json", "bad_signature.json"]


def print_decision(name: str, result: dict) -> None:
    out = result["output"]
    print("=" * 60)
    print(name)
    print("=" * 60)
    print("Action:                   %s" % out["action"])
    print("verified:                 %s" % out["verified"])
    print("secret_configured:        %s" % out["secret_configured"])
    print("record_unverified_audit:  %s" % out["record_unverified_audit"])
    print("event_type:               %s" % out["event_type"])
    print("tenant_action:            %s" % out["tenant_action"])
    print("resolved_plan:            %s" % out["resolved_plan"])
    print("http_status_hint:         %s" % out["http_status_hint"])
    print("Confidence:               %.0f%%" % (result["self_metric"]["confidence"] * 100))
    print("Rationale:                %s" % result["rationale"])
    print()


def main() -> None:
    here = Path(__file__).parent
    for name in SAMPLES:
        with open(here / name) as f:
            sample = json.load(f)
        result = decide(sample.get("state", {}), sample.get("context", {}))
        print_decision(name, result)

    print("=" * 60)
    print("EXTRA: empty state (fail-safe)")
    print("=" * 60)
    print_decision("empty_state", decide({}, {}))


if __name__ == "__main__":
    main()
