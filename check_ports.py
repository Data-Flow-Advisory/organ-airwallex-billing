"""Connection-standard port-manifest conformance check.

Asserts the four properties the orchestrator CONNECTORS.md gives the
conformance Action for a typed organ:

  1. ``ports.json`` parses and is well-formed (inputs/outputs lists; each
     input port has name+type+required, each output port has name+type).
  2. Every declared port ``type`` exists in the shared type vocabulary
     (the local vendored ``types.json``).
  3. ``decide`` actually **reads** each declared input ``name`` from
     ``state`` (proven statically against ``organ.py``'s source).
  4. ``decide`` actually **writes** each declared output ``name`` under
     ``output`` (proven dynamically against the organ's own samples).

The whole-output convention: an output port named ``"*"`` means decide's
entire ``output`` object is one value of the declared type — so property 4
checks that every field of that type's schema is present in ``output``.

Pure stdlib; no test deps. Run directly: ``python check_ports.py``.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WHOLE_OUTPUT = "*"


def _load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text())


def _state_reads(source: str) -> set:
    """Every literal string key read from ``state`` in the organ source.

    Catches both ``state.get("k")`` / ``state.get('k')`` and ``state["k"]``.
    """
    reads: set = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        # state.get("k")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "state"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            reads.add(node.args[0].value)
        # state["k"]
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "state"
            and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)
        ):
            reads.add(node.slice.value)
    return reads


def main() -> None:
    ports = _load_json("ports.json")
    types = _load_json("types.json")
    vocab = types.get("types", {})
    assert isinstance(vocab, dict) and vocab, "types.json has no `types` vocabulary"

    # 1. well-formed manifest
    inputs = ports.get("inputs")
    outputs = ports.get("outputs")
    assert isinstance(inputs, list), "ports.json: `inputs` must be a list"
    assert isinstance(outputs, list), "ports.json: `outputs` must be a list"
    assert outputs, "ports.json: at least one output port is required"
    for p in inputs:
        assert {"name", "type", "required"} <= set(p), f"input port missing keys: {p}"
        assert isinstance(p["name"], str) and p["name"], f"bad input name: {p}"
        assert isinstance(p["required"], bool), f"input `required` must be bool: {p}"
    for p in outputs:
        assert {"name", "type"} <= set(p), f"output port missing keys: {p}"
        assert isinstance(p["name"], str) and p["name"], f"bad output name: {p}"

    # 2. every declared type exists in the vocabulary
    for p in inputs + outputs:
        assert p["type"] in vocab, (
            f"port type '{p['type']}' not in vocabulary {sorted(vocab)}"
        )

    # 3. decide reads each declared input name
    reads = _state_reads((ROOT / "organ.py").read_text())
    for p in inputs:
        assert p["name"] in reads, (
            f"decide() does not read declared input '{p['name']}' from state "
            f"(state reads: {sorted(reads)})"
        )

    # 4. decide writes each declared output name (against the organ's samples)
    import organ  # noqa: E402  (imported after path setup)

    samples = sorted((ROOT / "samples").glob("*.json"))
    assert samples, "no samples/ to validate declared outputs against"
    for s in samples:
        data = json.loads(s.read_text())
        result = organ.decide(data.get("state", {}), data.get("context", {}))
        out = result["output"]
        assert isinstance(out, dict), f"{s.name}: decide output is not a dict"
        for p in outputs:
            if p["name"] == WHOLE_OUTPUT:
                schema_fields = set(vocab[p["type"]].get("schema", {}).keys())
                missing = schema_fields - set(out.keys())
                assert not missing, (
                    f"{s.name}: whole-output port '*' declared type "
                    f"'{p['type']}' but output is missing fields: {sorted(missing)}"
                )
            else:
                assert p["name"] in out, (
                    f"{s.name}: decide() did not write declared output "
                    f"'{p['name']}' (output keys: {sorted(out.keys())})"
                )

    print(
        "ports.json conformance OK: "
        f"{len(inputs)} input port(s), {len(outputs)} output port(s), "
        f"validated against {len(samples)} sample(s)."
    )


if __name__ == "__main__":
    main()
