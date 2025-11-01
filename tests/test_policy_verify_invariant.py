import pathlib
import sys

import yaml

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))
sys.path.insert(0, str(root / "cli"))

from llmfw_policy_verify import verify_no_allow_biohazard

from llm_firewall.policy.dsl import parse_yaml_spec


def test_invariant_holds_for_base_policy():
    base_policy = root / "policies" / "base.yaml"
    if not base_policy.exists():
        # Skip if base policy doesn't exist
        return

    data = yaml.safe_load(base_policy.read_text(encoding="utf-8"))
    spec = parse_yaml_spec(data)
    ok, msg = verify_no_allow_biohazard(spec)
    assert ok, msg


def test_invariant_violation_detected():
    # Create a minimal policy that violates the invariant
    policy_yaml = {
        "rules": [
            {
                "id": "allow_bio",
                "priority": 0,
                "when": {"topic_in": "biohazard"},
                "then": {"action": "allow"},
            }
        ],
        "defaults": {"action": "block"},
    }

    spec = parse_yaml_spec(policy_yaml)
    ok, msg = verify_no_allow_biohazard(spec)
    assert not ok, "Should detect invariant violation"
    assert "allow" in msg.lower() and "biohazard" in msg.lower()


def test_invariant_holds_with_block():
    # Policy that blocks biohazard
    policy_yaml = {
        "rules": [
            {
                "id": "block_bio",
                "priority": 0,
                "when": {"topic_in": "biohazard"},
                "then": {"action": "block"},
            }
        ],
        "defaults": {"action": "allow"},
    }

    spec = parse_yaml_spec(policy_yaml)
    ok, msg = verify_no_allow_biohazard(spec)
    assert ok, msg


if __name__ == "__main__":
    test_invariant_holds_for_base_policy()
    print("✓ test_invariant_holds_for_base_policy passed")

    test_invariant_violation_detected()
    print("✓ test_invariant_violation_detected passed")

    test_invariant_holds_with_block()
    print("✓ test_invariant_holds_with_block passed")

    print("\nAll policy verify tests passed!")
