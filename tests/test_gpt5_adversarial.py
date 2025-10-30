"""GPT-5 Adversarial Test Suite - Red Team Scenarios.

Purpose: Expose weaknesses in GuardNet, Secrets, Conformal, Safety-Sandwich.
Source: GPT-5 External Review (2025-10-30)
Philosophy: Show where system FAILS, not where it succeeds.
"""
import json
import pathlib
import sys

import pytest

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.gates.secrets_heuristics import analyze_secrets  # noqa: E402

# Load test cases
TEST_DATA_PATH = root / "data" / "gpt5_adversarial_suite.jsonl"


def load_test_cases():
    """Load GPT-5 adversarial test cases."""
    if not TEST_DATA_PATH.exists():
        pytest.skip(f"Test data not found: {TEST_DATA_PATH}")

    cases = []
    with open(TEST_DATA_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                cases.append(json.loads(line))
    return cases


def should_detect_secret(text: str) -> bool:
    """Check if secrets heuristics detect the payload."""
    result = analyze_secrets(text)
    # Block if severity high OR any hits detected
    return result.severity >= 0.4 or len(result.hits) > 0


# Generate parametrized tests
test_cases = load_test_cases()


@pytest.mark.parametrize("case", test_cases, ids=lambda c: c["id"])
def test_adversarial_case(case):
    """Test single adversarial case against secrets detector."""
    payload = case["payload"]
    expected = case["expected_detection"]
    attack_type = case["attack_type"]
    severity = case["severity"]
    weakness = case["weakness_if_pass"]

    detected = should_detect_secret(payload)

    if expected == "should_block":
        if not detected:
            # FAILURE - document the weakness
            msg = (
                f"FAIL [{severity.upper()}]: {attack_type}\n"
                f"Payload: {payload[:80]}...\n"
                f"Weakness: {weakness}"
            )
            pytest.fail(msg)
        # Success - but don't celebrate, just pass

    elif expected == "should_allow":
        if detected:
            # FALSE POSITIVE
            msg = (
                f"FALSE POSITIVE [{severity.upper()}]: {attack_type}\n"
                f"Payload: {payload[:80]}...\n"
                f"Weakness: {weakness}"
            )
            pytest.fail(msg)


def test_adversarial_summary_stats():
    """Generate summary statistics of adversarial test results."""
    if not test_cases:
        pytest.skip("No test cases loaded")

    by_severity = {}
    by_category = {}

    for case in test_cases:
        sev = case["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1

        attack_type = case["attack_type"]
        # Extract category from attack_type
        if "multi" in attack_type or "session" in attack_type or "slow_roll" in attack_type:
            cat = "session_level"
        elif "encoding" in attack_type or "base" in attack_type or "escape" in attack_type:
            cat = "encoding_evasion"
        elif "bidi" in attack_type or "homoglyph" in attack_type or "zero_width" in attack_type:
            cat = "unicode_obfuscation"
        elif "locale" in attack_type or "multilang" in attack_type or "domain" in attack_type:
            cat = "distribution_shift"
        elif "false_positive" in attack_type or "uuid" in attack_type or "dna" in attack_type:
            cat = "edge_case_fp"
        else:
            cat = "other_evasion"

        by_category[cat] = by_category.get(cat, 0) + 1

    print("\n=== GPT-5 ADVERSARIAL SUITE SUMMARY ===")
    print(f"Total Cases: {len(test_cases)}")
    print("\nBy Severity:")
    for sev in ["critical", "high", "medium", "low"]:
        count = by_severity.get(sev, 0)
        print(f"  {sev.upper()}: {count}")

    print("\nBy Category:")
    for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")

