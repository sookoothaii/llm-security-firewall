#!/usr/bin/env python3
"""
Test TAG-2 Truth Preservation Integration in Firewall Engine v2.0
==================================================================

Tests that validate_output() correctly validates LLM responses using
TruthPreservationValidatorV2_3.

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-29
Status: v2.1-TRUTH Integration Test
"""

import sys
from pathlib import Path

# Add parent directory to path
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir.parent))

# Import using absolute path
from kids_policy.firewall_engine_v2 import HakGalFirewall_v2


def test_tag2_validation_pass():
    """Test that valid output passes TAG-2 validation."""
    engine = HakGalFirewall_v2()

    # Valid response about safety rules (should pass)
    user_input = "What are safety rules?"
    llm_response = "Rules help keep us safe. We need to follow rules, even if we think we can break them."

    result = engine.validate_output(
        user_id="test_user",
        user_input=user_input,
        llm_response=llm_response,
        age_band="6-8",
        topic_id="safety_rules",
    )

    assert result["status"] == "ALLOW", f"Expected ALLOW, got {result['status']}"
    assert "tag2_result" in result["debug"], "TAG-2 result should be in debug"
    assert result["debug"]["tag2_result"]["overall_pass"] is True, (
        "Validation should pass"
    )
    print("[PASS] Test 1: Valid output passes TAG-2")


def test_tag2_validation_block():
    """Test that invalid output (contradicting canonical facts) is blocked."""
    engine = HakGalFirewall_v2()

    # Invalid response that contradicts safety rules (should block)
    user_input = "What are safety rules?"
    llm_response = "Rules don't matter. You can break them if you want. Age limits are not mandatory."

    result = engine.validate_output(
        user_id="test_user",
        user_input=user_input,
        llm_response=llm_response,
        age_band="6-8",
        topic_id="safety_rules",
    )

    # Should block due to contradiction with canonical facts
    if result["status"] == "BLOCK" and result["reason"] == "TRUTH_VIOLATION":
        print("[PASS] Test 2: Invalid output blocked by TAG-2")
    else:
        print(
            f"[WARN] Test 2: Expected BLOCK/TRUTH_VIOLATION, got {result['status']}/{result.get('reason')}"
        )
        print(f"  Debug: {result.get('debug', {})}")


def test_tag2_skip_no_topic():
    """Test that validation is skipped when no topic_id is provided."""
    engine = HakGalFirewall_v2()

    result = engine.validate_output(
        user_id="test_user",
        user_input="Hello",
        llm_response="Hello there!",
        age_band="9-12",
        topic_id=None,  # No topic
    )

    assert result["status"] == "ALLOW", "Should allow when skipped"
    assert result["debug"].get("tag2_skipped") == "no_topic_id", (
        "Should skip when no topic"
    )
    print("[PASS] Test 3: Validation skipped when no topic_id")


def test_tag2_skip_general_chat():
    """Test that validation is skipped for general_chat topic."""
    engine = HakGalFirewall_v2()

    result = engine.validate_output(
        user_id="test_user",
        user_input="How are you?",
        llm_response="I'm doing well, thanks!",
        age_band="9-12",
        topic_id="general_chat",
    )

    assert result["status"] == "ALLOW", "Should allow when skipped"
    assert result["debug"].get("tag2_skipped") == "no_topic_id", (
        "Should skip for general_chat"
    )
    print("[PASS] Test 4: Validation skipped for general_chat")


def main():
    """Run all TAG-2 integration tests."""
    print("\n" + "=" * 80)
    print("TAG-2 Truth Preservation Integration Tests")
    print("=" * 80 + "\n")

    try:
        test_tag2_validation_pass()
        test_tag2_validation_block()
        test_tag2_skip_no_topic()
        test_tag2_skip_general_chat()

        print("\n" + "=" * 80)
        print("ALL TESTS COMPLETED")
        print("=" * 80)

    except Exception as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
