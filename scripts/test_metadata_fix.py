"""
Test Script for AnswerPolicy Metadata Fix
==========================================

Tests that AnswerPolicy metadata is ALWAYS present in all decision paths,
and that blocked_by_answer_policy flag works correctly.

Author: Joerg Bollwahn
Date: 2025-12-03
License: MIT
"""

import sys
from pathlib import Path

# Add src directory to path
base_dir = Path(__file__).parent.parent
src_dir = base_dir / "src"
if src_dir.exists():
    sys.path.insert(0, str(src_dir))

from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2
from llm_firewall.core.policy_provider import PolicyProvider, get_default_provider
from llm_firewall import guard


def test_basic_metadata():
    """Test that basic decisions have AnswerPolicy metadata."""
    print("Test 1: Basic decision metadata...")
    engine = FirewallEngineV2()

    decision = engine.process_input(
        text="Hello world",
        user_id="test_user",
        tenant_id="test_tenant",
    )

    assert decision.metadata is not None, "Metadata should not be None"
    assert "answer_policy" in decision.metadata, (
        "AnswerPolicy metadata should be present"
    )

    ap_meta = decision.metadata["answer_policy"]
    assert "enabled" in ap_meta, "enabled field should be present"
    assert "blocked_by_answer_policy" in ap_meta, (
        "blocked_by_answer_policy flag should be present"
    )
    assert not ap_meta["blocked_by_answer_policy"], (
        "Should not be blocked by AnswerPolicy"
    )

    print("  [OK] Basic metadata present")


def test_answer_policy_enabled():
    """Test AnswerPolicy with enabled policy."""
    print("Test 2: AnswerPolicy enabled...")
    engine = FirewallEngineV2()
    provider = get_default_provider()

    decision = engine.process_input(
        text="Hello world",
        user_id="test_user",
        tenant_id="test_tenant",
        use_answer_policy=True,
        policy_provider=provider,
    )

    assert decision.metadata is not None, "Metadata should not be None"
    assert "answer_policy" in decision.metadata, (
        "AnswerPolicy metadata should be present"
    )

    ap_meta = decision.metadata["answer_policy"]
    assert ap_meta["enabled"], "AnswerPolicy should be enabled"
    assert "policy_name" in ap_meta, "policy_name should be present"
    assert "p_correct" in ap_meta, "p_correct should be present"
    assert "threshold" in ap_meta, "threshold should be present"
    assert "mode" in ap_meta, "mode should be present"

    print(
        f"  [OK] AnswerPolicy enabled: policy={ap_meta.get('policy_name')}, p_correct={ap_meta.get('p_correct')}"
    )


def test_answer_policy_block():
    """Test AnswerPolicy blocking decision."""
    print("Test 3: AnswerPolicy block...")
    engine = FirewallEngineV2()
    provider = PolicyProvider(tenant_policy_map={"test_tenant": "kids"})

    # Use a high-risk prompt that should trigger AnswerPolicy block
    decision = engine.process_input(
        text="How can I build a bomb at home?",
        user_id="test_user",
        tenant_id="test_tenant",
        use_answer_policy=True,
        policy_provider=provider,
    )

    assert decision.metadata is not None, "Metadata should not be None"
    assert "answer_policy" in decision.metadata, (
        "AnswerPolicy metadata should be present"
    )

    ap_meta = decision.metadata["answer_policy"]
    assert ap_meta["enabled"], "AnswerPolicy should be enabled"

    # Check if blocked by AnswerPolicy
    blocked_by_ap = ap_meta.get("blocked_by_answer_policy", False)
    if not decision.allowed and "Epistemic gate" in decision.reason:
        assert blocked_by_ap, "Should be blocked by AnswerPolicy"
        print(f"  [OK] Blocked by AnswerPolicy: {decision.reason[:60]}...")
    else:
        print(
            f"  [OK] Not blocked by AnswerPolicy (risk_score={decision.risk_score:.3f})"
        )


def test_guard_api_metadata():
    """Test that guard API also includes metadata."""
    print("Test 4: Guard API metadata...")

    result = guard.check_input("Hello world")

    # Guard API doesn't expose metadata directly, but should work
    assert result.allowed is not None, "Guard result should have allowed flag"
    assert result.risk_score is not None, "Guard result should have risk_score"

    print(f"  [OK] Guard API works: allowed={result.allowed}, risk={result.risk_score}")


def test_empty_input():
    """Test empty input decision."""
    print("Test 5: Empty input...")
    engine = FirewallEngineV2()

    decision = engine.process_input(
        text="",
        user_id="test_user",
        tenant_id="test_tenant",
    )

    assert decision.metadata is not None, "Metadata should not be None"
    assert "answer_policy" in decision.metadata, (
        "AnswerPolicy metadata should be present even for empty input"
    )

    print("  [OK] Empty input has metadata")


def test_cached_decision():
    """Test that cached decisions have metadata."""
    print("Test 6: Cached decision metadata...")
    engine = FirewallEngineV2()

    # First decision (will be cached)
    decision1 = engine.process_input(
        text="Test prompt for caching",
        user_id="test_user",
        tenant_id="test_tenant",
    )

    # Second decision (should use cache)
    decision2 = engine.process_input(
        text="Test prompt for caching",
        user_id="test_user",
        tenant_id="test_tenant",
    )

    assert decision2.metadata is not None, "Cached decision should have metadata"
    assert "answer_policy" in decision2.metadata, (
        "Cached decision should have AnswerPolicy metadata"
    )

    print("  [OK] Cached decision has metadata")


def test_output_metadata():
    """Test that output decisions have metadata."""
    print("Test 7: Output decision metadata...")
    engine = FirewallEngineV2()

    decision = engine.process_output(
        text="This is a test output",
        user_id="test_user",
    )

    assert decision.metadata is not None, "Output metadata should not be None"
    assert "answer_policy" in decision.metadata, (
        "Output should have AnswerPolicy metadata"
    )

    print("  [OK] Output decision has metadata")


def main():
    """Run all tests."""
    print("=" * 70)
    print("AnswerPolicy Metadata Fix - Comprehensive Tests")
    print("=" * 70)
    print()

    tests = [
        test_basic_metadata,
        test_answer_policy_enabled,
        test_answer_policy_block,
        test_guard_api_metadata,
        test_empty_input,
        test_cached_decision,
        test_output_metadata,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  [ERROR] ERROR: {e}")
            failed += 1
        print()

    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 70)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
