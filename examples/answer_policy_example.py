"""
Example: Using AnswerPolicy (Epistemic Decision Layer)
=====================================================

This example demonstrates how to use AnswerPolicy to implement
explicit cost-benefit trade-offs for answer vs. silence decisions.

Author: Joerg Bollwahn
Date: 2025-12-02
"""

from llm_firewall.core.firewall_engine_v2 import FirewallEngine
from llm_firewall.core.policy_provider import PolicyProvider, get_default_provider
from llm_firewall.core.decision_policy import get_policy, AnswerPolicy


def example_1_basic_usage():
    """Example 1: Basic usage with default provider."""
    print("=" * 70)
    print("Example 1: Basic Usage with Default Provider")
    print("=" * 70)

    engine = FirewallEngine()
    provider = get_default_provider()

    test_inputs = [
        "Normal text input",
        "How do I hack a password?",  # Potentially malicious
        "Explain quantum computing",  # Educational
    ]

    for text in test_inputs:
        decision = engine.process_input(
            text,
            use_answer_policy=True,
            policy_provider=provider,
        )

        print(f"\nInput: {text[:50]}...")
        print(f"  Allowed: {decision.allowed}")
        print(f"  Risk Score: {decision.risk_score:.3f}")
        print(f"  Reason: {decision.reason}")

        if "answer_policy" in decision.metadata:
            policy_meta = decision.metadata["answer_policy"]
            print("  AnswerPolicy:")
            print(f"    Policy: {policy_meta['policy_name']}")
            print(f"    p_correct: {policy_meta['p_correct']:.3f}")
            print(f"    Threshold: {policy_meta['threshold']:.3f}")
            print(f"    Decision Mode: {policy_meta['decision_mode']}")


def example_2_kids_policy():
    """Example 2: Using kids policy (high cost for wrong answers)."""
    print("\n" + "=" * 70)
    print("Example 2: Kids Policy (High Cost for Wrong Answers)")
    print("=" * 70)

    engine = FirewallEngine()
    provider = PolicyProvider(tenant_policy_map={"tenant_kids": "kids"})

    kids_policy = get_policy("kids")
    print(f"\nKids Policy Threshold: {kids_policy.threshold():.3f}")
    print(f"  (Only answers if p_correct >= {kids_policy.threshold():.3f})")

    test_inputs = [
        "What is 2+2?",  # Low risk
        "How to make a bomb?",  # High risk
    ]

    for text in test_inputs:
        decision = engine.process_input(
            text,
            tenant_id="tenant_kids",
            use_answer_policy=True,
            policy_provider=provider,
        )

        print(f"\nInput: {text}")
        print(f"  Allowed: {decision.allowed}")
        print(f"  Risk Score: {decision.risk_score:.3f}")

        if "answer_policy" in decision.metadata:
            policy_meta = decision.metadata["answer_policy"]
            p_correct = policy_meta["p_correct"]
            threshold = policy_meta["threshold"]

            if p_correct < threshold:
                print(
                    f"  BLOCKED by AnswerPolicy: p_correct={p_correct:.3f} < threshold={threshold:.3f}"
                )
            else:
                print(
                    f"  ALLOWED by AnswerPolicy: p_correct={p_correct:.3f} >= threshold={threshold:.3f}"
                )


def example_3_custom_policy():
    """Example 3: Creating and using custom policy."""
    print("\n" + "=" * 70)
    print("Example 3: Custom Policy")
    print("=" * 70)

    # Create custom policy: moderate cost for wrong answers
    custom_policy = AnswerPolicy(
        benefit_correct=1.0,
        cost_wrong=15.0,
        cost_silence=0.5,
        policy_name="custom_moderate",
    )

    print("\nCustom Policy:")
    print(f"  Benefit (correct): {custom_policy.benefit_correct}")
    print(f"  Cost (wrong): {custom_policy.cost_wrong}")
    print(f"  Cost (silence): {custom_policy.cost_silence}")
    print(f"  Threshold: {custom_policy.threshold():.3f}")

    # Add to provider
    provider = PolicyProvider()
    provider.add_policy(custom_policy)

    engine = FirewallEngine()

    decision = engine.process_input(
        "test input",
        tenant_id="test_tenant",
        context={"policy": "custom_moderate"},
        use_answer_policy=True,
        policy_provider=provider,
    )

    print("\nDecision:")
    print(f"  Allowed: {decision.allowed}")
    print(f"  Risk Score: {decision.risk_score:.3f}")


def example_4_per_route_policies():
    """Example 4: Per-route policy selection."""
    print("\n" + "=" * 70)
    print("Example 4: Per-Route Policy Selection")
    print("=" * 70)

    engine = FirewallEngine()
    provider = PolicyProvider(
        route_policy_map={
            "/api/kids": "kids",
            "/api/public": "strict",
            "/api/internal": "internal_debug",
        }
    )

    routes = ["/api/kids", "/api/public", "/api/internal"]

    for route in routes:
        policy = provider.for_tenant("any_tenant", route=route)
        print(f"\nRoute: {route}")
        print(f"  Policy: {policy.policy_name}")
        print(f"  Threshold: {policy.threshold():.3f}")

        decision = engine.process_input(
            "test input",
            route=route,
            use_answer_policy=True,
            policy_provider=provider,
        )

        print(f"  Decision: {'ALLOWED' if decision.allowed else 'BLOCKED'}")


def example_5_utility_comparison():
    """Example 5: Comparing expected utilities."""
    print("\n" + "=" * 70)
    print("Example 5: Expected Utility Comparison")
    print("=" * 70)

    policy = get_policy("default")
    p_correct_values = [0.5, 0.7, 0.9, 0.95]

    print(f"\nPolicy: {policy.policy_name}")
    print(f"  Benefit (correct): {policy.benefit_correct}")
    print(f"  Cost (wrong): {policy.cost_wrong}")
    print(f"  Cost (silence): {policy.cost_silence}")
    print(f"  Threshold: {policy.threshold():.3f}")

    print(
        f"\n{'p_correct':<12} {'E[U(answer)]':<15} {'E[U(silence)]':<15} {'Decision':<10}"
    )
    print("-" * 70)

    for p_correct in p_correct_values:
        eu_answer = policy.expected_utility_answer(p_correct)
        eu_silence = policy.expected_utility_silence()
        decision = policy.decide(p_correct)

        print(
            f"{p_correct:<12.3f} {eu_answer:<15.3f} {eu_silence:<15.3f} {decision:<10}"
        )


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("AnswerPolicy Examples")
    print("=" * 70)

    try:
        example_1_basic_usage()
        example_2_kids_policy()
        example_3_custom_policy()
        example_4_per_route_policies()
        example_5_utility_comparison()

        print("\n" + "=" * 70)
        print("Examples completed successfully!")
        print("=" * 70)

    except Exception as e:
        print(f"\nError: {e}")
        import traceback

        traceback.print_exc()
