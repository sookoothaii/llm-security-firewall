"""
Unit tests for AnswerPolicy (epistemic decision layer).

Tests the mathematical foundation and decision logic.
"""

import pytest
from llm_firewall.core.decision_policy import AnswerPolicy, get_policy
from llm_firewall.core.policy_provider import PolicyProvider


class TestAnswerPolicy:
    """Test AnswerPolicy class."""

    def test_threshold_calculation(self):
        """Test threshold calculation formula."""
        policy = AnswerPolicy(benefit_correct=1.0, cost_wrong=9.0, cost_silence=0.0)
        expected = (9.0 - 0.0) / (9.0 + 1.0)  # 0.9
        assert abs(policy.threshold() - expected) < 1e-6

    def test_threshold_with_silence_cost(self):
        """Test threshold with non-zero silence cost."""
        policy = AnswerPolicy(benefit_correct=1.0, cost_wrong=5.0, cost_silence=0.5)
        expected = (5.0 - 0.5) / (5.0 + 1.0)  # 0.75
        assert abs(policy.threshold() - expected) < 1e-6

    def test_threshold_clamping(self):
        """Test threshold is clamped to [0, 1]."""
        # Negative threshold (should clamp to 0.0)
        policy = AnswerPolicy(benefit_correct=1.0, cost_wrong=1.0, cost_silence=2.0)
        assert policy.threshold() == 0.0

        # Threshold > 1.0 (should clamp to 1.0)
        policy = AnswerPolicy(benefit_correct=0.1, cost_wrong=100.0, cost_silence=0.0)
        assert policy.threshold() == 1.0

    def test_decide_with_p_correct(self):
        """Test decision logic with p_correct."""
        policy = AnswerPolicy(benefit_correct=1.0, cost_wrong=9.0, cost_silence=0.0)
        # Threshold = 0.9

        assert policy.decide(0.95) == "answer"  # Above threshold
        assert policy.decide(0.9) == "answer"  # At threshold
        assert policy.decide(0.85) == "silence"  # Below threshold

    def test_decide_with_risk_score(self):
        """Test decision logic with risk_score (derives p_correct)."""
        policy = AnswerPolicy(benefit_correct=1.0, cost_wrong=9.0, cost_silence=0.0)
        # Threshold = 0.9, so p_correct must be >= 0.9
        # p_correct = 1.0 - risk_score, so risk_score must be <= 0.1

        assert policy.decide(0.05, risk_score=0.05) == "answer"  # p_correct = 0.95
        assert policy.decide(0.1, risk_score=0.1) == "answer"  # p_correct = 0.9
        assert policy.decide(0.15, risk_score=0.15) == "silence"  # p_correct = 0.85

    def test_expected_utility_answer(self):
        """Test expected utility calculation for answering."""
        policy = AnswerPolicy(benefit_correct=1.0, cost_wrong=9.0, cost_silence=0.0)

        # p_correct = 0.9
        # E[U] = 0.9 * 1.0 - 0.1 * 9.0 = 0.9 - 0.9 = 0.0
        assert abs(policy.expected_utility_answer(0.9)) < 1e-6

        # p_correct = 1.0 (perfect)
        # E[U] = 1.0 * 1.0 - 0.0 * 9.0 = 1.0
        assert abs(policy.expected_utility_answer(1.0) - 1.0) < 1e-6

    def test_expected_utility_silence(self):
        """Test expected utility calculation for silence."""
        policy = AnswerPolicy(benefit_correct=1.0, cost_wrong=9.0, cost_silence=0.5)
        assert abs(policy.expected_utility_silence() - (-0.5)) < 1e-6

    def test_threshold_basics(self):
        """Test threshold calculation basics (Review Checkpoint 2.1.1)."""
        # B=1, C=9, A=0 → threshold = 0.9
        policy1 = AnswerPolicy(benefit_correct=1.0, cost_wrong=9.0, cost_silence=0.0)
        assert abs(policy1.threshold() - 0.9) < 1e-6

        # B=1, C=50, A=0 → threshold ≈ 0.98
        policy2 = AnswerPolicy(benefit_correct=1.0, cost_wrong=50.0, cost_silence=0.0)
        expected2 = (50.0 - 0.0) / (50.0 + 1.0)  # ≈ 0.9804
        assert abs(policy2.threshold() - expected2) < 1e-6

        # B=1, C=1, A=0 → threshold = 0.5
        policy3 = AnswerPolicy(benefit_correct=1.0, cost_wrong=1.0, cost_silence=0.0)
        assert abs(policy3.threshold() - 0.5) < 1e-6

    def test_edge_cases(self):
        """Test edge cases (Review Checkpoint 2.1.2)."""
        # A > C (silence "more expensive" than wrong) → threshold < 0 → clamped to 0
        policy = AnswerPolicy(benefit_correct=1.0, cost_wrong=1.0, cost_silence=2.0)
        assert policy.threshold() == 0.0  # Clamped

        # C very large (Kids Policy) → threshold near 1, but < 1
        kids_policy = AnswerPolicy(
            benefit_correct=1.0, cost_wrong=1000.0, cost_silence=0.0
        )
        threshold = kids_policy.threshold()
        assert 0.999 < threshold < 1.0  # Near 1, but strictly < 1

    def test_monotonicity(self):
        """Test monotonicity: increasing p_correct never flips from answer to silence (Review Checkpoint 2.1.3)."""
        policy = AnswerPolicy(benefit_correct=1.0, cost_wrong=9.0, cost_silence=0.0)
        threshold = policy.threshold()  # 0.9

        # Test sequence: p_correct increasing
        p_values = [0.0, 0.5, 0.85, 0.9, 0.95, 1.0]
        decisions = [policy.decide(p) for p in p_values]

        # Find first "answer" decision
        first_answer_idx = next(
            (i for i, d in enumerate(decisions) if d == "answer"), None
        )
        if first_answer_idx is not None:
            # All subsequent decisions must be "answer" (monotonicity)
            for i in range(first_answer_idx + 1, len(decisions)):
                assert decisions[i] == "answer", (
                    f"Monotonicity violated at p_correct={p_values[i]}"
                )

    def test_validation(self):
        """Test parameter validation."""
        # Negative benefit_correct
        with pytest.raises(ValueError):
            AnswerPolicy(benefit_correct=-1.0, cost_wrong=9.0, cost_silence=0.0)

        # Negative cost_wrong
        with pytest.raises(ValueError):
            AnswerPolicy(benefit_correct=1.0, cost_wrong=-1.0, cost_silence=0.0)

        # Negative cost_silence
        with pytest.raises(ValueError):
            AnswerPolicy(benefit_correct=1.0, cost_wrong=9.0, cost_silence=-1.0)

        # Both benefit and cost zero
        with pytest.raises(ValueError):
            AnswerPolicy(benefit_correct=0.0, cost_wrong=0.0, cost_silence=0.0)


class TestPredefinedPolicies:
    """Test predefined policy configurations."""

    def test_default_policy(self):
        """Test default policy."""
        policy = get_policy("default")
        assert policy.policy_name == "default"
        assert policy.benefit_correct == 1.0
        assert policy.cost_wrong == 5.0
        assert policy.cost_silence == 0.5

    def test_kids_policy(self):
        """Test kids policy (high cost for wrong answers)."""
        policy = get_policy("kids")
        assert policy.policy_name == "kids"
        assert policy.cost_wrong == 50.0
        # Threshold should be approximately 0.98
        assert abs(policy.threshold() - (50.0 - 0.0) / (50.0 + 1.0)) < 1e-6

        # High confidence required
        assert policy.decide(0.95) == "silence"  # Below threshold
        assert policy.decide(0.99) == "answer"  # Above threshold

    def test_internal_debug_policy(self):
        """Test internal debug policy (low cost for wrong answers)."""
        policy = get_policy("internal_debug")
        assert policy.policy_name == "internal_debug"
        assert policy.cost_wrong == 1.0
        assert policy.cost_silence == 2.0

        # Threshold should be negative (clamped to 0.0), so always answers
        assert policy.threshold() == 0.0
        assert policy.decide(0.1) == "answer"  # Even low confidence answers

    def test_strict_policy(self):
        """Test strict policy."""
        policy = get_policy("strict")
        assert policy.policy_name == "strict"
        assert policy.cost_wrong == 20.0

    def test_permissive_policy(self):
        """Test permissive policy."""
        policy = get_policy("permissive")
        assert policy.policy_name == "permissive"
        assert policy.cost_wrong == 2.0

    def test_invalid_policy_name(self):
        """Test error handling for invalid policy name."""
        with pytest.raises(KeyError):
            get_policy("nonexistent")


class TestPolicyProvider:
    """Test PolicyProvider class."""

    def test_default_provider(self):
        """Test default provider with predefined policies."""
        provider = PolicyProvider()
        policy = provider.for_tenant("test_tenant")
        assert policy.policy_name == "default"

    def test_tenant_policy_mapping(self):
        """Test per-tenant policy mapping."""
        provider = PolicyProvider(
            tenant_policy_map={
                "tenant_kids": "kids",
                "tenant_enterprise": "default",
            }
        )

        kids_policy = provider.for_tenant("tenant_kids")
        assert kids_policy.policy_name == "kids"

        default_policy = provider.for_tenant("tenant_enterprise")
        assert default_policy.policy_name == "default"

        # Unknown tenant falls back to default
        fallback_policy = provider.for_tenant("unknown_tenant")
        assert fallback_policy.policy_name == "default"

    def test_route_policy_mapping(self):
        """Test per-route policy mapping."""
        provider = PolicyProvider(
            route_policy_map={
                "/api/kids": "kids",
                "/api/public": "strict",
            }
        )

        kids_policy = provider.for_tenant("any_tenant", route="/api/kids")
        assert kids_policy.policy_name == "kids"

        strict_policy = provider.for_tenant("any_tenant", route="/api/public")
        assert strict_policy.policy_name == "strict"

    def test_context_based_policy(self):
        """Test context-based policy selection."""
        provider = PolicyProvider()

        # Context with policy name
        policy = provider.for_tenant("any_tenant", context={"policy": "kids"})
        assert policy.policy_name == "kids"

        # Context without policy falls back to default
        policy = provider.for_tenant("any_tenant", context={})
        assert policy.policy_name == "default"

    def test_priority_order(self):
        """Test policy selection priority: route > tenant > context > default."""
        provider = PolicyProvider(
            tenant_policy_map={"tenant1": "kids"},
            route_policy_map={"/api/public": "strict"},
        )

        # Route takes priority over tenant
        policy = provider.for_tenant(
            "tenant1", route="/api/public", context={"policy": "default"}
        )
        assert policy.policy_name == "strict"

        # Tenant takes priority over context
        policy = provider.for_tenant("tenant1", context={"policy": "default"})
        assert policy.policy_name == "kids"

        # Context takes priority over default
        policy = provider.for_tenant("unknown", context={"policy": "strict"})
        assert policy.policy_name == "strict"

    def test_add_policy(self):
        """Test adding custom policy."""
        provider = PolicyProvider()
        custom_policy = AnswerPolicy(
            benefit_correct=1.0, cost_wrong=30.0, cost_silence=0.0, policy_name="custom"
        )

        provider.add_policy(custom_policy)
        retrieved = provider.get_policy("custom")
        assert retrieved.policy_name == "custom"
        assert retrieved.cost_wrong == 30.0

    def test_get_policy_error(self):
        """Test error handling for non-existent policy."""
        provider = PolicyProvider()
        with pytest.raises(KeyError):
            provider.get_policy("nonexistent")
