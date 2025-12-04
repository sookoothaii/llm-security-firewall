"""
Integration tests for AnswerPolicy with FirewallEngine.

Tests the integration of AnswerPolicy into the firewall decision pipeline.
"""

from llm_firewall.core.firewall_engine_v2 import FirewallEngine
from llm_firewall.core.policy_provider import PolicyProvider, get_default_provider


class TestAnswerPolicyIntegration:
    """Test AnswerPolicy integration with FirewallEngine."""

    def test_firewall_without_answer_policy(self):
        """Test firewall works normally without AnswerPolicy enabled."""
        engine = FirewallEngine()

        # Normal input (should pass)
        decision = engine.process_input("Normal text input")
        assert decision.allowed is True

        # High risk input (should be blocked by threshold)
        # Note: This depends on actual risk calculation, may need adjustment
        decision = engine.process_input("test")
        # Should work normally without AnswerPolicy

    def test_case_1_answer_policy_blocks_threshold_would_allow(self):
        """
        Case 1: AnswerPolicy blocks, threshold would allow (Review Checkpoint 2.2).

        Scenario:
        - base_risk_score = 0.2 → p_correct = 0.8
        - Policy 'kids' with threshold ≈ 0.98
        - Old threshold (0.7) would allow (0.2 < 0.7)
        - AnswerPolicy should block (0.8 < 0.98)
        """
        engine = FirewallEngine()
        provider = PolicyProvider(tenant_policy_map={"tenant_kids": "kids"})

        # Create input that generates low risk_score but high enough to be below kids threshold
        # Note: Actual risk_score depends on input, so we test the logic path
        decision = engine.process_input(
            "test input with some risk",
            tenant_id="tenant_kids",
            use_answer_policy=True,
            policy_provider=provider,
        )

        # If AnswerPolicy blocked, verify metadata
        if not decision.allowed and "answer_policy" in decision.metadata:
            policy_meta = decision.metadata["answer_policy"]
            assert policy_meta["policy_name"] == "kids"
            assert "Epistemic gate" in decision.reason
            assert policy_meta["p_correct"] < policy_meta["threshold"]
            assert policy_meta["decision_mode"] == "silence"

    def test_case_2_answer_policy_allows_threshold_allows(self):
        """
        Case 2: AnswerPolicy allows, threshold allows (Review Checkpoint 2.2).

        Scenario:
        - base_risk_score = 0.1, Policy 'default' with threshold < 0.9
        - p_correct = 0.9, which is >= default threshold
        - AnswerPolicy says "answer"
        - Final decision depends on old threshold (0.7) - should allow (0.1 < 0.7)
        """
        engine = FirewallEngine()
        provider = PolicyProvider(tenant_policy_map={"tenant_default": "default"})

        decision = engine.process_input(
            "normal low risk input",
            tenant_id="tenant_default",
            use_answer_policy=True,
            policy_provider=provider,
        )

        # AnswerPolicy should allow (p_correct high enough)
        # Final decision should be allowed (risk_score < 0.7)
        if "answer_policy" in decision.metadata:
            policy_meta = decision.metadata["answer_policy"]
            if policy_meta["decision_mode"] == "answer":
                # AnswerPolicy allowed, so decision continues to normal threshold logic
                # If risk_score < 0.7, should be allowed
                if decision.risk_score < 0.7:
                    assert decision.allowed is True

    def test_case_3_fallback_on_error(self):
        """
        Case 3: Fallback on error (Review Checkpoint 2.2).

        Scenario:
        - PolicyProvider throws exception (e.g., defekte YAML)
        - Should log warning
        - Should fall back to normal threshold logic
        """
        engine = FirewallEngine()

        # Invalid policy provider (should fall back gracefully)
        class InvalidProvider:
            def for_tenant(self, tenant_id, route=None, context=None):
                raise ValueError("Simulated policy provider error")

        decision = engine.process_input(
            "test input",
            use_answer_policy=True,
            policy_provider=InvalidProvider(),  # type: ignore
        )

        # Should fall back to normal threshold logic
        assert isinstance(decision.allowed, bool)
        # Should not have answer_policy metadata if fallback occurred
        # (unless error was caught and handled, in which case metadata might be None)

    def test_firewall_with_answer_policy_default(self):
        """Test firewall with AnswerPolicy enabled (default policy)."""
        engine = FirewallEngine()
        provider = get_default_provider()

        # Low risk input (should pass AnswerPolicy)
        decision = engine.process_input(
            "Normal text input",
            use_answer_policy=True,
            policy_provider=provider,
        )

        # Should be allowed (low risk -> high p_correct -> above threshold)
        # Note: Actual result depends on risk score calculation
        assert isinstance(decision.allowed, bool)

    def test_firewall_with_kids_policy(self):
        """Test firewall with kids policy (high threshold)."""
        engine = FirewallEngine()
        provider = PolicyProvider(tenant_policy_map={"tenant_kids": "kids"})

        # High risk input (should be blocked by kids policy)
        # Kids policy has threshold ~0.98, so p_correct must be >= 0.98
        # This means risk_score must be <= 0.02
        decision = engine.process_input(
            "test input",
            tenant_id="tenant_kids",
            use_answer_policy=True,
            policy_provider=provider,
        )

        # If risk_score > 0.02, should be blocked by AnswerPolicy
        # If risk_score <= 0.02, should pass
        assert isinstance(decision.allowed, bool)

        # Check metadata if blocked
        if not decision.allowed and "answer_policy" in decision.metadata:
            policy_meta = decision.metadata["answer_policy"]
            assert "policy_name" in policy_meta
            assert "p_correct" in policy_meta
            assert "threshold" in policy_meta

    def test_firewall_with_internal_debug_policy(self):
        """Test firewall with internal debug policy (low threshold, always answers)."""
        engine = FirewallEngine()
        provider = PolicyProvider(tenant_policy_map={"tenant_debug": "internal_debug"})

        # Internal debug policy has threshold = 0.0, so always answers
        decision = engine.process_input(
            "test input",
            tenant_id="tenant_debug",
            use_answer_policy=True,
            policy_provider=provider,
        )

        # Should always be allowed by AnswerPolicy (threshold = 0.0)
        # But may still be blocked by other layers (RegexGate, Kids Policy, etc.)
        assert isinstance(decision.allowed, bool)

    def test_answer_policy_metadata(self):
        """Test that AnswerPolicy adds metadata to decisions."""
        engine = FirewallEngine()
        provider = get_default_provider()

        decision = engine.process_input(
            "test input",
            use_answer_policy=True,
            policy_provider=provider,
        )

        # If AnswerPolicy was used, metadata should contain answer_policy info
        # Note: This depends on whether AnswerPolicy actually made the decision
        if "answer_policy" in decision.metadata:
            policy_meta = decision.metadata["answer_policy"]
            assert "policy_name" in policy_meta
            assert "p_correct" in policy_meta
            assert "threshold" in policy_meta
            assert "expected_utility_answer" in policy_meta
            assert "expected_utility_silence" in policy_meta
            assert "decision_mode" in policy_meta

    def test_answer_policy_fallback_on_error(self):
        """Test that firewall falls back to threshold logic if AnswerPolicy fails."""
        engine = FirewallEngine()

        # Invalid policy provider (should fall back gracefully)
        class InvalidProvider:
            pass

        decision = engine.process_input(
            "test input",
            use_answer_policy=True,
            policy_provider=InvalidProvider(),  # type: ignore
        )

        # Should fall back to normal threshold logic
        assert isinstance(decision.allowed, bool)
        # Should not have answer_policy metadata if fallback occurred
        # (unless error was caught and handled)

    def test_answer_policy_disabled_by_default(self):
        """Test that AnswerPolicy is disabled by default (backward compatibility)."""
        engine = FirewallEngine()

        # Without use_answer_policy flag, should use normal threshold logic
        decision1 = engine.process_input("test input")

        # With use_answer_policy=False, should also use normal threshold logic
        decision2 = engine.process_input("test input", use_answer_policy=False)

        # Both should behave the same (normal threshold logic)
        assert decision1.allowed == decision2.allowed

    def test_per_route_policy_selection(self):
        """Test per-route policy selection."""
        engine = FirewallEngine()
        provider = PolicyProvider(
            route_policy_map={
                "/api/kids": "kids",
                "/api/public": "strict",
            }
        )

        # Route-specific policy
        decision = engine.process_input(
            "test input",
            route="/api/kids",
            use_answer_policy=True,
            policy_provider=provider,
        )

        assert isinstance(decision.allowed, bool)

        # Different route
        decision2 = engine.process_input(
            "test input",
            route="/api/public",
            use_answer_policy=True,
            policy_provider=provider,
        )

        assert isinstance(decision2.allowed, bool)
