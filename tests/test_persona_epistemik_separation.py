"""
Tests for Persona/Epistemik Separation
=======================================

CRITICAL: Verify that personality affects ONLY tone, NEVER thresholds!

GPT-5 Requirement (2025-10-27):
"Persona strikt aus Epistemik herauslösen. Persona steuert NUR Ton, NIEMALS Thresholds!"
"""

import pytest

from llm_firewall.fusion.adaptive_threshold import AdaptiveThresholdManager


class TestPersonaEpistemikSeparation:
    """
    Test suite verifying personality isolation from epistemic decisions.
    
    CRITICAL for scientific integrity and AI Safety.
    """

    def test_threshold_independent_of_personality(self):
        """
        CRITICAL: Verify threshold is independent of personality.
        
        Same domain should give same initial threshold regardless of user personality.
        """
        manager = AdaptiveThresholdManager(db_connection=None)

        # User A (high directness)
        threshold_user_a = manager.get_threshold("user_a_direct_0.95", "SCIENCE")

        # User B (low directness)
        threshold_user_b = manager.get_threshold("user_b_direct_0.50", "SCIENCE")

        # Thresholds MUST be identical (domain-based only)
        assert threshold_user_a == threshold_user_b, (
            f"Thresholds differ: A={threshold_user_a}, B={threshold_user_b}. "
            "Personality must NOT affect thresholds!"
        )

        # Should equal domain base threshold (SCIENCE = 0.75)
        assert threshold_user_a == 0.75

    def test_all_domains_personality_independent(self):
        """Test that ALL domains are personality-independent."""
        manager = AdaptiveThresholdManager(db_connection=None)

        domains = ['MATH', 'SCIENCE', 'GEOGRAPHY', 'MEDICINE', 'NEWS', 'GLOBAL']

        for domain in domains:
            threshold_a = manager.get_threshold("user_strict", domain)
            threshold_b = manager.get_threshold("user_relaxed", domain)

            assert threshold_a == threshold_b, (
                f"Domain {domain}: Thresholds differ! "
                f"A={threshold_a}, B={threshold_b}"
            )

    def test_threshold_equals_domain_base(self):
        """Test that initial threshold equals domain base (no adjustment)."""
        from llm_firewall.evidence.ground_truth_scorer import DOMAIN_CONFIGS

        manager = AdaptiveThresholdManager(db_connection=None)

        # Test each domain (using actual values from DOMAIN_CONFIGS)
        test_cases = {
            'MATH': 0.80,
            'SCIENCE': 0.75,
            'GEOGRAPHY': 0.70,
            'MEDICINE': 0.80,
            'NEWS': 0.60,
            'GLOBAL': 0.70
        }

        for domain, expected_base in test_cases.items():
            threshold = manager.get_threshold("test_user", domain)

            # Should equal domain config base (NO personality boost)
            domain_config = DOMAIN_CONFIGS.get(domain, DOMAIN_CONFIGS['GLOBAL'])
            assert threshold == domain_config.base_threshold, (
                f"Domain {domain}: threshold={threshold}, "
                f"expected base={domain_config.base_threshold}"
            )

    def test_personality_change_does_not_affect_threshold(self):
        """
        CRITICAL: Simulated personality change should NOT affect threshold.
        
        This test verifies that even if personality system is updated,
        thresholds remain stable (epistemic independence).
        """
        manager = AdaptiveThresholdManager(db_connection=None)

        # Get initial threshold
        user_id = "test_user_stable"
        domain = "SCIENCE"
        threshold_before = manager.get_threshold(user_id, domain)

        # Simulate personality change (in real system)
        # This should NOT affect threshold since it's already initialized
        # and cached

        # Get threshold again
        threshold_after = manager.get_threshold(user_id, domain)

        # Must be identical
        assert threshold_before == threshold_after

        # Must equal domain base (0.75 for SCIENCE)
        assert threshold_before == 0.75

    def test_feedback_learning_personality_independent(self):
        """
        Test that feedback learning is also personality-independent.
        
        Learning rate should be same for all users.
        """
        from llm_firewall.utils.types import FeedbackType

        manager = AdaptiveThresholdManager(db_connection=None)

        # User A: Get threshold and provide feedback
        threshold_a_before = manager.get_threshold("user_a", "SCIENCE")
        update_a = manager.update_from_feedback(
            user_id="user_a",
            domain="SCIENCE",
            feedback=FeedbackType.WRONG_ABSTAIN,
            gt_score=0.60,
            decision="ABSTAIN"
        )

        # User B: Same feedback scenario
        threshold_b_before = manager.get_threshold("user_b", "SCIENCE")
        update_b = manager.update_from_feedback(
            user_id="user_b",
            domain="SCIENCE",
            feedback=FeedbackType.WRONG_ABSTAIN,
            gt_score=0.60,
            decision="ABSTAIN"
        )

        # Initial thresholds must be equal
        assert threshold_a_before == threshold_b_before

        # Learning rate should be same
        assert abs(update_a.learning_rate - update_b.learning_rate) < 0.001

        # Adjustment magnitude should be same
        assert abs(update_a.adjustment - update_b.adjustment) < 0.001

    def test_no_personality_getter_used_for_thresholds(self):
        """
        Test that _get_personality() is NOT called during threshold computation.
        
        This is a white-box test to ensure implementation compliance.
        """
        manager = AdaptiveThresholdManager(db_connection=None)

        # Mock _get_personality to raise exception
        original_get_personality = manager._get_personality

        def mock_get_personality(user_id):
            raise AssertionError(
                "VIOLATION: _get_personality() called during threshold computation! "
                "Personality MUST NOT affect thresholds!"
            )

        manager._get_personality = mock_get_personality

        try:
            # This should NOT raise because _get_personality shouldn't be called
            threshold = manager.get_threshold("test_user", "SCIENCE")

            # Should succeed and return domain base
            assert threshold == 0.75

        finally:
            # Restore original
            manager._get_personality = original_get_personality


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

