"""
Tests for NLI Consistency Checker
==================================

Validates evidence against KB consensus.
"""

import pytest

from llm_firewall.trust.nli_consistency import (
    FakeNLI,
    check_contradiction,
    consistency_against_kb,
)


class TestNLIConsistency:
    """Test suite for NLI consistency checking."""

    def setup_method(self):
        """Setup test NLI model."""
        self.model = FakeNLI()

    def test_nli_max_aggregate(self):
        """Test max aggregation finds strongest support."""
        kb = ["The quick brown fox jumps over the lazy dog."]

        score = consistency_against_kb("brown fox jumps", kb, self.model, "max")

        assert score == 1.0  # Substring match

    def test_nli_mean_aggregate(self):
        """Test mean aggregation averages scores."""
        kb = [
            "Paris is the capital of France",
            "Berlin is the capital of Germany"
        ]

        # "Paris" is in first sentence only
        score_max = consistency_against_kb("Paris", kb, self.model, "max")
        score_mean = consistency_against_kb("Paris", kb, self.model, "mean")

        assert score_max == 1.0   # Found in one
        assert score_mean == 0.5  # Average: 1.0 + 0.0 / 2

    def test_nli_min_aggregate(self):
        """Test min aggregation requires all support."""
        kb = [
            "Paris is the capital of France",
            "Berlin is the capital of Germany"
        ]

        # "capital" is in both sentences
        score = consistency_against_kb("capital", kb, self.model, "min")

        assert score == 1.0  # In both

        # "Paris" only in one
        score = consistency_against_kb("Paris", kb, self.model, "min")

        assert score == 0.0  # Not in all

    def test_empty_kb_returns_zero(self):
        """Test that empty KB returns 0.0."""
        score = consistency_against_kb("test claim", [], self.model, "max")

        assert score == 0.0

    def test_no_match_returns_zero(self):
        """Test that no matching KB facts returns 0.0."""
        kb = ["Completely unrelated fact"]

        score = consistency_against_kb("Different topic", kb, self.model, "max")

        assert score == 0.0

    def test_check_contradiction_simple(self):
        """Test simple contradiction detection."""
        kb = ["Paris is the capital of France"]

        # No contradiction
        score_no = check_contradiction("Paris is capital", kb, self.model)
        assert score_no == 0.0

        # Contradiction (negation)
        score_yes = check_contradiction("Paris is not the capital", kb, self.model)
        assert score_yes > 0.0  # Should detect negation


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

