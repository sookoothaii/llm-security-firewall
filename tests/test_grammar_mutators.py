"""
Tests for Grammar Mutators
Creator: Joerg Bollwahn
Date: 2025-10-30
"""

import random

from src.llm_firewall.redteam.grammar_mutators import (
    MUTATORS,
    mutate,
    random_mutation_plan,
    risk_feature_coverage,
)


class TestIndividualMutators:
    """Test individual mutator functions."""

    def test_roleplay_mutator(self):
        """Test roleplay jailbreak."""
        result = MUTATORS["roleplay"]("test command")
        assert "override" in result.lower()
        assert "test command" in result

    def test_base64_mutator(self):
        """Test base64 encoding."""
        result = MUTATORS["base64"]("hello")
        assert result != "hello"
        # Decode to verify
        import base64

        decoded = base64.b64decode(result).decode()
        assert decoded == "hello"

    def test_leet_mutator(self):
        """Test leetspeak transformation."""
        result = MUTATORS["leet"]("test")
        assert "7" in result  # 't' -> '7'
        assert "3" in result  # 'e' -> '3'

    def test_homoglyph_mutator(self):
        """Test homoglyph substitution."""
        result = MUTATORS["homoglyph"]("aeo")
        # Should contain Cyrillic lookalikes
        assert result != "aeo"

    def test_punct_burst_mutator(self):
        """Test punctuation burst."""
        result = MUTATORS["punct_burst"]("test")
        assert "!!!" in result
        assert "QUICK" in result


class TestMutationChaining:
    """Test mutation chaining."""

    def test_mutate_single(self):
        """Test single mutation."""
        text = "test input"
        mutated, applied = mutate(text, ["leet"])

        assert mutated != text
        assert applied == ["leet"]

    def test_mutate_chain(self):
        """Test mutation chain."""
        text = "test input"
        mutated, applied = mutate(text, ["leet", "roleplay", "punct_burst"])

        assert mutated != text
        assert len(applied) == 3
        assert "leet" in applied
        assert "roleplay" in applied

    def test_mutate_unknown_skipped(self):
        """Unknown mutators should be skipped."""
        text = "test"
        mutated, applied = mutate(text, ["leet", "unknown_mutator", "roleplay"])

        assert "unknown_mutator" not in applied
        assert "leet" in applied
        assert "roleplay" in applied


class TestRiskFeatureCoverage:
    """Test risk feature coverage tracking."""

    def test_coverage_obfuscations(self):
        """Test obfuscation coverage."""
        applied = ["base64", "leet"]
        cov = risk_feature_coverage(applied)

        assert cov["obfuscations"] == 1
        assert cov["social_engineering"] == 0
        assert cov["language_pressure"] == 0

    def test_coverage_social_engineering(self):
        """Test social engineering coverage."""
        applied = ["roleplay"]
        cov = risk_feature_coverage(applied)

        assert cov["social_engineering"] == 1
        assert cov["obfuscations"] == 0

    def test_coverage_multiple_categories(self):
        """Test multiple category coverage."""
        applied = ["leet", "roleplay", "translation"]
        cov = risk_feature_coverage(applied)

        assert cov["obfuscations"] == 1
        assert cov["social_engineering"] == 1
        assert cov["language_pressure"] == 1

    def test_coverage_empty(self):
        """Empty applied list should have zero coverage."""
        cov = risk_feature_coverage([])
        assert all(v == 0 for v in cov.values())


class TestRandomMutationPlan:
    """Test random mutation plan generation."""

    def test_random_plan_deterministic(self):
        """Same seed should produce same plan."""
        rng1 = random.Random(42)
        rng2 = random.Random(42)

        plan1 = random_mutation_plan(rng1, max_ops=3)
        plan2 = random_mutation_plan(rng2, max_ops=3)

        assert plan1 == plan2

    def test_random_plan_length(self):
        """Plan length should be within bounds."""
        rng = random.Random(1337)
        plan = random_mutation_plan(rng, max_ops=3)

        assert 1 <= len(plan) <= 3

    def test_random_plan_valid_mutators(self):
        """Plan should only contain valid mutator names."""
        rng = random.Random(999)
        plan = random_mutation_plan(rng, max_ops=5)

        for name in plan:
            assert name in MUTATORS


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])

