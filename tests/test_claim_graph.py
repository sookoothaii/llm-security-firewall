"""
Tests for Source-Attribution Graph
Creator: Joerg Bollwahn
Date: 2025-10-30
"""

import pytest

from src.llm_firewall.evidence.graph import ClaimGraph


class TestClaimGraphBasics:
    """Test basic graph operations."""

    def test_add_claim(self):
        """Test adding claims."""
        g = ClaimGraph()
        g.add_claim("C1", "Test claim text")
        assert "C1" in g._claims
        assert g.get_claim_text("C1") == "Test claim text"

    def test_add_source(self):
        """Test adding sources."""
        g = ClaimGraph()
        g.add_source("S1", {"author": "Smith", "year": 2025})
        assert "S1" in g._sources
        metadata = g.get_source_metadata("S1")
        assert metadata["author"] == "Smith"

    def test_add_claim_support(self):
        """Test adding support edges."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")

        g.add_claim_support("C1", "S1", trust=0.9, recency=0.8, support_score=0.7)

        sources = g.get_supporting_sources("C1")
        assert "S1" in sources

    def test_add_citation(self):
        """Test adding citation edges."""
        g = ClaimGraph()
        g.add_source("S1")
        g.add_source("S2")

        g.add_citation("S1", "S2")  # S1 cites S2

        citations = g.get_source_citations("S1")
        assert "S2" in citations


class TestClaimGraphValidation:
    """Test validation and error handling."""

    def test_support_without_claim_raises(self):
        """Adding support without claim should raise."""
        g = ClaimGraph()
        g.add_source("S1")

        with pytest.raises(AssertionError, match="must be registered"):
            g.add_claim_support("C_NOT_EXIST", "S1", 0.8, 0.8, 0.7)

    def test_support_without_source_raises(self):
        """Adding support without source should raise."""
        g = ClaimGraph()
        g.add_claim("C1")

        with pytest.raises(AssertionError, match="must be registered"):
            g.add_claim_support("C1", "S_NOT_EXIST", 0.8, 0.8, 0.7)

    def test_invalid_trust_raises(self):
        """Trust outside [0,1] should raise."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")

        with pytest.raises(ValueError, match="trust must be in"):
            g.add_claim_support("C1", "S1", trust=1.5, recency=0.8, support_score=0.7)

    def test_invalid_recency_raises(self):
        """Recency outside [0,1] should raise."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")

        with pytest.raises(ValueError, match="recency must be in"):
            g.add_claim_support("C1", "S1", trust=0.8, recency=-0.1, support_score=0.7)


class TestCycleDetection:
    """Test cycle detection logic."""

    def test_no_cycle_linear_chain(self):
        """Linear chain should have no cycle."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")
        g.add_source("S2")
        g.add_source("S3")

        g.add_claim_support("C1", "S1", 0.9, 0.9, 0.8)
        g.add_citation("S1", "S2")  # S1 → S2
        g.add_citation("S2", "S3")  # S2 → S3

        assert g.has_cycle("C1") is False

    def test_detects_simple_cycle(self):
        """Simple cycle S1 → S2 → S1 should be detected."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")
        g.add_source("S2")

        g.add_claim_support("C1", "S1", 0.9, 0.9, 0.8)
        g.add_citation("S1", "S2")
        g.add_citation("S2", "S1")  # Cycle!

        assert g.has_cycle("C1") is True

    def test_detects_three_node_cycle(self):
        """Three-node cycle S1 → S2 → S3 → S1."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")
        g.add_source("S2")
        g.add_source("S3")

        g.add_claim_support("C1", "S1", 0.9, 0.9, 0.8)
        g.add_citation("S1", "S2")
        g.add_citation("S2", "S3")
        g.add_citation("S3", "S1")  # Cycle!

        assert g.has_cycle("C1") is True

    def test_cycle_not_reachable_from_claim(self):
        """Cycle exists but not reachable from claim."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")  # Supports C1
        g.add_source("S2")  # Cycle node
        g.add_source("S3")  # Cycle node

        g.add_claim_support("C1", "S1", 0.9, 0.9, 0.8)
        # S1 is isolated, cycle is in S2 ↔ S3
        g.add_citation("S2", "S3")
        g.add_citation("S3", "S2")

        assert g.has_cycle("C1") is False  # Cycle not reachable from C1


class TestAggregatedSupport:
    """Test aggregated support calculation."""

    def test_single_source_support(self):
        """Single source support calculation."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")
        g.add_claim_support("C1", "S1", trust=0.9, recency=0.8, support_score=0.7)

        support = g.aggregated_support("C1")
        expected = 0.9 * 0.8 * 0.7
        assert abs(support - expected) < 0.001

    def test_multiple_sources_support(self):
        """Multiple sources should sum."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")
        g.add_source("S2")

        g.add_claim_support("C1", "S1", trust=0.9, recency=0.9, support_score=0.6)
        g.add_claim_support("C1", "S2", trust=0.8, recency=0.8, support_score=0.5)

        support = g.aggregated_support("C1")
        expected = (0.9 * 0.9 * 0.6) + (0.8 * 0.8 * 0.5)
        assert abs(support - expected) < 0.001

    def test_no_sources_zero_support(self):
        """Claim with no sources should have zero support."""
        g = ClaimGraph()
        g.add_claim("C1")
        assert g.aggregated_support("C1") == 0.0


class TestPromotionReady:
    """Test promotion readiness check."""

    def test_promotion_blocked_by_cycle(self):
        """Cycle should block promotion."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")
        g.add_source("S2")

        g.add_claim_support("C1", "S1", 0.9, 0.9, 0.8)
        g.add_citation("S1", "S2")
        g.add_citation("S2", "S1")  # Cycle

        assert g.promotion_ready("C1", min_support=0.1) is False

    def test_promotion_blocked_by_low_support(self):
        """Low support should block promotion."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")

        g.add_claim_support("C1", "S1", trust=0.5, recency=0.5, support_score=0.5)

        # Support = 0.5 * 0.5 * 0.5 = 0.125 < 0.5 threshold
        assert g.promotion_ready("C1", min_support=0.5) is False

    def test_promotion_ready_when_valid(self):
        """Valid claim with no cycle and high support."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_source("S1")

        g.add_claim_support("C1", "S1", trust=0.9, recency=0.95, support_score=0.7)

        # Support = 0.9 * 0.95 * 0.7 ≈ 0.5985 > 0.5
        assert g.promotion_ready("C1", min_support=0.5) is True


class TestStatistics:
    """Test graph statistics."""

    def test_statistics_empty_graph(self):
        """Empty graph statistics."""
        g = ClaimGraph()
        stats = g.statistics()
        assert stats["claim_count"] == 0
        assert stats["source_count"] == 0
        assert stats["support_edges"] == 0

    def test_statistics_with_data(self):
        """Graph with data."""
        g = ClaimGraph()
        g.add_claim("C1")
        g.add_claim("C2")
        g.add_source("S1")
        g.add_source("S2")

        g.add_claim_support("C1", "S1", 0.9, 0.9, 0.8)
        g.add_claim_support("C1", "S2", 0.8, 0.8, 0.7)
        g.add_citation("S1", "S2")

        stats = g.statistics()
        assert stats["claim_count"] == 2
        assert stats["source_count"] == 2
        assert stats["support_edges"] == 2
        assert stats["citation_edges"] == 1
        assert stats["claims_with_support"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

