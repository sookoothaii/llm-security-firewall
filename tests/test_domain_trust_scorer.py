"""
Tests for Domain Trust Scorer
==============================

Verifies trust scoring for various source domains.
"""

import pytest

from llm_firewall.trust.domain_scorer import DomainTrustScorer


class TestDomainTrustScorer:
    """Test suite for DomainTrustScorer."""

    def setup_method(self):
        """Setup test scorer."""
        self.scorer = DomainTrustScorer()

    def test_tier_1_authoritative(self):
        """Test Tier 1 authoritative sources."""
        test_cases = [
            ("https://nature.com/articles/123", 0.98),
            ("https://science.org/doi/123", 0.98),
            ("https://nejm.org/doi/full/123", 0.98),
        ]

        for url, expected_score in test_cases:
            score, reasoning = self.scorer.score_source(url)
            assert score == expected_score
            assert (
                "nature.com" in reasoning
                or "science.org" in reasoning
                or "nejm.org" in reasoning
            )

    def test_tier_2_academic_government(self):
        """Test Tier 2 academic and government sources."""
        test_cases = [
            ("https://arxiv.org/abs/1234.5678", 0.95),
            ("https://who.int/news/item/123", 0.95),
            ("https://cdc.gov/coronavirus/2019-ncov/", 0.95),
            ("https://mit.edu/research/paper.pdf", 0.88),  # .edu
            ("https://example.gov/report", 0.90),  # .gov
        ]

        for url, expected_score in test_cases:
            score, reasoning = self.scorer.score_source(url)
            assert score == expected_score, (
                f"URL: {url}, got {score}, expected {expected_score}"
            )

    def test_tier_4_wikipedia(self):
        """Test Wikipedia (Tier 4: General Reference)."""
        score, reasoning = self.scorer.score_source(
            "https://en.wikipedia.org/wiki/Paris"
        )

        assert score == 0.70
        assert "wikipedia.org" in reasoning

    def test_tier_5_social_media(self):
        """Test social media (low trust)."""
        test_cases = [
            ("https://reddit.com/r/science/comments/123", 0.30),
            ("https://twitter.com/user/status/123", 0.25),
            ("https://medium.com/@author/article", 0.40),
        ]

        for url, expected_score in test_cases:
            score, reasoning = self.scorer.score_source(url)
            assert score == expected_score

    def test_denylisted_domains(self):
        """Test denylisted domains (trust = 0.0)."""
        test_cases = [
            ("https://example.tk/fake-news", ".tk"),
            ("https://spam.ml/article", ".ml"),
            ("https://test.ga/story", ".ga"),
        ]

        for url, tld in test_cases:
            score, reasoning = self.scorer.score_source(url)
            assert score == 0.0, f"URL {url} should be denylisted (got {score})"
            assert self.scorer.is_denylisted(url)

    def test_unknown_domain_low_trust(self):
        """Test unknown domains get low trust (0.10)."""
        score, reasoning = self.scorer.score_source("https://random-blog-xyz.com/post")

        assert score == 0.10
        assert "Unknown domain" in reasoning or "default low trust" in reasoning.lower()

    def test_signature_bonus(self):
        """Test that signatures increase trust score."""
        # Without signature
        score_no_sig, _ = self.scorer.score_source("https://example.edu/paper.pdf")

        # With signature
        score_with_sig, _ = self.scorer.score_source(
            "https://example.edu/paper.pdf", has_signature=True, signature_type="pgp"
        )

        assert score_with_sig > score_no_sig
        assert score_with_sig == min(score_no_sig + 0.05, 1.0)

    def test_www_prefix_handling(self):
        """Test that www. prefix is handled correctly."""
        score_with_www, _ = self.scorer.score_source(
            "https://www.nature.com/articles/123"
        )
        score_without_www, _ = self.scorer.score_source(
            "https://nature.com/articles/123"
        )

        # Should be identical
        assert score_with_www == score_without_www
        assert score_with_www == 0.98

    def test_batch_scoring(self):
        """Test batch scoring of multiple URLs."""
        urls = [
            "https://nature.com/articles/1",
            "https://arxiv.org/abs/1234",
            "https://reddit.com/r/science/123",
            "https://unknown-domain.xyz/page",
        ]

        results = self.scorer.batch_score(urls)

        assert len(results) == 4
        assert results[urls[0]][0] == 0.98  # nature
        assert results[urls[1]][0] == 0.95  # arxiv
        assert results[urls[2]][0] == 0.30  # reddit
        assert results[urls[3]][0] == 0.10  # unknown

    def test_get_tier_classification(self):
        """Test tier classification from scores."""
        test_cases = [
            (0.98, "Tier 1: Authoritative"),
            (0.90, "Tier 2: Academic/Government"),
            (0.80, "Tier 3: Established Media"),
            (0.70, "Tier 4: General Reference"),
            (0.40, "Tier 5: Social/Community"),
            (0.20, "Tier 6: Low Trust"),
            (0.0, "Tier 7: Denylisted"),
        ]

        for score, expected_tier in test_cases:
            tier = self.scorer.get_tier(score)
            assert tier == expected_tier

    def test_statistics(self):
        """Test scorer statistics."""
        stats = self.scorer.get_statistics()

        assert stats["total_domains"] > 0
        assert stats["tier_1_count"] >= 5  # At least 5 authoritative
        assert stats["denylisted_count"] >= 3  # At least 3 denylisted


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
