"""
Unit Tests for Ground Truth Scorer
===================================

Tests:
1. KB coverage scoring (0 facts → 0.0, 10 facts → saturated)
2. Source quality scoring
3. Recency scoring with domain half-lives
4. Domain detection
5. Overall score computation
"""

import pytest
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src_hexagonal.services.honesty.ground_truth_scorer import (
    GroundTruthScorer,
    DOMAIN_CONFIGS
)


class TestGroundTruthScorer:
    """Test suite for GroundTruthScorer"""
    
    def setup_method(self):
        """Setup before each test"""
        self.scorer = GroundTruthScorer()
    
    def test_kb_coverage_zero_facts(self):
        """Test: 0 KB facts → coverage score 0.0"""
        result = self.scorer.score(
            query="Test query",
            kb_facts=[],
            sources=[],
            domain='MATH'
        )
        
        assert result.kb_coverage == 0.0
        assert result.kb_fact_count == 0
    
    def test_kb_coverage_saturation(self):
        """Test: Logistic saturation curve - diminishing returns"""
        # 10 facts (saturation point)
        facts_10 = [{'id': i} for i in range(10)]
        result_10 = self.scorer.score("Test", facts_10, [], 'MATH')
        
        # 20 facts (beyond saturation)
        facts_20 = [{'id': i} for i in range(20)]
        result_20 = self.scorer.score("Test", facts_20, [], 'MATH')
        
        # Logistic saturation: n/(1+n) where n = facts/10
        # 10 facts: 1/(1+1) = 0.5
        # 20 facts: 2/(1+2) = 0.667
        assert 0.48 < result_10.kb_coverage < 0.52  # ~0.5
        assert 0.64 < result_20.kb_coverage < 0.70  # ~0.667
        
        # Diminishing returns: 2x facts → only +33% score
        assert result_20.kb_coverage > result_10.kb_coverage
        assert result_20.kb_coverage - result_10.kb_coverage < 0.20
    
    def test_source_quality_verified(self):
        """Test: Verified sources increase quality"""
        sources_unverified = [
            {'url': 'example.com', 'verified': False}
        ]
        
        sources_verified = [
            {'url': 'wikipedia.org/wiki/Test', 'verified': True}
        ]
        
        result_unverified = self.scorer.score("Test", [], sources_unverified, 'SCIENCE')
        result_verified = self.scorer.score("Test", [], sources_verified, 'SCIENCE')
        
        assert result_verified.source_quality > result_unverified.source_quality
    
    def test_domain_half_life_math(self):
        """Test: MATH domain never ages (half-life = infinity)"""
        # 10 year old math fact
        old_fact = {
            'id': 1,
            'timestamp': (datetime.now() - timedelta(days=3650)).isoformat()
        }
        
        result = self.scorer.score("Test", [old_fact], [], 'MATH')
        
        # Recency should still be high (math doesn't age)
        assert result.recency_score > 0.95
        assert result.domain_half_life == 999999
    
    def test_domain_half_life_news(self):
        """Test: NEWS domain ages fast (half-life = 30 days)"""
        # 60 day old news
        old_news = {
            'id': 1,
            'timestamp': (datetime.now() - timedelta(days=60)).isoformat()
        }
        
        result = self.scorer.score("Test", [old_news], [], 'NEWS')
        
        # Recency should be low (2 half-lives passed)
        # After 2 half-lives: 2^(-2) = 0.25
        assert result.recency_score < 0.30
        assert result.domain_half_life == 30
    
    def test_domain_specific_weights_math(self):
        """Test: MATH emphasizes KB over sources (GPT-5/Perplexity)"""
        config = DOMAIN_CONFIGS['MATH']
        
        # Math should weight KB high, sources low
        assert config.weight_kb == 0.60  # 60% KB
        assert config.weight_sources == 0.20  # 20% sources
        assert config.weight_recency == 0.20  # 20% recency
    
    def test_overall_score_computation(self):
        """Test: Overall score = weighted average"""
        facts = [{'id': i} for i in range(5)]  # 5 facts
        sources = [{'url': f'source{i}.com', 'verified': True} for i in range(3)]
        
        result = self.scorer.score("Test query", facts, sources, 'SCIENCE')
        
        # Check that overall is in valid range
        assert 0.0 <= result.overall_score <= 1.0
        
        # Check components contribute
        assert result.kb_coverage > 0.0
        assert result.source_quality > 0.0
        
        # Overall should be weighted average
        config = DOMAIN_CONFIGS['SCIENCE']
        expected = (
            config.weight_kb * result.kb_coverage +
            config.weight_sources * result.source_quality +
            config.weight_recency * result.recency_score
        )
        
        assert abs(result.overall_score - expected) < 0.001
    
    def test_domain_detection(self):
        """Test: Auto-detect domain from query"""
        math_query = "Calculate the square root of 16"
        result = self.scorer.score(math_query, [], [], domain=None)
        
        assert result.domain == 'MATH'
    
    def test_authority_domain_bonus(self):
        """Test: Wikipedia, .edu, arxiv increase source quality"""
        sources_authority = [
            {'url': 'https://en.wikipedia.org/wiki/Test'},
            {'url': 'https://arxiv.org/abs/1234.5678'}
        ]
        
        sources_random = [
            {'url': 'https://random-blog.com/test'},
            {'url': 'https://unknown-site.net/article'}
        ]
        
        result_authority = self.scorer.score("Test", [], sources_authority, 'SCIENCE')
        result_random = self.scorer.score("Test", [], sources_random, 'SCIENCE')
        
        assert result_authority.source_quality > result_random.source_quality


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v'])

