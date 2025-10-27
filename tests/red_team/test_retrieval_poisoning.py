"""
Red-Team Test: Retrieval Poisoning Attack
==========================================

Tests resistance to biased source selection and RAG poisoning.

Attack Vector:
- Attacker provides only sources supporting one viewpoint
- Filters out contradictory evidence
- Creates echo chamber through biased retrieval

Expected Defense:
- Source diversity checks
- Multi-source corroboration requirements
- NLI detects missing perspectives
"""

import pytest
from src_hexagonal.services.honesty.evidence_pipeline import (
    EvidencePipeline, PipelineConfig, EvidenceRecord
)
from src_hexagonal.services.honesty.evidence_validator import EvidenceValidator
from src_hexagonal.services.honesty.domain_trust_scorer import DomainTrustScorer
from src_hexagonal.services.honesty.source_verifier import SourceVerifier
from src_hexagonal.services.honesty.nli_consistency import FakeNLI


class TestRetrievalPoisoning:
    """Red-Team: Retrieval poisoning and biased source selection."""
    
    def setup_method(self):
        """Setup pipeline."""
        self.pipeline = EvidencePipeline(
            config=PipelineConfig(
                tau_trust=0.75,
                tau_nli=0.85,
                require_corroboration=True,
                min_corroborations=2
            ),
            evidence_validator=EvidenceValidator("red-team-retrieval"),
            domain_trust_scorer=DomainTrustScorer(),
            source_verifier=SourceVerifier(timeout=5),
            nli_model=FakeNLI()
        )
    
    def test_single_sided_sources_detected(self):
        """Test detection of one-sided source selection."""
        # Attack: All pro-X sources, no contra
        pro_x_records = [
            EvidenceRecord(
                content="X is definitely beneficial",
                source_url="https://pro-x-advocacy.org/study1",
                kb_corroborations=0
            ),
            EvidenceRecord(
                content="X shows clear advantages",
                source_url="https://pro-x-research.com/paper2",
                kb_corroborations=0
            ),
            EvidenceRecord(
                content="X is universally accepted",
                source_url="https://x-supporters.net/article3",
                kb_corroborations=0
            )
        ]
        
        kb = []  # Empty KB (no prior knowledge)
        
        results = []
        for record in pro_x_records:
            result = self.pipeline.process(record, kb)
            results.append(result)
        
        # All should be quarantined due to:
        # - Low domain trust (unknown domains)
        # - Insufficient corroboration (0 < 2)
        quarantined = [r for r in results if r['decision'] == 'QUARANTINE']
        
        assert len(quarantined) == 3  # All quarantined
        
        # Check reasons
        for result in results:
            assert any('low_trust' in r or 'low_corroboration' in r 
                      for r in result['reasons'])
    
    def test_insufficient_corroboration_blocks_claim(self):
        """Test that single-source claims are blocked."""
        # Attack: High-trust source but no corroboration
        record = EvidenceRecord(
            content="Controversial claim Z",
            source_url="https://nature.com/articles/controversial",
            kb_corroborations=0  # No KB support!
        )
        
        kb = []  # No corroborating KB facts
        result = self.pipeline.process(record, kb)
        
        # High trust (nature.com = 0.98) but no corroboration
        assert result['decision'] == 'QUARANTINE'
        assert result['trust'] > 0.9  # Trust is high
        assert any('low_corroboration' in r for r in result['reasons'])
    
    def test_low_trust_sources_rejected_even_with_corroboration(self):
        """Test that low-trust sources are rejected despite corroboration."""
        # Attack: Multiple low-trust sources all saying same thing
        record = EvidenceRecord(
            content="Dubious claim from unreliable sources",
            source_url="https://random-blog.xyz/article",
            kb_corroborations=3  # Artificially high
        )
        
        kb = ["dubious claim"]  # KB has it (NLI will match)
        result = self.pipeline.process(record, kb)
        
        # Low trust (unknown domain = 0.10) should trigger quarantine
        assert result['decision'] == 'QUARANTINE'
        assert result['trust'] < 0.75
        assert any('low_trust' in r for r in result['reasons'])
    
    def test_source_diversity_requirement(self):
        """Test that source diversity is implicitly enforced."""
        # Attack: Multiple sources from same domain
        same_domain_records = [
            EvidenceRecord(
                content="Claim A from blog",
                source_url="https://biased-blog.com/post1",
                kb_corroborations=0
            ),
            EvidenceRecord(
                content="Claim B from same blog",
                source_url="https://biased-blog.com/post2",
                kb_corroborations=0
            )
        ]
        
        kb = []
        results = []
        
        for record in same_domain_records:
            result = self.pipeline.process(record, kb)
            results.append(result)
        
        # Both should be quarantined (low trust + no corroboration)
        assert all(r['decision'] == 'QUARANTINE' for r in results)
    
    def test_high_trust_with_corroboration_passes(self):
        """Test that legitimate multi-source evidence passes."""
        # NOT an attack: Proper evidence
        record = EvidenceRecord(
            content="Well-established scientific fact",
            source_url="https://nature.com/articles/established-fact",
            kb_corroborations=3  # Multiple KB facts support
        )
        
        kb = ["well-established scientific fact documented in multiple sources"]
        result = self.pipeline.process(record, kb)
        
        # Should PROMOTE (high trust + corroboration + NLI match)
        assert result['decision'] == 'PROMOTE'
        assert result['trust'] > 0.9
        assert result['nli'] > 0.8
        assert result['corroborations'] >= 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

