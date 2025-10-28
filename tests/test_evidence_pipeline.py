"""
Tests for Evidence Pipeline Integration
========================================

End-to-End verification pipeline testing.
"""

import pytest
from llm_firewall.evidence.pipeline import (
    EvidencePipeline, PipelineConfig, EvidenceRecord
)
from llm_firewall.evidence.validator import EvidenceValidator
from llm_firewall.trust.domain_scorer import DomainTrustScorer
from llm_firewall.evidence.source_verifier import SourceVerifier
from llm_firewall.trust.nli_consistency import FakeNLI


class TestEvidencePipeline:
    """Test suite for evidence pipeline integration."""
    
    def setup_method(self):
        """Setup pipeline components."""
        self.validator = EvidenceValidator(instance_id="test-inst")
        self.trust_scorer = DomainTrustScorer()
        self.verifier = SourceVerifier(timeout=5)
        self.nli = FakeNLI()
        
        self.config = PipelineConfig(
            tau_trust=0.75,
            tau_nli=0.85,
            require_corroboration=True,
            min_corroborations=2
        )
        
        self.pipeline = EvidencePipeline(
            config=self.config,
            evidence_validator=self.validator,
            domain_trust_scorer=self.trust_scorer,
            source_verifier=self.verifier,
            nli_model=self.nli
        )
    
    def test_pipeline_promotes_when_all_thresholds_pass(self):
        """Test promotion when all criteria met."""
        record = EvidenceRecord(
            content="Alpha beta gamma delta",
            source_url="https://nature.com/articles/123",
            source_domain="nature.com",
            kb_corroborations=3
        )
        
        kb = ["alpha beta gamma delta epsilon"]
        
        result = self.pipeline.process(record, kb)
        
        # High trust (nature.com = 0.98)
        # NLI match (substring = 1.0)
        # Corroboration sufficient (3 >= 2)
        assert result['decision'] == "PROMOTE"
        assert result['verified'] == True
        assert result['trust'] >= 0.75
        assert result['nli'] >= 0.85
    
    def test_pipeline_quarantines_low_trust(self):
        """Test quarantine when trust too low."""
        record = EvidenceRecord(
            content="Some claim",
            source_url="https://random-blog.com/post",
            kb_corroborations=3
        )
        
        kb = ["Some claim is valid"]
        
        result = self.pipeline.process(record, kb)
        
        # Low trust (unknown domain = 0.10)
        assert result['decision'] == "QUARANTINE"
        assert "low_trust" in result['reasons'][0]
    
    def test_pipeline_quarantines_low_nli(self):
        """Test quarantine when NLI too low."""
        record = EvidenceRecord(
            content="Unrelated content",
            source_url="https://arxiv.org/abs/1234",
            kb_corroborations=3
        )
        
        kb = ["Completely different topic"]
        
        result = self.pipeline.process(record, kb)
        
        # High trust (arxiv = 0.95) but NLI fails
        assert result['decision'] == "QUARANTINE"
        assert any("low_nli" in r for r in result['reasons'])
    
    def test_pipeline_quarantines_insufficient_corroboration(self):
        """Test quarantine when corroboration insufficient."""
        record = EvidenceRecord(
            content="New fact alpha beta",
            source_url="https://nature.com/articles/456",
            kb_corroborations=1  # Less than min (2)
        )
        
        kb = ["alpha beta gamma"]
        
        result = self.pipeline.process(record, kb)
        
        # High trust, NLI ok, but corroboration fails
        assert result['decision'] == "QUARANTINE"
        assert any("low_corroboration" in r for r in result['reasons'])
    
    def test_pipeline_rejects_self_authored(self):
        """Test rejection of self-authored evidence."""
        # Create evidence that would be self-authored
        record = EvidenceRecord(
            content="My own analysis",
            source_url=None,
            source_domain="generated",
            kb_corroborations=3
        )
        
        # Manually mark as self-authored for test
        evidence_obj = {
            'content': record.content,
            'authored_by': 'test-inst',  # Matches validator instance_id
            'source': 'generated'
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence_obj)
        
        assert not is_valid
        assert reason == "SELF_AUTHORED_EVIDENCE"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

