"""
Tests for Evidence Validator - Memory-Poisoning Prevention
===========================================================

Critical Security Tests:
- Self-authored evidence rejection
- Supermemory self-created content blocking
- Circular reference detection
- KB self-authored facts blocking
"""

import pytest
from llm_firewall.evidence.validator import EvidenceValidator


class TestEvidenceValidator:
    """Test suite for EvidenceValidator."""
    
    def setup_method(self):
        """Setup test validator."""
        self.validator = EvidenceValidator(instance_id="test-inst-123")
    
    def test_self_authored_evidence_rejected(self):
        """Test that self-authored evidence is rejected."""
        evidence = {
            'content': 'System is production ready',
            'authored_by': 'test-inst-123',
            'source': 'generated'
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence)
        
        assert not is_valid
        assert reason == 'SELF_AUTHORED_EVIDENCE'
        assert self.validator.rejected_count == 1
    
    def test_creator_instance_id_rejected(self):
        """Test that evidence with matching creator_instance_id is rejected."""
        evidence = {
            'content': 'Analysis shows X is true',
            'creator_instance_id': 'test-inst-123',
            'source': 'analysis'
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence)
        
        assert not is_valid
        assert reason == 'SELF_AUTHORED_EVIDENCE'
    
    def test_supermemory_self_created_rejected(self):
        """Test that Supermemory content created by this instance is rejected."""
        evidence = {
            'source': 'supermemory',
            'content': 'Previous session completed successfully',
            'metadata': {
                'creator_instance_id': 'test-inst-123',
                'timestamp': '2025-10-27T10:00:00Z'
            }
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence)
        
        assert not is_valid
        assert reason == 'SELF_AUTHORED_SUPERMEMORY'
    
    def test_supermemory_excluded_from_evidence_rejected(self):
        """Test that Supermemory content marked as excluded is rejected."""
        evidence = {
            'source': 'supermemory',
            'content': 'Session summary',
            'metadata': {
                'creator_instance_id': 'other-inst-456',
                'excluded_from_evidence': True
            }
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence)
        
        assert not is_valid
        assert reason == 'SELF_AUTHORED_SUPERMEMORY'
    
    def test_kb_self_authored_rejected(self):
        """Test that KB facts created by this instance are rejected."""
        evidence = {
            'source': 'kb',
            'content': 'Fact about X',
            'created_by_instance': 'test-inst-123'
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence)
        
        assert not is_valid
        assert reason == 'SELF_AUTHORED_KB'
    
    def test_circular_reference_rejected(self):
        """Test that circular references are detected and rejected."""
        evidence = {
            'content': 'Analysis from previous session',
            'source': 'supermemory',
            'reference_chain': [
                {'instance_id': 'other-inst-456', 'timestamp': '2025-10-27T09:00:00Z'},
                {'instance_id': 'test-inst-123', 'timestamp': '2025-10-27T08:00:00Z'}
            ]
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence)
        
        assert not is_valid
        assert reason == 'CIRCULAR_REFERENCE'
    
    def test_derived_from_instance_rejected(self):
        """Test that evidence derived from this instance's output is rejected."""
        evidence = {
            'content': 'Summary based on previous analysis',
            'source': 'derived',
            'derived_from_instance': 'test-inst-123'
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence)
        
        assert not is_valid
        assert reason == 'CIRCULAR_REFERENCE'
    
    def test_valid_external_evidence_accepted(self):
        """Test that valid external evidence is accepted."""
        evidence = {
            'source': 'wikipedia',
            'url': 'https://en.wikipedia.org/wiki/Paris',
            'content': 'Paris is the capital of France',
            'authored_by': 'wikipedia_editors',
            'creator_instance_id': 'external'
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence)
        
        assert is_valid
        assert reason == 'VALID'
        assert self.validator.rejected_count == 0
    
    def test_valid_supermemory_from_other_instance_accepted(self):
        """Test that Supermemory content from other instances is accepted."""
        evidence = {
            'source': 'supermemory',
            'content': 'Fact from previous user session',
            'metadata': {
                'creator_instance_id': 'other-inst-456',
                'excluded_from_evidence': False
            }
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence)
        
        assert is_valid
        assert reason == 'VALID'
    
    def test_batch_validation(self):
        """Test batch validation of multiple evidence items."""
        evidence_list = [
            # Valid
            {
                'source': 'arxiv',
                'url': 'https://arxiv.org/abs/1234.5678',
                'content': 'Research paper on X',
                'creator_instance_id': 'external'
            },
            # Invalid - self-authored
            {
                'source': 'generated',
                'content': 'My analysis',
                'authored_by': 'test-inst-123'
            },
            # Valid
            {
                'source': 'nature',
                'url': 'https://nature.com/articles/123',
                'content': 'Study on Y',
                'creator_instance_id': 'external'
            },
            # Invalid - supermemory self-created
            {
                'source': 'supermemory',
                'content': 'Session notes',
                'metadata': {'creator_instance_id': 'test-inst-123'}
            }
        ]
        
        valid, rejected = self.validator.validate_batch(evidence_list)
        
        assert len(valid) == 2
        assert len(rejected) == 2
        assert rejected[0]['rejection_reason'] == 'SELF_AUTHORED_EVIDENCE'
        assert rejected[1]['rejection_reason'] == 'SELF_AUTHORED_SUPERMEMORY'
    
    def test_statistics_tracking(self):
        """Test that rejection statistics are tracked correctly."""
        # Create multiple rejections
        self.validator.is_valid_evidence({'authored_by': 'test-inst-123'})
        self.validator.is_valid_evidence({'authored_by': 'test-inst-123'})
        self.validator.is_valid_evidence({
            'source': 'supermemory',
            'metadata': {'creator_instance_id': 'test-inst-123'}
        })
        
        stats = self.validator.get_statistics()
        
        assert stats['total_rejected'] == 3
        assert stats['rejection_reasons']['SELF_AUTHORED_EVIDENCE'] == 2
        assert stats['rejection_reasons']['SELF_AUTHORED_SUPERMEMORY'] == 1
        assert stats['instance_id'] == 'test-inst-123'
    
    def test_missing_source_rejected(self):
        """Test that evidence without source is rejected."""
        evidence = {
            'content': 'Some fact',
            # Missing 'source' field
        }
        
        is_valid, reason = self.validator.is_valid_evidence(evidence)
        
        assert not is_valid
        assert reason == 'MISSING_PROVENANCE'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

