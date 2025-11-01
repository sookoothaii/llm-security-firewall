"""
Tests for Tri-Key Enforcement (RC2 P4.1)
=========================================
Validates that entropy/dense_alphabet count ONLY with:
- Transport/Decode indicator OR
- Unicode obfuscation OR
- STRONG signal

Author: Claude Sonnet 4.5 (Autonomous Executive)
Date: 2025-10-31
"""

import pytest
from llm_firewall.policy.risk_weights_v2 import calculate_risk_score
from llm_firewall.policy.risk_thresholds import passes_tri_key_gate


class TestTriKeyGate:
    """Test Tri-Key gate function"""
    
    def test_entropy_suppressed_without_keys(self):
        """Entropy suppressed when no Transport/Unicode/STRONG present"""
        hits = ['high_entropy', 'dense_alphabet']
        assert not passes_tri_key_gate('high_entropy', hits)
        assert not passes_tri_key_gate('dense_alphabet', hits)
    
    def test_entropy_passes_with_transport(self):
        """Entropy counts when Transport indicator present"""
        hits = ['high_entropy', 'base64_multiline']
        assert passes_tri_key_gate('high_entropy', hits)
    
    def test_entropy_passes_with_unicode_obfuscation(self):
        """Entropy counts when Unicode obfuscation present"""
        hits = ['high_entropy', 'fullwidth_forms']
        assert passes_tri_key_gate('high_entropy', hits)
    
    def test_entropy_passes_with_strong_signal(self):
        """Entropy counts when STRONG signal present"""
        hits = ['high_entropy', 'base64_jwt']
        assert passes_tri_key_gate('high_entropy', hits)
    
    def test_non_entropy_signals_always_pass(self):
        """Non-entropy signals not affected by gate"""
        hits = ['high_entropy']
        assert passes_tri_key_gate('suspicious_concat', hits)  # Should pass regardless


class TestTriKeyEnforcementIntegration:
    """Integration tests with risk scoring"""
    
    def test_entropy_only_suppressed(self):
        """Entropy-only text scores near zero (suppressed)"""
        hits = ['high_entropy', 'dense_alphabet']
        context_meta = {'context': 'natural'}
        
        score, contrib = calculate_risk_score(hits, context_meta)
        
        # Should be suppressed (near zero)
        assert score < 0.1, f"Expected suppressed score, got {score}"
        assert 'high_entropy_suppressed' in contrib
        assert 'dense_alphabet_suppressed' in contrib
    
    def test_entropy_plus_transport_counts(self):
        """Entropy + Transport = counts (Transport key)"""
        hits = ['high_entropy', 'dense_alphabet', 'base64_multiline']
        context_meta = {'context': 'natural'}
        
        score, contrib = calculate_risk_score(hits, context_meta)
        
        # Should count (Transport key present)
        assert score > 0.2, f"Expected score > 0.2, got {score}"
        assert 'high_entropy' in contrib
        assert 'high_entropy_suppressed' not in contrib
    
    def test_entropy_plus_unicode_counts(self):
        """Entropy + Unicode obfuscation = counts (Unicode key)"""
        hits = ['high_entropy', 'dense_alphabet', 'fullwidth_forms']
        context_meta = {'context': 'natural'}
        
        score, contrib = calculate_risk_score(hits, context_meta)
        
        # Should count (Unicode key present)
        assert score > 0.3, f"Expected score > 0.3, got {score}"
        assert 'high_entropy' in contrib
        assert 'high_entropy_suppressed' not in contrib
    
    def test_entropy_plus_strong_counts(self):
        """Entropy + STRONG signal = counts (STRONG key)"""
        hits = ['high_entropy', 'dense_alphabet', 'base64_jwt']
        context_meta = {'context': 'natural'}
        
        score, contrib = calculate_risk_score(hits, context_meta)
        
        # Should count (STRONG key present)
        # Note: base64_jwt alone may not reach 1.0 depending on exact weights
        assert score > 0.2, f"Expected score > 0.2, got {score}"
        assert 'high_entropy' in contrib
        assert 'base64_jwt' in contrib
    
    def test_unicode_only_attack_blocked(self):
        """Unicode-only attack (Fullwidth + entropy) blocks"""
        hits = ['high_entropy', 'dense_alphabet', 'fullwidth_forms', 'unicode_combining_seen']
        context_meta = {'context': 'natural'}
        
        score, contrib = calculate_risk_score(hits, context_meta)
        
        # Should be high enough to WARN or BLOCK
        # fullwidth_forms + unicode_combining_seen = MEDIUM signals
        # entropy/dense count because Unicode key present
        assert score >= 0.6, f"Expected WARN/BLOCK, got score {score}"
    
    def test_benign_code_entropy_suppressed(self):
        """Benign code with entropy but no keys = suppressed"""
        hits = ['high_entropy', 'dense_alphabet', 'code_comment', 'python_import']
        context_meta = {'context': 'code'}
        
        score, contrib = calculate_risk_score(hits, context_meta)
        
        # Entropy should be suppressed (no keys)
        # Context damping also applies
        assert score < 0.2, f"Expected low score for benign code, got {score}"
        assert 'high_entropy_suppressed' in contrib


class TestBypassCoverage:
    """Tests for known bypasses from Handover Report"""
    
    def test_fullwidth_base64_closed(self):
        """Fullwidth Base64 attack (Unicode + Transport keys)"""
        hits = ['high_entropy', 'dense_alphabet', 'fullwidth_forms', 'decoded_unspecified']
        context_meta = {'context': 'natural'}
        
        score, _ = calculate_risk_score(hits, context_meta)
        
        # Both Unicode and Transport keys present → should count
        assert score >= 0.6, "Fullwidth Base64 should WARN/BLOCK"
    
    def test_combining_marks_closed(self):
        """Combining marks attack (Unicode key)"""
        hits = ['high_entropy', 'dense_alphabet', 'unicode_combining_seen']
        context_meta = {'context': 'natural'}
        
        score, _ = calculate_risk_score(hits, context_meta)
        
        # Unicode key present → entropy counts
        assert score >= 0.4, "Combining marks attack should score high"
    
    def test_ligature_attack_closed(self):
        """Ligature obfuscation (Unicode key)"""
        hits = ['high_entropy', 'unicode_ligature_seen']
        context_meta = {'context': 'natural'}
        
        score, _ = calculate_risk_score(hits, context_meta)
        
        # Unicode key present
        assert score >= 0.4, "Ligature attack should score high"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

