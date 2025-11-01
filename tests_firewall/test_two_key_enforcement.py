#!/usr/bin/env python3
"""
Unit tests for RC2 P3.4 Two-Key Enforcement
Ensures entropy/dense signals ONLY fire with Transport indicators
"""
import sys
from pathlib import Path

repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.policy.risk_weights_v2 import calculate_risk_score


def test_entropy_without_transport_eliminated():
    """high_entropy without Transport signal should be eliminated"""
    hits = ['high_entropy', 'dense_alphabet']
    context = {'context': 'code'}
    
    risk, contrib = calculate_risk_score(hits, context)
    
    # Should be near-zero since no transport
    assert risk < 0.1, f"Risk should be ~0 without transport, got {risk}"
    assert 'Tri-Key gate' in str(contrib), "Should have Tri-Key Gate message (RC2 P4 upgrade)"


def test_entropy_with_transport_counts():
    """high_entropy WITH base64_secret should count"""
    hits = ['high_entropy', 'dense_alphabet', 'base64_secret']
    context = {'context': 'code'}
    
    risk, contrib = calculate_risk_score(hits, context)
    
    # Should have risk from entropy + transport (context dampening applies)
    assert risk > 0.3, f"Risk should be >0.3 with transport, got {risk}"
    assert 'base64_secret' in contrib


def test_entropy_with_multiline_counts():
    """high_entropy WITH base64_multiline_detected should count"""
    hits = ['high_entropy', 'base64_multiline_detected']
    context = {'context': 'code'}
    
    risk, contrib = calculate_risk_score(hits, context)
    
    # Should have risk
    assert risk > 0.5, f"Risk should be >0.5 with multiline, got {risk}"


def test_entropy_with_chain_decoded_counts():
    """high_entropy WITH chain_decoded should count"""
    hits = ['dense_alphabet', 'chain_decoded_1_stages']
    context = {'context': 'code'}
    
    risk, contrib = calculate_risk_score(hits, context)
    
    # Should have risk (dampened in code context)
    assert risk > 0.2, f"Risk should be >0.2 with chain_decoded, got {risk}"


def test_normal_code_no_false_positive():
    """Normal code with entropy but no transport should pass"""
    hits = ['high_entropy', 'dense_alphabet']
    context = {'context': 'code'}
    
    risk, contrib = calculate_risk_score(hits, context)
    
    # Near-zero risk
    assert risk < 0.1
    

def test_config_with_entropy_no_transport():
    """Config file with entropy but no transport should not trigger"""
    hits = ['high_entropy']
    context = {'context': 'config'}
    
    risk, contrib = calculate_risk_score(hits, context)
    
    assert risk < 0.1


def test_attack_with_transport_and_entropy():
    """Real attack: Base64 + entropy should trigger"""
    hits = ['base64_multiline_detected', 'high_entropy', 'dense_alphabet', 
            'chain_decoded_1_stages', 'base64_secret']
    context = {'context': 'code'}
    
    risk, contrib = calculate_risk_score(hits, context)
    
    # High risk
    assert risk > 1.0, f"Attack should have high risk, got {risk}"


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])

