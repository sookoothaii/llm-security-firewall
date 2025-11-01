# -*- coding: utf-8 -*-
"""
Tests for P2 FPR Recovery (risk_weights_v2)
"""
import pytest
from llm_firewall.policy.risk_weights_v2 import (
    calculate_risk_score,
    decide_action,
    STRONG_SIGNALS,
    MEDIUM_SIGNALS,
    WEAK_SIGNALS,
    TRANSPORT_DECODE_INDICATORS
)


def test_co_occurrence_gate_without_transport():
    """Co-Occurrence Gate: entropy/dense_alphabet without Transport/Decode"""
    hits = ['high_entropy', 'dense_alphabet']
    ctx = {'context': 'natural', 'is_dev_placeholder': False}
    
    risk, contrib = calculate_risk_score(hits, ctx)
    
    # Both should be heavily penalized (0.1x)
    assert risk < 0.1, "Should be very low without Transport/Decode"
    assert 'high_entropy_gate' in contrib or 'dense_alphabet_gate' in contrib


def test_co_occurrence_gate_with_transport():
    """Co-Occurrence Gate: entropy WITH Transport/Decode"""
    hits = ['high_entropy', 'base64_secret']  # base64_secret is Transport
    ctx = {'context': 'natural', 'is_dev_placeholder': False}
    
    risk, contrib = calculate_risk_score(hits, ctx)
    
    # Should be higher with Transport hint
    assert risk > 0.5, "Should be elevated with Transport/Decode"


def test_indicator_gate_code_context():
    """Indicator Gate: <2 indicators in code without STRONG"""
    # Single MEDIUM indicator in code
    hits = ['bidi_controls']
    ctx = {'context': 'code', 'is_dev_placeholder': False}
    
    risk, contrib = calculate_risk_score(hits, ctx)
    
    # Should trigger Indicator Gate penalty
    assert 'indicator_gate' in contrib
    assert risk <= MEDIUM_SIGNALS['bidi_controls'] * 0.5 * 0.5  # dampened + gate


def test_indicator_gate_with_strong():
    """Indicator Gate: STRONG bypasses gate"""
    hits = ['pgp_armor']  # STRONG signal
    ctx = {'context': 'code', 'is_dev_placeholder': False}
    
    risk, contrib = calculate_risk_score(hits, ctx)
    
    # Should NOT trigger Indicator Gate (STRONG present)
    assert 'indicator_gate' not in contrib
    assert risk == STRONG_SIGNALS['pgp_armor']  # No dampening on STRONG


def test_indicator_gate_multiple_indicators():
    """Indicator Gate: ≥2 indicators bypass gate"""
    hits = ['bidi_controls', 'zero_width_chars']  # 2 MEDIUM
    ctx = {'context': 'code', 'is_dev_placeholder': False}
    
    risk, contrib = calculate_risk_score(hits, ctx)
    
    # Should NOT trigger Indicator Gate (≥2 indicators)
    assert 'indicator_gate' not in contrib


def test_context_dampening_conservative():
    """V2 dampening more conservative than V1"""
    hits = ['fullwidth_forms', 'mixed_scripts']  # Both WEAK
    ctx_code = {'context': 'code', 'is_dev_placeholder': False}
    ctx_natural = {'context': 'natural', 'is_dev_placeholder': False}
    
    risk_code, _ = calculate_risk_score(hits, ctx_code)
    risk_natural, _ = calculate_risk_score(hits, ctx_natural)
    
    # Code should be heavily dampened
    assert risk_code < risk_natural * 0.5, "Code context should dampen WEAK signals heavily"


def test_dev_placeholder():
    """Dev placeholder → zero risk"""
    hits = ['chain_decoded_3_stages', 'pgp_armor']  # Even STRONG signals
    ctx = {'context': 'natural', 'is_dev_placeholder': True}
    
    risk, contrib = calculate_risk_score(hits, ctx)
    
    assert risk == 0.0
    assert 'dev_placeholder' in contrib


def test_decide_action_thresholds():
    """Decide action with V2 default thresholds"""
    import os
    
    # Save original ENV
    orig_warn = os.getenv('P2_WARN_TH')
    orig_block = os.getenv('P2_BLOCK_TH')
    
    try:
        # Set explicit thresholds
        os.environ['P2_WARN_TH'] = '1.8'
        os.environ['P2_BLOCK_TH'] = '2.8'
        
        ctx = {'context': 'natural', 'is_dev_placeholder': False}
        
        # PASS case
        action, risk, _ = decide_action(['fullwidth_forms'], ctx)
        assert action == 'PASS'
        assert risk < 1.8
        
        # WARN case
        action, risk, _ = decide_action(['bidi_controls', 'zero_width_chars'], ctx)
        if risk >= 1.8:
            assert action in ('WARN', 'BLOCK')
        
        # BLOCK case
        action, risk, _ = decide_action(['pgp_armor', 'chain_decoded_2_stages'], ctx)
        assert action == 'BLOCK'
        assert risk >= 2.8
        
    finally:
        # Restore ENV
        if orig_warn:
            os.environ['P2_WARN_TH'] = orig_warn
        elif 'P2_WARN_TH' in os.environ:
            del os.environ['P2_WARN_TH']
        
        if orig_block:
            os.environ['P2_BLOCK_TH'] = orig_block
        elif 'P2_BLOCK_TH' in os.environ:
            del os.environ['P2_BLOCK_TH']


def test_transport_decode_indicators_complete():
    """Verify TRANSPORT_DECODE_INDICATORS mapping"""
    expected = {
        'base64_secret', 'base85', 'rfc2047', 'armor_markers',
        'chain_decoded_1_stages', 'chain_decoded_2_stages', 'chain_decoded_3_stages',
        'any_armor', 'pgp_armor', 'smime_ct'
    }
    assert TRANSPORT_DECODE_INDICATORS == expected


def test_weak_signals_reduced():
    """Verify V2 WEAK signals are reduced from V1"""
    # Expected reductions
    assert WEAK_SIGNALS['fullwidth_forms'] == 0.2  # Was 0.3 in V1
    assert WEAK_SIGNALS['high_entropy'] == 0.12     # Was 0.15 in V1
    assert WEAK_SIGNALS['css_unescaped'] == 0.15    # Was 0.2 in V1

