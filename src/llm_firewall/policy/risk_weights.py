# -*- coding: utf-8 -*-
"""
Risk-Weighted Decision System
Context-aware scoring for FPR reduction
"""

# Signal strength categories (BALANCED)
STRONG_SIGNALS = {
    'pgp_armor': 2.0,
    'smime_ct': 2.0,
    'pdf_b64': 1.8,
    'chain_decoded_2_stages': 1.6,
    'chain_decoded_3_stages': 2.0,
    'archive_secret': 1.8,
    'png_metadata': 1.6,
    'any_armor': 1.5,
}

MEDIUM_SIGNALS = {
    'bidi_controls': 1.0,
    'zero_width_chars': 0.9,
    'utf7_segments': 0.7,
    'armor_markers': 0.8,
    'pdf_xmp_detected': 0.6,
    'yaml_anchors_neutralized': 0.6,
    'rfc2047': 0.5,
    'base64_secret': 0.7,
    'base85': 0.6,
    'chain_decoded_1_stages': 0.5,
}

WEAK_SIGNALS = {
    'fullwidth_forms': 0.3,
    'mixed_scripts': 0.3,
    'mime_headers_unfolded': 0.2,
    'dense_alphabet': 0.2,
    'high_entropy': 0.15,
    'css_unescaped': 0.2,
    'js_unescaped': 0.2,
}

# Context dampening factors
CONTEXT_DAMPEN = {
    'code': {
        'STRONG': 1.0,  # No dampening for strong signals
        'MEDIUM': 0.6,  # Moderate dampening (was 0.4)
        'WEAK': 0.3,    # Heavy for weak (was 0.2)
    },
    'config': {
        'STRONG': 1.0,
        'MEDIUM': 0.7,  # Moderate (was 0.5)
        'WEAK': 0.4,    # Moderate (was 0.3)
    },
    'natural': {
        'STRONG': 1.0,
        'MEDIUM': 1.0,
        'WEAK': 1.0,
    }
}

def calculate_risk_score(hits: list, context_meta: dict) -> tuple:
    """
    Calculate weighted risk score
    
    Args:
        hits: List of detector hit names
        context_meta: Context metadata from classify_context()
    
    Returns:
        (total_score, contributions_dict)
    """
    context = context_meta.get('context', 'natural')
    is_dev = context_meta.get('is_dev_placeholder', False)
    
    # Dev placeholder → zero risk (lab only)
    if is_dev:
        return 0.0, {'dev_placeholder': -99}
    
    dampen = CONTEXT_DAMPEN[context]
    contributions = {}
    total = 0.0
    
    for hit in hits:
        # Determine signal strength
        if hit in STRONG_SIGNALS:
            base_score = STRONG_SIGNALS[hit]
            factor = dampen['STRONG']
            strength = 'STRONG'
        elif hit in MEDIUM_SIGNALS:
            base_score = MEDIUM_SIGNALS[hit]
            factor = dampen['MEDIUM']
            strength = 'MEDIUM'
        elif hit in WEAK_SIGNALS:
            base_score = WEAK_SIGNALS[hit]
            factor = dampen['WEAK']
            strength = 'WEAK'
        else:
            # Unknown signal - treat as weak
            base_score = 0.1
            factor = dampen['WEAK']
            strength = 'WEAK'
        
        score = base_score * factor
        total += score
        contributions[hit] = {
            'base': base_score,
            'dampened': score,
            'strength': strength,
            'context': context
        }
    
    return total, contributions

def decide_action(hits: list, context_meta: dict, warn_threshold: float = 1.5, block_threshold: float = 2.5) -> tuple:
    """
    Make final decision with context-aware weights
    
    Args:
        hits: List of detector hits
        context_meta: Context classification
        warn_threshold: WARN threshold (default 1.5, was 0.3)
        block_threshold: BLOCK threshold (default 2.5, was 1.0)
    
    Returns:
        (action, risk_score, contributions)
    """
    risk, contrib = calculate_risk_score(hits, context_meta)
    
    if risk >= block_threshold:
        action = 'BLOCK'
    elif risk >= warn_threshold:
        action = 'WARN'
    else:
        action = 'PASS'
    
    return action, risk, contrib

