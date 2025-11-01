"""
Risk Thresholds - Constants for WARN/BLOCK decisions
=====================================================
Centralized threshold configuration for policy decisions.

Author: Claude Sonnet 4.5 (Autonomous Executive)
Date: 2025-10-31
"""

# =============================================================================
# RISK SCORE THRESHOLDS
# =============================================================================

# WARN threshold: Issue warning but allow content
WARN_THRESHOLD = 0.6

# BLOCK threshold: Hard block, reject content
BLOCK_THRESHOLD = 2.0

# =============================================================================
# TRI-KEY ENFORCEMENT SIGNALS
# =============================================================================

# Transport/Decode indicators (existing + RC2 P4.2 additions)
TRANSPORT_DECODE_INDICATORS = {
    # Existing
    'base64_multiline', 'base64_secret', 'base64_jwt',
    'hex_encoded', 'ascii85', 'morse_code',
    'decoded_unspecified', 'decoded_benign_media',
    'url_encoded', 'punycode_domain',
    # RC2 P4.2: Transport-Indicators Complete
    'rfc2047_encoded',      # MIME encoded-words
    'idna_punycode',        # xn-- domains
    'fullwidth_b64',        # Fullwidth + Base64 combo
    'comment_split_b64',    # Base64 fragmented by comments
    'qp_multiline'          # Quoted-Printable multiline
}

# Unicode obfuscation signals (existing, from risk_weights_v2.py)
UNICODE_OBFUSCATION_SIGNALS = {
    'bidi_controls', 'zero_width_chars', 'fullwidth_forms',
    'unicode_combining_seen', 'unicode_ligature_seen', 'unicode_math_alpha_seen',
    'unicode_enclosed_seen', 'unicode_invisible_space', 'unicode_tag_seen', 'unicode_vs_seen'
}

# STRONG signals (from risk_weights_v2.py STRONG_SIGNALS dict)
# These are signals that indicate high-confidence attack patterns
# (Extracted from STRONG_SIGNALS in risk_weights_v2.py for TRI-KEY logic)
STRONG_SIGNAL_NAMES = {
    'base64_jwt', 'base64_secret', 'aws_key', 'private_key',
    'bash_inject', 'unicode_homoglyph', 'rtl_override', 'bidi_controls',
    'zero_width_chars', 'morse_code'
}

# =============================================================================
# TRI-KEY GATE LOGIC
# =============================================================================

def passes_tri_key_gate(hit: str, hits: list) -> bool:
    """
    Tri-Key Enforcement: entropy/dense_alphabet count ONLY if one of three keys present:
    
    1. Transport/Decode indicator present (Base64, Hex, etc.)
    2. Unicode obfuscation present (Fullwidth, Combining, Bidi, etc.)
    3. STRONG signal present (JWT, Secret, AWS Key, etc.)
    
    This prevents false positives on entropy/dense_alphabet in benign code
    while still catching:
    - Transport-based attacks (Key 1)
    - Unicode-only attacks (Key 2)
    - Strong-signal attacks (Key 3)
    
    Args:
        hit: Current signal being evaluated
        hits: All signals present in text
    
    Returns:
        True if signal should count, False if it should be suppressed
    """
    # Only apply gate to entropy/dense_alphabet (WEAK signals that caused FPR)
    if hit not in {'high_entropy', 'dense_alphabet'}:
        return True  # Not a gated signal, always count
    
    # Check three keys
    has_transport = any(h in TRANSPORT_DECODE_INDICATORS for h in hits)
    has_unicode_obfuscation = any(h in UNICODE_OBFUSCATION_SIGNALS for h in hits)
    has_strong = any(h in STRONG_SIGNAL_NAMES for h in hits)
    
    # Pass if ANY key present
    return has_transport or has_unicode_obfuscation or has_strong


# =============================================================================
# CONTEXT SENSITIVITY
# =============================================================================

# Hysteresis: Avoid flip-flop between WARN/BLOCK near threshold
HYSTERESIS_MARGIN = 0.05  # ±5% around thresholds

def apply_hysteresis(score: float, previous_decision: str = None) -> str:
    """
    Apply hysteresis to prevent flip-flop near thresholds.
    
    Args:
        score: Current risk score
        previous_decision: Previous decision ('ALLOW', 'WARN', 'BLOCK')
    
    Returns:
        Decision ('ALLOW', 'WARN', 'BLOCK')
    """
    if score >= BLOCK_THRESHOLD:
        return 'BLOCK'
    elif score >= WARN_THRESHOLD:
        # Near WARN threshold - check previous decision
        if previous_decision == 'ALLOW' and score < WARN_THRESHOLD + HYSTERESIS_MARGIN:
            return 'ALLOW'  # Don't escalate yet
        return 'WARN'
    else:
        # Near ALLOW/WARN boundary - check previous decision
        if previous_decision == 'WARN' and score > WARN_THRESHOLD - HYSTERESIS_MARGIN:
            return 'WARN'  # Don't de-escalate yet
        return 'ALLOW'

