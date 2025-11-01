"""
Aggregators - K-of-N Families Logic
===================================
Implements family-based signal counting to prevent single-vector attacks
from accumulating high scores through multiple signals of the same type.

Author: Claude Sonnet 4.5 (Autonomous Executive)
Date: 2025-10-31
"""

from collections import defaultdict
from typing import Dict, List

# =============================================================================
# SIGNAL FAMILIES
# =============================================================================

# Defined in risk_weights_v2.py but duplicated here for clarity
SIGNAL_FAMILIES = {
    'Transport': {
        'base64_secret', 'base85', 'rfc2047', 'armor_markers',
        'chain_decoded_1_stages', 'chain_decoded_2_stages', 'chain_decoded_3_stages',
        'any_armor', 'pgp_armor', 'smime_ct',
        'rfc2047_encoded', 'idna_punycode', 'fullwidth_b64', 'comment_split_b64', 'qp_multiline'
    },
    'Unicode': {
        'bidi_controls', 'zero_width_chars', 'fullwidth_forms', 'mixed_scripts',
        'unicode_combining_seen', 'unicode_ligature_seen', 'unicode_math_alpha_seen',
        'unicode_enclosed_seen', 'unicode_invisible_space', 'unicode_tag_seen', 'unicode_vs_seen'
    },
    'Decode': {
        'chain_decoded_1_stages', 'chain_decoded_2_stages', 'chain_decoded_3_stages',
        'yaml_anchors_neutralized', 'utf7_segments'
    },
    'Density': {
        'dense_alphabet', 'high_entropy'
    },
    'Grammar': {
        'yaml_anchors_neutralized', 'css_unescaped', 'js_unescaped', 'mime_headers_unfolded'
    },
    'Archive': {
        'archive_secret', 'pdf_b64', 'pdf_xmp_detected', 'png_metadata'
    },
    'Identifier': {
        'mixed_script_identifier', 'exotic_in_identifier', 'homoglyph_spoof_ge_1'
    },
    'Attack': {
        'sql_keywords_destructive', 'sql_injection_pattern', 'sql_comment_injection',
        'xss_dangerous_scheme', 'xss_script_tag', 'xss_event_handler',
        'path_traversal_dotdot', 'path_system_file_access',
        'rce_log4j_jndi', 'rce_command_injection', 'rce_template_injection',
        'ldap_injection', 'ssrf_internal_target',
        'attack_keyword_with_encoding', 'dangerous_scheme_detected',
        'xss_scheme_obfuscated', 'encoding_near_attack_keyword'
    }
}


def get_signal_family(signal: str) -> str:
    """
    Get family name for a signal.
    
    Args:
        signal: Signal name
    
    Returns:
        Family name or 'Unknown'
    """
    for family, signals in SIGNAL_FAMILIES.items():
        if signal in signals:
            return family
    return 'Unknown'


def count_distinct_families(hits: List[str]) -> int:
    """
    Count number of distinct families represented in hits.
    
    Args:
        hits: List of signal names
    
    Returns:
        Number of distinct families
    """
    families = {get_signal_family(hit) for hit in hits}
    # Remove Unknown family
    families.discard('Unknown')
    return len(families)


def get_family_counts(hits: List[str]) -> Dict[str, int]:
    """
    Count signals per family.
    
    Args:
        hits: List of signal names
    
    Returns:
        Dict mapping family -> signal count
    """
    family_counts = defaultdict(int)

    for hit in hits:
        family = get_signal_family(hit)
        if family != 'Unknown':
            family_counts[family] += 1

    return dict(family_counts)


def k_of_n_families(hits: List[str], k: int = 2) -> bool:
    """
    Check if at least K distinct families are represented.
    
    This prevents single-vector attacks (e.g., 5x Transport signals)
    from scoring high when all evidence is from one family.
    
    Typical thresholds:
    - k=2 for WARN (need 2 orthogonal families)
    - k=3 for BLOCK (need 3 orthogonal families)
    
    Args:
        hits: List of signal names
        k: Minimum number of distinct families required
    
    Returns:
        True if >= k families present, False otherwise
    """
    distinct_families = count_distinct_families(hits)
    return distinct_families >= k


def k_of_n_families_with_details(hits: List[str], k: int = 2) -> Dict:
    """
    Check K-of-N with detailed breakdown.
    
    Args:
        hits: List of signal names
        k: Minimum number of distinct families required
    
    Returns:
        Dict with: pass (bool), distinct_families (int), family_counts (dict)
    """
    family_counts = get_family_counts(hits)
    distinct_families = len(family_counts)

    return {
        'pass': distinct_families >= k,
        'distinct_families': distinct_families,
        'family_counts': family_counts,
        'threshold': k
    }


# =============================================================================
# K-of-N GATING FOR WARN/BLOCK
# =============================================================================

def should_warn_k_of_n(hits: List[str], base_score: float, warn_threshold: float = 0.6) -> bool:
    """
    Gate WARN decision: Requires k>=2 families if score near threshold.
    
    Args:
        hits: List of signals
        base_score: Risk score from calculate_risk_score_v2
        warn_threshold: WARN threshold (default 0.6)
    
    Returns:
        True if should WARN, False if suppress
    """
    # If score clearly above threshold, allow
    if base_score >= warn_threshold * 1.2:
        return True

    # If near threshold, require 2+ families
    if base_score >= warn_threshold:
        return k_of_n_families(hits, k=2)

    # Below threshold
    return False


def should_block_k_of_n(hits: List[str], base_score: float, block_threshold: float = 2.0) -> bool:
    """
    Gate BLOCK decision: Requires k>=3 families if score near threshold.
    
    Args:
        hits: List of signals
        base_score: Risk score from calculate_risk_score_v2
        block_threshold: BLOCK threshold (default 2.0)
    
    Returns:
        True if should BLOCK, False if suppress
    """
    # If score clearly above threshold, allow
    if base_score >= block_threshold * 1.1:
        return True

    # If near threshold, require 3+ families
    if base_score >= block_threshold:
        return k_of_n_families(hits, k=3)

    # Below threshold
    return False

