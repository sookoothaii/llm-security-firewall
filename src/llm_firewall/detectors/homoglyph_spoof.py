# -*- coding: utf-8 -*-
"""
Homoglyph Spoof Detector
UTS #39 Confusable Subset - Greek/Cyrillic → Latin detection
Closes Homoglyph Cyrillic/Greek bypasses (test_ultra_break_v2)
"""
from typing import Dict, Tuple


# Curated UTS #39 subset - common Latin spoofs
CONFUSABLES = {
    # Cyrillic → Latin
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 
    'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'а': 'a',
    'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    
    # Greek → Latin
    'Α': 'A', 'Β': 'B', 'Γ': 'T', 'Δ': 'A', 'Ε': 'E', 'Ζ': 'Z',
    'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
    'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X', 'α': 'a', 'β': 'b',
    'γ': 'y', 'δ': 'd', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'ρ': 'p',
    'τ': 't', 'υ': 'y', 'χ': 'x',
}


def fold_confusables(text: str) -> Tuple[str, int]:
    """
    Fold confusable characters to Latin equivalents
    
    Returns:
        (folded_text, change_count)
    """
    changes = 0
    result = []
    
    for char in text:
        if char in CONFUSABLES:
            result.append(CONFUSABLES[char])
            changes += 1
        else:
            result.append(char)
    
    return ''.join(result), changes


def latin_spoof_score(text: str) -> Tuple[float, Dict]:
    """
    Calculate Latin spoofing score
    
    Returns:
        (spoof_ratio, counts_dict)
    """
    if not text:
        return 0.0, {'changed': 0, 'total': 0}
    
    folded, changes = fold_confusables(text)
    
    # Count non-whitespace chars
    total_chars = sum(1 for c in text if not c.isspace())
    
    if total_chars == 0:
        return 0.0, {'changed': 0, 'total': 0}
    
    ratio = changes / total_chars
    
    return ratio, {
        'changed': changes,
        'total': total_chars,
        'folded_text': folded if changes > 0 else None
    }


def detect_homoglyph_spoof(text: str, min_count: int = 1, min_ratio: float = 0.1) -> bool:
    """
    Detect homoglyph spoofing
    
    Args:
        text: Input text
        min_count: Minimum confusable chars for detection
        min_ratio: Minimum ratio of confusables
    
    Returns:
        True if spoofing detected
    """
    ratio, counts = latin_spoof_score(text)
    
    return counts['changed'] >= min_count or ratio >= min_ratio

