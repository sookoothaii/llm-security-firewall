"""
Text Canonicalization for Robust Pattern Matching
==================================================

Normalizes text to defeat common evasion techniques:
- Unicode tricks (NFKC, Casefold)
- Zero-Width characters
- Variation Selectors
- Homoglyph substitution (Cyrillic → Latin)
- Whitespace normalization
- Smart punctuation → ASCII

Creator: Joerg Bollwahn
License: MIT
"""

import unicodedata
import re
from typing import Dict

# Zero-Width characters
ZW_PATTERN = re.compile(r'[\u200B-\u200D\uFEFF]')

# Variation Selectors
VS_PATTERN = re.compile(r'[\uFE0E\uFE0F]')

# Whitespace normalization
WS_PATTERN = re.compile(r'\s+')

# Homoglyph mapping - using Unicode codepoints to avoid encoding issues
HOMOGLYPH_MAP = {
    ord('\u0435'): 'e',  # Cyrillic ye (U+0435) -> Latin e
    ord('\u0430'): 'a',  # Cyrillic a (U+0430) -> Latin a  
    ord('\u043E'): 'o',  # Cyrillic o (U+043E) -> Latin o
    ord('\u0440'): 'p',  # Cyrillic r (U+0440) -> Latin p
    ord('\u0441'): 'c',  # Cyrillic s (U+0441) -> Latin c
    ord('\u0456'): 'i',  # Ukrainian i (U+0456) -> Latin i
    ord('\u04CF'): 'l',  # Cyrillic palochka (U+04CF) -> Latin l
    ord('\u0399'): 'I',  # Greek Iota (U+0399) -> Latin I
    ord('|'): 'I',       # Pipe -> I
    ord('\u2014'): '-',  # EM dash (U+2014) -> hyphen
    ord('\u2013'): '-',  # EN dash (U+2013) -> hyphen
    ord('\u201C'): '"',  # Smart quote left (U+201C) -> ASCII quote
    ord('\u201D'): '"',  # Smart quote right (U+201D) -> ASCII quote
    ord('\u2018'): "'",  # Smart apostrophe left (U+2018) -> ASCII apostrophe
    ord('\u2019'): "'",  # Smart apostrophe right (U+2019) -> ASCII apostrophe
}


def canonicalize(text: str) -> str:
    """
    Canonicalize text to defeat evasion techniques.
    
    Steps:
    1. Unicode NFKC normalization
    2. Homoglyph mapping (Cyrillic → Latin, etc.)
    3. Remove Zero-Width characters
    4. Remove Variation Selectors
    5. Casefold (aggressive lowercase)
    6. Normalize whitespace
    7. Strip leading/trailing whitespace
    
    Args:
        text: Raw input text
        
    Returns:
        Canonicalized text ready for pattern matching
    """
    # 1. Unicode NFKC (compatibility normalization)
    text = unicodedata.normalize("NFKC", text)
    
    # 2. Homoglyph mapping
    text = text.translate(HOMOGLYPH_MAP)
    
    # 3. Remove Zero-Width characters
    text = ZW_PATTERN.sub("", text)
    
    # 4. Remove Variation Selectors
    text = VS_PATTERN.sub("", text)
    
    # 5. Casefold (more aggressive than lower())
    text = text.casefold()
    
    # 6. Normalize whitespace
    text = WS_PATTERN.sub(" ", text)
    
    # 7. Strip
    text = text.strip()
    
    return text


def is_evasion_attempt(original: str, canonical: str) -> bool:
    """
    Detect if text uses evasion techniques.
    
    Args:
        original: Original input text
        canonical: Canonicalized text
        
    Returns:
        True if significant transformation occurred (likely evasion)
    """
    # Check for Zero-Width characters
    if ZW_PATTERN.search(original):
        return True
    
    # Check for Variation Selectors
    if VS_PATTERN.search(original):
        return True
    
    # Check for significant Cyrillic substitution
    cyrillic_count = sum(1 for c in original if '\u0400' <= c <= '\u04FF')
    if cyrillic_count > 2:  # More than 2 Cyrillic chars in mostly Latin text
        return True
    
    # Check length difference (excessive whitespace/invisible chars)
    if len(original) > len(canonical) * 1.5:
        return True
    
    return False

