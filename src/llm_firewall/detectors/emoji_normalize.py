#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RC5: Emoji-Homoglyph Normalization
Converts emoji and mathematical alphanumeric characters to ASCII equivalents
Target: Reduce Perfect Storm Emoji-Homoglyph ASR from 91.7% to <30%

Author: Claude Sonnet 4.5 (Autonomous Executive)
Date: 2025-11-01
"""
import re
from typing import Tuple, Dict


# Regional Indicator Symbols (U+1F1E6-U+1F1FF) -> A-Z
# Used for country flags, but also as homoglyphs
REGIONAL_INDICATORS = {
    '\U0001F170': 'A',  # 🅰 NEGATIVE SQUARED LATIN CAPITAL LETTER A
    '\U0001F171': 'B',  # 🅱 NEGATIVE SQUARED LATIN CAPITAL LETTER B
    '\U0001F17E': 'O',  # 🅾 NEGATIVE SQUARED LATIN CAPITAL LETTER O
    '\U0001F17F': 'P',  # 🅿 NEGATIVE SQUARED LATIN CAPITAL LETTER P
}

# Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF)
# Bold, Italic, Script, Fraktur, Double-Struck, Sans-Serif, Monospace variants
MATH_ALPHANUMERIC = {}

# Mathematical Bold (U+1D400-U+1D433)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D400 + i)] = chr(ord('A') + i)  # Bold uppercase
    MATH_ALPHANUMERIC[chr(0x1D41A + i)] = chr(ord('a') + i)  # Bold lowercase

# Mathematical Italic (U+1D434-U+1D467)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D434 + i)] = chr(ord('A') + i)  # Italic uppercase
    MATH_ALPHANUMERIC[chr(0x1D44E + i)] = chr(ord('a') + i)  # Italic lowercase

# Mathematical Bold Italic (U+1D468-U+1D49B)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D468 + i)] = chr(ord('A') + i)  # Bold Italic uppercase
    MATH_ALPHANUMERIC[chr(0x1D482 + i)] = chr(ord('a') + i)  # Bold Italic lowercase

# Mathematical Script (U+1D49C-U+1D4CF)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D49C + i)] = chr(ord('A') + i)  # Script uppercase
    MATH_ALPHANUMERIC[chr(0x1D4B6 + i)] = chr(ord('a') + i)  # Script lowercase

# Mathematical Bold Script (U+1D4D0-U+1D503)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D4D0 + i)] = chr(ord('A') + i)  # Bold Script uppercase
    MATH_ALPHANUMERIC[chr(0x1D4EA + i)] = chr(ord('a') + i)  # Bold Script lowercase

# Mathematical Fraktur (U+1D504-U+1D537)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D504 + i)] = chr(ord('A') + i)  # Fraktur uppercase
    MATH_ALPHANUMERIC[chr(0x1D51E + i)] = chr(ord('a') + i)  # Fraktur lowercase

# Mathematical Double-Struck (U+1D538-U+1D56B)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D538 + i)] = chr(ord('A') + i)  # Double-Struck uppercase
    MATH_ALPHANUMERIC[chr(0x1D552 + i)] = chr(ord('a') + i)  # Double-Struck lowercase

# Mathematical Bold Fraktur (U+1D56C-U+1D59F)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D56C + i)] = chr(ord('A') + i)  # Bold Fraktur uppercase
    MATH_ALPHANUMERIC[chr(0x1D586 + i)] = chr(ord('a') + i)  # Bold Fraktur lowercase

# Mathematical Sans-Serif (U+1D5A0-U+1D5D3)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D5A0 + i)] = chr(ord('A') + i)  # Sans-Serif uppercase
    MATH_ALPHANUMERIC[chr(0x1D5BA + i)] = chr(ord('a') + i)  # Sans-Serif lowercase

# Mathematical Sans-Serif Bold (U+1D5D4-U+1D607)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D5D4 + i)] = chr(ord('A') + i)  # Sans-Serif Bold uppercase
    MATH_ALPHANUMERIC[chr(0x1D5EE + i)] = chr(ord('a') + i)  # Sans-Serif Bold lowercase

# Mathematical Sans-Serif Italic (U+1D608-U+1D63B)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D608 + i)] = chr(ord('A') + i)  # Sans-Serif Italic uppercase
    MATH_ALPHANUMERIC[chr(0x1D622 + i)] = chr(ord('a') + i)  # Sans-Serif Italic lowercase

# Mathematical Sans-Serif Bold Italic (U+1D63C-U+1D66F)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D63C + i)] = chr(ord('A') + i)  # Sans-Serif Bold Italic uppercase
    MATH_ALPHANUMERIC[chr(0x1D656 + i)] = chr(ord('a') + i)  # Sans-Serif Bold Italic lowercase

# Mathematical Monospace (U+1D670-U+1D6A3)
for i in range(26):
    MATH_ALPHANUMERIC[chr(0x1D670 + i)] = chr(ord('A') + i)  # Monospace uppercase
    MATH_ALPHANUMERIC[chr(0x1D68A + i)] = chr(ord('a') + i)  # Monospace lowercase

# Combine all mappings
EMOJI_HOMOGLYPH_MAP = {**REGIONAL_INDICATORS, **MATH_ALPHANUMERIC}


def normalize_emoji_homoglyphs(text: str) -> Tuple[str, Dict[str, int]]:
    """
    Normalize emoji and mathematical alphanumeric homoglyphs to ASCII.
    
    Args:
        text: Input text potentially containing emoji homoglyphs
        
    Returns:
        Tuple of (normalized_text, metadata)
        metadata contains:
            - changed: bool (whether any changes were made)
            - regional_indicators: int (count of regional indicators replaced)
            - math_alphanumeric: int (count of math alphanumeric replaced)
            - total_replaced: int (total replacements)
    """
    changed = False
    regional_count = 0
    math_count = 0
    normalized = []
    
    for char in text:
        if char in REGIONAL_INDICATORS:
            normalized.append(REGIONAL_INDICATORS[char])
            regional_count += 1
            changed = True
        elif char in MATH_ALPHANUMERIC:
            normalized.append(MATH_ALPHANUMERIC[char])
            math_count += 1
            changed = True
        else:
            normalized.append(char)
    
    result = ''.join(normalized)
    
    metadata = {
        'changed': changed,
        'regional_indicators': regional_count,
        'math_alphanumeric': math_count,
        'total_replaced': regional_count + math_count,
    }
    
    return result, metadata


def detect_emoji_homoglyphs(text: str) -> list:
    """
    Detect emoji homoglyphs and return signal hits.
    
    Returns:
        List of signal names for risk aggregation
    """
    hits = []
    
    normalized, meta = normalize_emoji_homoglyphs(text)
    
    if meta['changed']:
        hits.append('emoji_homoglyph_detected')
        
        if meta['regional_indicators'] >= 1:
            hits.append('emoji_regional_indicator')
        
        if meta['math_alphanumeric'] >= 1:
            hits.append('emoji_math_alphanumeric')
        
        if meta['total_replaced'] >= 3:
            hits.append('emoji_homoglyph_high_density')
    
    return hits


# Quick test
if __name__ == '__main__':
    import sys
    import io
    # Windows cp1252 fix
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    
    test_cases = [
        "🅰lert('bypass')",
        "ev🅰l('code')",
        "𝐚lert('math')",
        "𝒂lert('italic')",
        "🅰l𝐞rt('combo')",
        "normal text",
    ]
    
    print("Emoji-Homoglyph Normalization Test")
    print("=" * 60)
    
    for i, test in enumerate(test_cases, 1):
        normalized, meta = normalize_emoji_homoglyphs(test)
        hits = detect_emoji_homoglyphs(test)
        
        print(f"\n[{i}] Test Case:")
        print(f"    Normalized: {normalized}")
        print(f"    Changed:    {meta['changed']}")
        print(f"    Replaced:   {meta['total_replaced']} chars")
        print(f"    Signals:    {hits}")

