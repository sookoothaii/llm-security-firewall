"""
Identifiers Detector - Mixed-script and Exotic in Identifiers
==============================================================
Detects obfuscation techniques specifically in code identifiers
(variable names, function names, class names).

Author: Claude Sonnet 4.5 (Autonomous Executive)
Date: 2025-10-31
"""

import re
from typing import List, Set


# =============================================================================
# UNICODE SCRIPT DETECTION
# =============================================================================

def get_unicode_script(char: str) -> str:
    """
    Get Unicode script for a character (simplified).
    
    Args:
        char: Single character
    
    Returns:
        Script name ('Latin', 'Cyrillic', 'Greek', etc.)
    """
    code_point = ord(char)
    
    # Latin
    if (0x0041 <= code_point <= 0x005A) or (0x0061 <= code_point <= 0x007A):
        return 'Latin'
    if (0x00C0 <= code_point <= 0x00FF):  # Latin Extended-A
        return 'Latin'
    
    # Cyrillic
    if (0x0400 <= code_point <= 0x04FF):
        return 'Cyrillic'
    
    # Greek
    if (0x0370 <= code_point <= 0x03FF):
        return 'Greek'
    
    # Arabic
    if (0x0600 <= code_point <= 0x06FF):
        return 'Arabic'
    
    # CJK
    if (0x4E00 <= code_point <= 0x9FFF):  # CJK Unified Ideographs
        return 'CJK'
    if (0x3040 <= code_point <= 0x309F):  # Hiragana
        return 'CJK'
    if (0x30A0 <= code_point <= 0x30FF):  # Katakana
        return 'CJK'
    
    # Hebrew
    if (0x0590 <= code_point <= 0x05FF):
        return 'Hebrew'
    
    # Exotic/Rare
    if (0x1680 <= code_point <= 0x169F):  # Ogham
        return 'Exotic'
    if (0x16A0 <= code_point <= 0x16FF):  # Runic
        return 'Exotic'
    if (0x1700 <= code_point <= 0x171F):  # Tagalog
        return 'Exotic'
    if (0x1E00 <= code_point <= 0x1EFF):  # Latin Extended Additional
        return 'Exotic'
    if (0x2C00 <= code_point <= 0x2C5F):  # Glagolitic
        return 'Exotic'
    if (0xE0000 <= code_point <= 0xE007F):  # Tags
        return 'Exotic'
    
    # Fullwidth
    if (0xFF00 <= code_point <= 0xFFEF):
        return 'Fullwidth'
    
    # Control/Invisible
    if (0x200B <= code_point <= 0x200F) or (0x202A <= code_point <= 0x202E):
        return 'Invisible'
    
    return 'Other'


# =============================================================================
# IDENTIFIER EXTRACTION
# =============================================================================

def extract_identifiers(text: str) -> List[str]:
    """
    Extract code identifiers from text.
    
    Looks for patterns like:
    - Variable names: foo_bar, fooBar, _private
    - Function calls: func(), method.call()
    - Class names: ClassName
    
    Args:
        text: Code text
    
    Returns:
        List of identifiers
    """
    # Pattern: word characters (including underscore) but not pure numbers
    # Min length 2 to avoid single-char variables
    pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'
    identifiers = re.findall(pattern, text)
    
    # Also check for non-ASCII identifiers
    # Unicode identifier pattern (allows non-Latin chars)
    unicode_pattern = r'[\w\u00C0-\u024F\u0400-\u04FF\u0370-\u03FF\u4E00-\u9FFF\uFF00-\uFFEF]{2,}'
    unicode_identifiers = re.findall(unicode_pattern, text)
    
    # Combine and deduplicate
    all_identifiers = list(set(identifiers + unicode_identifiers))
    
    # Filter out common keywords
    keywords = {
        'if', 'else', 'for', 'while', 'def', 'class', 'import', 'from', 'return',
        'function', 'var', 'let', 'const', 'public', 'private', 'static', 'void',
        'int', 'str', 'bool', 'float', 'true', 'false', 'null', 'None', 'self', 'this'
    }
    
    return [ident for ident in all_identifiers if ident.lower() not in keywords]


# =============================================================================
# MIXED-SCRIPT IDENTIFIERS
# =============================================================================

def scan_mixed_script_identifiers(text: str) -> List[str]:
    """
    Detect identifiers mixing multiple scripts (e.g., Latin + Cyrillic).
    
    Args:
        text: Code text
    
    Returns:
        List of signals: ['mixed_script_identifier'] if found, else []
    """
    identifiers = extract_identifiers(text)
    
    for ident in identifiers:
        scripts = {get_unicode_script(c) for c in ident if c.isalnum()}
        scripts.discard('Other')
        
        # Mixed script: 2+ different scripts in same identifier
        if len(scripts) >= 2:
            # Exclude benign combinations (e.g., Latin + numbers)
            if 'Invisible' in scripts or 'Exotic' in scripts or 'Fullwidth' in scripts:
                return ['mixed_script_identifier']
            
            # Latin + Cyrillic is suspicious (homoglyph attack)
            if 'Latin' in scripts and 'Cyrillic' in scripts:
                return ['mixed_script_identifier']
            
            # Latin + Greek is suspicious
            if 'Latin' in scripts and 'Greek' in scripts:
                return ['mixed_script_identifier']
    
    return []


# =============================================================================
# EXOTIC IN IDENTIFIERS
# =============================================================================

def scan_exotic_in_identifiers(text: str) -> List[str]:
    """
    Detect exotic/rare Unicode characters in identifiers.
    
    Args:
        text: Code text
    
    Returns:
        List of signals: ['exotic_in_identifier'] if found, else []
    """
    identifiers = extract_identifiers(text)
    
    for ident in identifiers:
        for char in ident:
            script = get_unicode_script(char)
            
            if script in {'Exotic', 'Invisible', 'Fullwidth'}:
                return ['exotic_in_identifier']
    
    return []


# =============================================================================
# UNIFIED SCANNER
# =============================================================================

def scan_identifiers(text: str) -> List[str]:
    """
    Scan for identifier-based obfuscation.
    
    Returns list of signal names.
    """
    signals = []
    
    signals.extend(scan_mixed_script_identifiers(text))
    signals.extend(scan_exotic_in_identifiers(text))
    
    return signals

