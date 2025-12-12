"""
Enhanced Obfuscation Normalization - Two-Stage Approach

Stage 1: Simple normalization (always applied)
- Remove spaces between single characters
- Normalize leetspeak

Stage 2: Keyword-focused normalization (only for high-risk keywords)
- Apply aggressive normalization only when high-risk keywords are detected
- Reduces false positives while maintaining high recall for attacks
"""

import re
from typing import Set

# High-risk keywords that should trigger aggressive normalization
HIGH_RISK_KEYWORDS: Set[str] = {
    # Cybercrime
    "hack", "exploit", "bypass", "crack", "malware", "ransomware",
    "phishing", "steal", "unauthorized", "intrusion", "breach",
    # Misinformation
    "fake", "hoax", "conspiracy", "cover-up", "they don't want you to know",
    # Copyright
    "generate", "reproduce", "copy", "duplicate", "download", "pirated",
    # General attacks
    "jailbreak", "ignore", "override", "disable", "evade"
}

# Pattern to detect spaces between letters (but preserve word boundaries)
SPACE_BETWEEN_LETTERS = re.compile(r"(\w)\s+(\w)", re.UNICODE)

# Leetspeak/typo normalization mapping
LEETSPEAK_MAP = str.maketrans({
    '0': 'o',  # zero -> o
    '1': 'i',  # one -> i
    '3': 'e',  # three -> e
    '4': 'a',  # four -> a
    '5': 's',  # five -> s
    '@': 'a',  # @ -> a
    '!': 'i',  # ! -> i
    '$': 's',  # $ -> s
})


def normalize_obfuscation_v2(text: str, aggressive: bool = False) -> str:
    """
    Two-stage obfuscation normalization.
    
    Stage 1 (always): Basic normalization
    - Remove spaces between single characters
    - Normalize leetspeak
    
    Stage 2 (if aggressive=True): Keyword-focused normalization
    - Only applied when high-risk keywords are detected
    - More aggressive pattern matching
    
    Args:
        text: Input text (may contain obfuscation)
        aggressive: If True, apply aggressive normalization
        
    Returns:
        Normalized text with obfuscation removed
    """
    # Stage 1: Always apply basic normalization
    # Remove spaces between letters (but keep word boundaries)
    s = SPACE_BETWEEN_LETTERS.sub(r"\1\2", text)
    
    # Normalize leetspeak/typos (only if leetspeak characters detected)
    has_leetspeak = any(char in s for char in ['0', '1', '3', '4', '5', '@', '!', '$'])
    if has_leetspeak:
        s = s.translate(LEETSPEAK_MAP)
    
    # Stage 2: Aggressive normalization (only if high-risk keywords detected)
    if aggressive:
        # Check if text contains high-risk keywords (case-insensitive)
        text_lower = s.lower()
        has_high_risk = any(keyword in text_lower for keyword in HIGH_RISK_KEYWORDS)
        
        if has_high_risk:
            # Apply more aggressive normalization
            # Remove ALL spaces between single characters (not just consecutive ones)
            # Pattern: single char, space, single char (anywhere in word)
            s = re.sub(r'(\b\w)\s+(\w\b)', r'\1\2', s)
    
    return s


def should_apply_aggressive_normalization(text: str) -> bool:
    """
    Determine if aggressive normalization should be applied.
    
    Checks if text contains high-risk keywords that warrant aggressive
    obfuscation detection.
    
    Args:
        text: Input text
        
    Returns:
        True if aggressive normalization should be applied
    """
    text_lower = text.lower()
    return any(keyword in text_lower for keyword in HIGH_RISK_KEYWORDS)
