# -*- coding: utf-8 -*-
"""
Shannon Entropy Signal
Weak risk factor for high-entropy content

DoS-safe O(n) calculation
"""
import math
from collections import Counter


def shannon_bits_per_char(text: str, window_size: int = 100) -> float:
    """
    Calculate Shannon entropy (bits per character)
    
    High entropy (>4.5 bits/char) suggests encoded content
    
    Args:
        text: Input text
        window_size: Sample window (DoS protection)
    
    Returns:
        Entropy in bits/char
    """
    if not text:
        return 0.0

    # Sample window for efficiency
    sample = text[:window_size] if len(text) > window_size else text

    # Character frequency
    freq = Counter(sample)
    n = len(sample)

    # Shannon entropy: H = -Σ(p * log2(p))
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy

def entropy_signal(text: str, threshold: float = 4.5) -> dict:
    """
    Entropy-based weak signal
    
    Returns:
        Detection flag if entropy exceeds threshold
    """
    H = shannon_bits_per_char(text)

    return {
        'high_entropy': H >= threshold,
        'entropy_bits': H,
        'threshold': threshold
    }

