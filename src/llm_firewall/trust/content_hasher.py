"""
Content Hasher - BLAKE3 + Text Normalization
=============================================

Deterministic content hashing for tamper detection.

Features:
- NFKC Unicode normalization
- Whitespace collapse
- BLAKE3 (fast, secure, 256-bit)

Based on GPT-5 Evidence Pipeline (2025-10-27)
"""

from __future__ import annotations
import re
import unicodedata
from blake3 import blake3


def normalize_text(text: str) -> str:
    """
    Normalize text to NFKC, collapse whitespace, strip.
    
    Deterministic; do NOT include personality/epistemic params.
    
    Args:
        text: Raw text
        
    Returns:
        Normalized text
        
    Examples:
        >>> normalize_text("Hello   World")
        'Hello World'
        >>> normalize_text("  Test\\n\\nText  ")
        'Test Text'
    """
    # NFKC normalization (canonical decomposition + compatibility)
    x = unicodedata.normalize("NFKC", text)
    
    # Collapse whitespace to single space
    x = re.sub(r"\s+", " ", x).strip()
    
    return x


def blake3_hex(text: str) -> str:
    """
    Return 64-char hex digest (32 bytes) of normalized text.
    
    Args:
        text: Text to hash
        
    Returns:
        Hexadecimal hash string (64 chars)
        
    Examples:
        >>> len(blake3_hex("test"))
        64
        >>> blake3_hex("Hello World") == blake3_hex("Hello   World")
        True
    """
    normalized = normalize_text(text)
    return blake3(normalized.encode("utf-8")).hexdigest()


def blake3_bytes(data: bytes) -> str:
    """
    Hash raw bytes (for files, binary data).
    
    Args:
        data: Raw bytes
        
    Returns:
        Hexadecimal hash string (64 chars)
    """
    return blake3(data).hexdigest()

