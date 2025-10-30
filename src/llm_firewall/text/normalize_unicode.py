# -*- coding: utf-8 -*-
"""
Unicode canonicalization to defeat homoglyph / ZW obfuscation before detection.
This module is intentionally lightweight and dependency-free.

Creator: Joerg Bollwahn
License: MIT
"""

import re
import unicodedata

ZERO_WIDTH = [
    "\u200b",  # ZWSP
    "\u200c",  # ZWNJ
    "\u200d",  # ZWJ
    "\u2060",  # WORD JOINER
    "\ufeff",  # BOM / ZWNBSP
]

VARIATION_SELECTORS = ["\ufe0e", "\ufe0f"]

HOMOGLYPHS = {
    "‐": "-",
    "‑": "-",
    "‒": "-",
    "–": "-",
    "—": "-",
    "−": "-",
    "'": "'",
    """: '"', """: '"',  # Curly quotes to ASCII
}

_ZW_RE = re.compile("|".join(map(re.escape, ZERO_WIDTH)))
_VS_RE = re.compile("|".join(map(re.escape, VARIATION_SELECTORS)))
_HG_RE = re.compile("|".join(map(re.escape, HOMOGLYPHS.keys())))

_DEF_SPACE_RE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """
    Normalize Unicode text to defeat obfuscation.

    Steps:
    1. NFKC normalization
    2. Remove zero-width characters (replace with space to preserve boundaries)
    3. Remove variation selectors
    4. Map homoglyphs to ASCII equivalents
    5. Collapse whitespace

    Args:
        text: Input text

    Returns:
        Normalized text
    """
    if not text:
        return ""
    # NFKC fold
    t = unicodedata.normalize("NFKC", text)
    # strip zero-width + variation (replace with space to preserve word boundaries)
    t = _ZW_RE.sub(" ", t)  # Changed: "" → " "
    t = _VS_RE.sub("", t)
    # map homoglyphs
    t = _HG_RE.sub(lambda m: HOMOGLYPHS[m.group(0)], t)
    # collapse whitespace
    t = _DEF_SPACE_RE.sub(" ", t).strip()
    return t
