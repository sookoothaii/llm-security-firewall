"""
Text Canonicalization (Production-Grade)
=========================================

Deterministic canonicalization pipeline to defeat evasion techniques.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

import re
import unicodedata

# Zero-width characters (ZW) and Variation Selectors (VS)
_ZW = re.compile(r"[\u200B-\u200D\uFEFF]")
_VS = re.compile(r"[\uFE0E\uFE0F]")
_WS = re.compile(r"\s+")

# Basic homoglyph map (using ord() for compatibility)
_HOMO = {
    ord("\u0435"): "e",  # Cyrillic ye
    ord("\u0430"): "a",  # Cyrillic a
    ord("\u043e"): "o",  # Cyrillic o
    ord("\u0456"): "i",  # Ukrainian i
    ord("\u04cf"): "l",  # Cyrillic palochka
    ord("\u0399"): "I",  # Greek Iota
    ord("\u0131"): "i",  # Dotless i
    ord("\u2014"): "-",  # EM dash
    ord("\u2013"): "-",  # EN dash
    ord("\u201c"): '"',  # Smart quote left
    ord("\u201d"): '"',  # Smart quote right
    ord("\u2018"): "'",  # Smart apostrophe left
    ord("\u2019"): "'",  # Smart apostrophe right
    ord("\uff07"): "'",  # Fullwidth apostrophe
    ord("\uff02"): '"',  # Fullwidth quote
}


def canonicalize(text: str) -> str:
    """
    Deterministic canonicalization pipeline:
      1) Unicode NFKC
      2) Homoglyph mapping
      3) Strip Zero-Width + Variation Selectors
      4) Casefold
      5) Whitespace normalize
    """
    s = unicodedata.normalize("NFKC", text)
    s = s.translate(_HOMO)
    s = _ZW.sub("", s)
    s = _VS.sub("", s)
    s = s.casefold()
    s = _WS.sub(" ", s).strip()
    return s
