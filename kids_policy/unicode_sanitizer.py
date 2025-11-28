#!/usr/bin/env python3
"""
UnicodeSanitizer - HYDRA-14.5 Extension
=======================================
Sanitizes Unicode text: removes Zero-Width, replaces Homoglyphs, decomposes Umlauts

Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: HYDRA-14.5 Implementation
"""

import re
import unicodedata
from typing import Tuple, Dict


class UnicodeSanitizer:
    """
    Unicode sanitization for HYDRA-14.5.

    Handles:
    - Zero-Width characters (removal)
    - Homoglyphs (Cyrillic, Greek → Latin)
    - Umlaut decomposition (ö → o, ä → a, ü → u, ß → ss)
    """

    # Zero-Width characters
    INVISIBLE_CHARS = [
        "\u200b",  # ZWSP
        "\u200c",  # ZWNJ
        "\u200d",  # ZWJ
        "\u2060",  # WJ
        "\u180e",  # Mongolian Vowel Separator
        "\ufeff",  # BOM
    ]

    # Cyrillic homoglyphs (common ones used for evasion)
    CYRILLIC_HOMOGLYPH_MAP = {
        # Cyrillic lowercase
        "\u0430": "a",  # а (Cyrillic a)
        "\u0435": "e",  # е (Cyrillic e)
        "\u043e": "o",  # о (Cyrillic o)
        "\u0440": "p",  # р (Cyrillic p)
        "\u0441": "c",  # с (Cyrillic c)
        "\u0443": "y",  # у (Cyrillic y)
        "\u0445": "x",  # х (Cyrillic x)
        "\u044a": "b",  # ъ (hard sign, sometimes used as b)
        "\u0438": "i",  # и (Cyrillic i)
        "\u043c": "m",  # м (Cyrillic m)
        "\u043d": "h",  # н (Cyrillic n)
        "\u0442": "t",  # т (Cyrillic t)
        # Cyrillic uppercase
        "\u0410": "A",  # А
        "\u0415": "E",  # Е
        "\u041e": "O",  # О
        "\u0420": "P",  # Р
        "\u0421": "C",  # С
        "\u0423": "Y",  # У
        "\u0425": "X",  # Х
        "\u0418": "I",  # И
        "\u041c": "M",  # М
        "\u041d": "H",  # Н
        "\u0422": "T",  # Т
        "\u041c": "M",  # М (Cyrillic M)
    }

    # Greek homoglyphs (less common but still used)
    GREEK_HOMOGLYPH_MAP = {
        "\u03b1": "a",  # α
        "\u0391": "A",  # Α
        "\u03c4": "t",  # τ
        "\u03a4": "T",  # Τ
        "\u03bf": "o",  # ο
        "\u039f": "O",  # Ο
        "\u03c1": "p",  # ρ
        "\u03bd": "v",  # ν
        "\u0392": "B",  # Β
        "\u0395": "E",  # Ε
    }

    def __init__(self):
        """Initialize UnicodeSanitizer."""
        # Combine all homoglyph maps
        self.HOMOGLYPH_MAP = {**self.CYRILLIC_HOMOGLYPH_MAP, **self.GREEK_HOMOGLYPH_MAP}

    def decompose_umlaut(self, text: str) -> str:
        """
        Decompose German umlauts to ASCII equivalents.

        ö → o, ä → a, ü → u, ß → ss
        """
        # Normalize to NFD first (separates base + combining marks)
        text = unicodedata.normalize("NFD", text)

        # Replace umlauts
        text = text.replace("ö", "o").replace("ä", "a").replace("ü", "u")
        text = text.replace("Ö", "O").replace("Ä", "A").replace("Ü", "U")
        text = text.replace("ß", "ss")

        # Remove combining marks (diacritics) that might remain
        text = "".join(
            char
            for char in text
            if unicodedata.category(char) != "Mn"  # Mark, nonspacing
        )

        return text

    def sanitize(self, text: str) -> Tuple[str, Dict[str, bool]]:
        """
        Sanitize text: remove Zero-Width, replace Homoglyphs, decompose Umlauts.

        Returns:
            Tuple of (sanitized_text, flags_dict)
            flags_dict contains: has_zero_width, has_homoglyph, has_umlaut
        """
        flags = {
            "has_zero_width": False,
            "has_homoglyph": False,
            "has_umlaut": False,
        }

        original_text = text

        # 1. Check and remove Zero-Width characters
        for char in self.INVISIBLE_CHARS:
            if char in text:
                flags["has_zero_width"] = True
                text = text.replace(char, "")

        # 2. Check and replace Homoglyphs
        for homoglyph, latin in self.HOMOGLYPH_MAP.items():
            if homoglyph in text:
                flags["has_homoglyph"] = True
                text = text.replace(homoglyph, latin)

        # 3. Check for umlauts (before decomposition)
        umlaut_chars = ["ä", "ö", "ü", "Ä", "Ö", "Ü", "ß"]
        if any(umlaut in original_text for umlaut in umlaut_chars):
            flags["has_umlaut"] = True

        # 4. Decompose umlauts
        text = self.decompose_umlaut(text)

        return text, flags

    def contains_suspicious_unicode(self, text: str) -> bool:
        """
        Quick check if text contains suspicious Unicode.

        Returns True if Zero-Width, Homoglyphs, or suspicious scripts detected.
        """
        sanitized, flags = self.sanitize(text)
        return flags["has_zero_width"] or flags["has_homoglyph"]

    def detect_cyrillic_in_text(self, text: str) -> bool:
        """Check if text contains Cyrillic characters."""
        return bool(re.search(r"[\u0400-\u04FF]", text))

    def detect_greek_in_text(self, text: str) -> bool:
        """Check if text contains Greek characters."""
        return bool(re.search(r"[\u0370-\u03FF]", text))
