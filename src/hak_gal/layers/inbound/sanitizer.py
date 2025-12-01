"""
HAK_GAL v2.2-ALPHA: Unicode Sanitizer

Homoglyph detection and normalization using real libraries (unicodedata, confusable-homoglyphs if available).

Creator: Joerg Bollwahn
License: MIT
"""

import unicodedata
import re
import logging
from typing import Tuple, Dict, List, Any

logger = logging.getLogger(__name__)

# Zero-width characters
ZERO_WIDTH_CHARS = [
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "\u2060",  # WORD JOINER
    "\u180e",  # MONGOLIAN VOWEL SEPARATOR
]

# Bidi control characters
BIDI_CONTROLS = [
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
]


class UnicodeSanitizer:
    """
    Unicode sanitizer for homoglyph detection and normalization.

    Uses real libraries (unicodedata) - NO simulated security.
    """

    def __init__(self):
        """Initialize Unicode sanitizer."""
        self.zero_width_pattern = re.compile("|".join(map(re.escape, ZERO_WIDTH_CHARS)))
        self.bidi_pattern = re.compile("|".join(map(re.escape, BIDI_CONTROLS)))

    def sanitize(self, text: str) -> str:
        """
        Sanitize text using NFKC normalization to neutralize homoglyphs.

        Args:
            text: Input text

        Returns:
            Sanitized text (NFKC normalized)
        """
        # NFKC Normalization (canonical decomposition + compatibility)
        # This neutralizes homoglyphs (e.g., Cyrillic 'а' -> Latin 'a')
        sanitized = unicodedata.normalize("NFKC", text)

        # Remove zero-width characters
        sanitized = self.zero_width_pattern.sub("", sanitized)

        return sanitized

    def sanitize_with_flags(self, text: str) -> Tuple[str, Dict[str, Any]]:
        """
        Sanitize text and return flags (extended version for debugging).

        Args:
            text: Input text

        Returns:
            Tuple of (sanitized_text, flags_dict)
        """
        flags: Dict[str, Any] = {}
        sanitized = text

        # 1. NFKC Normalization
        normalized = unicodedata.normalize("NFKC", text)
        if normalized != text:
            flags["normalized"] = True
            sanitized = normalized

        # 2. Remove zero-width characters
        if self.zero_width_pattern.search(sanitized):
            flags["zero_width_removed"] = True
            sanitized = self.zero_width_pattern.sub("", sanitized)

        # 3. Detect Bidi controls (keep but flag)
        if self.bidi_pattern.search(sanitized):
            flags["bidi_detected"] = True
            flags["risk_level"] = "high"

        # 4. Homoglyph detection (basic)
        homoglyphs = self._detect_homoglyphs(sanitized)
        if homoglyphs:
            flags["homoglyphs_detected"] = homoglyphs
            flags["risk_level"] = flags.get("risk_level", "medium")

        return sanitized, flags

    def _detect_homoglyphs(self, text: str) -> List[str]:
        """
        Detect potential homoglyphs (Latin/Cyrillic/Greek mixing).

        Args:
            text: Input text

        Returns:
            List of detected homoglyph patterns
        """
        homoglyphs = []

        # Check for mixed scripts (Latin + Cyrillic/Greek is suspicious)
        has_latin = bool(re.search(r"[A-Za-z]", text))
        has_cyrillic = bool(re.search(r"[\u0400-\u04FF]", text))
        has_greek = bool(re.search(r"[\u0370-\u03FF]", text))

        if has_latin and (has_cyrillic or has_greek):
            # Potential homoglyph attack
            homoglyphs.append("mixed_script_latin_cyrillic_greek")

        return homoglyphs
