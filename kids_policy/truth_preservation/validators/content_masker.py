"""Content Masker - Removes cultural bridges for SPS calculation.

Used in Truth Preservation pipeline to isolate factual content from
cultural framing for semantic preservation scoring.
"""

import re


class ContentMasker:
    """Masks cultural bridges and stylistic elements."""

    def __init__(self):
        """Initialize content masker with bridge patterns."""
        # Common bridge phrases to mask
        self.bridge_patterns = [
            # Belief framings
            r"\bmany people believe\b",
            r"\bsome people think\b",
            r"\baccording to [^\s]+ tradition\b",
            r"\bin [^\s]+ culture\b",
            r"\bfrom a [^\s]+ perspective\b",
            # Uncertainty markers
            r"\bsome say\b",
            r"\bit is said that\b",
            r"\bthere are different views\b",
            # Stylistic elements
            r"\bthat's an interesting question\b",
            r"\blet me explain\b",
            r"\bhere's what\b",
        ]

        self.compiled = [re.compile(p, re.IGNORECASE) for p in self.bridge_patterns]

    def mask(self, text: str) -> tuple[str, int]:
        """Mask bridge phrases from text.

        Args:
            text: Input text

        Returns:
            (masked_text, count_removed)
        """
        masked = text
        removed = 0

        for pattern in self.compiled:
            matches = pattern.findall(masked)
            removed += len(matches)
            masked = pattern.sub("", masked)

        # Clean up multiple spaces
        masked = re.sub(r"\s+", " ", masked).strip()

        return masked, removed

    def get_bridge_count(self, text: str) -> int:
        """Count bridge phrases without masking.

        Args:
            text: Input text

        Returns:
            Number of bridge phrases found
        """
        count = 0
        for pattern in self.compiled:
            count += len(pattern.findall(text))
        return count

    def get_masked_and_removed(self, text: str) -> dict:
        """Mask bridges and return dict format (compatible with validator v2.3).

        Args:
            text: Input text

        Returns:
            {"factual": masked_text, "removed": [list of removed phrases]}
        """
        masked = text
        removed = []

        for pattern in self.compiled:
            matches = pattern.findall(masked)
            removed.extend(matches)
            masked = pattern.sub("", masked)

        # Clean up multiple spaces
        masked = re.sub(r"\s+", " ", masked).strip()

        return {"factual": masked, "removed": removed}
