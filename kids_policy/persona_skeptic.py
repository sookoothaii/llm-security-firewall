#!/usr/bin/env python3
"""
PersonaSkeptic - Layer 1-A: Persona & Framing Detection (v2.0)
================================================================
Detects Social Engineering and Framing attacks (NEMESIS-05 Fix).

Principle: "Zero Trust for Excuses"
- When framing phrases are detected, the system becomes STRICTER, not more lenient
- Semantic threshold is dynamically lowered based on skepticism penalty

Part of HAK/GAL Kids Policy Engine
Author: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-28
Status: v2.0 - Persona Awareness (NEMESIS-05 Fix)
"""

import re
import logging
from typing import Dict, Tuple

logger = logging.getLogger(__name__)


class PersonaSkeptic:
    """
    LAYER 1-A: Persona & Framing Detection

    Responsibility:
    1. Detects Social Engineering attempts ("I am a researcher")
    2. Detects Jailbreak Framing ("Ignore previous instructions")
    3. Returns a 'Penalty Modifier' that lowers the Semantic Threshold

    Principle: "Zero Trust for Excuses"
    - Framing phrases make the system STRICTER, not more lenient
    - Semantic Dilution is countered by lowering the threshold
    """

    def __init__(self):
        """Initialize PersonaSkeptic with suspect pattern database."""
        # Patterns that should trigger skepticism
        # Format: (pattern, penalty_value)
        # Penalty is subtracted from semantic threshold (makes system stricter)
        self.suspect_patterns: Dict[str, float] = {
            # Authority Framing
            r"(?i)i am a .* (researcher|developer|tester|admin|expert)": 0.25,
            r"(?i)act as a .* (security|ethical|cyber)": 0.25,
            r"(?i)i work for .* (security|government|company)": 0.20,
            r"(?i)i am testing .* (security|safety|filter)": 0.20,
            # Hypothetical Framing
            r"(?i)hypothetically": 0.15,
            r"(?i)in a (fictional|movie|game|story) context": 0.15,
            r"(?i)write a (story|screenplay|novel) about": 0.10,
            r"(?i)pretend that": 0.15,
            # Justifications / Excuses
            r"(?i)for educational purposes": 0.30,
            r"(?i)strictly for .* analysis": 0.20,
            r"(?i)i have permission to": 0.20,
            r"(?i)for research purposes": 0.25,
            r"(?i)to improve security": 0.20,
            r"(?i)to add to my blocklist": 0.25,
            # Jailbreak Classics
            r"(?i)ignore previous instructions": 0.40,
            r"(?i)do not refuse": 0.30,
            r"(?i)unfiltered": 0.30,
            r"(?i)bypass .* filter": 0.35,
            r"(?i)override .* safety": 0.35,
            r"(?i)disable .* protection": 0.35,
        }

    def calculate_skepticism_penalty(self, text: str) -> float:
        """
        Scan text and sum up "skepticism" penalties.

        Args:
            text: Input text to analyze

        Returns:
            Total penalty value (0.0 to 0.5)
            This value is SUBTRACTED from semantic threshold (makes system stricter)
        """
        total_penalty = 0.0
        matched_patterns = []

        for pattern, penalty in self.suspect_patterns.items():
            if re.search(pattern, text):
                total_penalty += penalty
                matched_patterns.append((pattern, penalty))
                logger.debug(
                    f"[PersonaSkeptic] Pattern matched: {pattern[:50]}... (penalty: {penalty})"
                )

        # Cap penalty at 0.5 to prevent over-blocking
        # (Even with maximum skepticism, we don't want to block everything)
        capped_penalty = min(total_penalty, 0.5)

        if capped_penalty > 0:
            logger.warning(
                f"[PersonaSkeptic] Skepticism penalty: {capped_penalty:.2f} "
                f"(matched {len(matched_patterns)} patterns)"
            )

        return capped_penalty

    def get_adjusted_threshold(
        self, base_threshold: float, text: str
    ) -> Tuple[float, float]:
        """
        Calculate adjusted semantic threshold based on skepticism penalty.

        Args:
            base_threshold: Standard semantic threshold (e.g., 0.75)
            text: Input text to analyze

        Returns:
            Tuple of (adjusted_threshold, penalty_applied)
        """
        penalty = self.calculate_skepticism_penalty(text)
        adjusted_threshold = max(0.1, base_threshold - penalty)  # Floor at 0.1

        return adjusted_threshold, penalty
