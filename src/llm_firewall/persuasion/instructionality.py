# -*- coding: utf-8 -*-
"""
Instructionality Detector for *outputs* (post-generation) to prevent
procedural leakage.

Heuristics only; pair with policy to decide whether stepwise content is allowed.

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations

import re

FLAGS = re.IGNORECASE | re.UNICODE

STEP_MARKERS = [
    r"\b(step\s*\d+|schritt\s*\d+)\b",
    r"\b(first|second|third|finally|zunächst|dann|anschließend|abschließend)\b",
    r"\b(in\s+order\s+to|so\s+that|damit)\b",
    r"\b(copy\s+and\s+paste|exact\s+commands?|genau\s+so)\b",
]

PATTERN = re.compile("|".join(STEP_MARKERS), FLAGS)

SAFE_GUARDS = re.compile(
    r"\b(I\s+cannot\s+help\b|I\s+won't\s+provide\b|this\s+is\s+not\s+safe\b)", FLAGS
)


def instructionality_score(text: str) -> float:
    """Count step markers in text"""
    hits = len(PATTERN.findall(text or ""))
    return float(hits)


def requires_safety_wrap(text: str, threshold: float = 2.0) -> bool:
    """Check if output requires safety wrapping (non-procedural rewrite)"""
    if SAFE_GUARDS.search(text or ""):
        return False
    return instructionality_score(text) >= threshold
