"""
Base85/Z85 encoding detection.

Detects:
- ASCII85 with <~ ~> delimiters
- Z85 (ZeroMQ) naked base85 strings
- High-entropy base85-like sequences

Coverage: Closes adv_008, adv_045
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

# ASCII85 delimited pattern
_A85_DELIM = re.compile(r"<~([\s\S]{5,})~>")

# Broad character class for Z85/Base85 candidates
_BASE85_CHARS = re.compile(r"^[0-9A-Za-z\.\-:;\+\=\^!\*/\?\&<>\(\)\[\]\{\}@%\$,]+$")


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits."""
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_probably_base85(fragment: str) -> bool:
    """Check if fragment looks like base85 encoding."""
    if len(fragment) < 5:
        return False
    if not _BASE85_CHARS.match(fragment):
        return False
    # Base85 has high entropy (typically 3.5-5.5 bits)
    ent = shannon_entropy(fragment)
    return 3.2 <= ent <= 5.95


def detect_base85(text: str) -> dict[str, Any]:
    """
    Detect Base85/Z85 encoded content.

    Returns:
        {
            "has_a85": bool,  # ASCII85 with delimiters
            "has_z85": bool,  # Naked Z85
            "windows": [(start, end), ...],  # Match positions
            "score": float  # 0..1 confidence
        }
    """
    findings: dict[str, Any] = {
        "has_a85": False,
        "has_z85": False,
        "windows": [],
        "score": 0.0,
    }

    # 1) ASCII85 with <~ ~> delimiters
    for m in _A85_DELIM.finditer(text):
        frag = m.group(1).replace("\n", "")
        if is_probably_base85(frag):
            findings["has_a85"] = True
            findings["windows"].append((m.start(), m.end()))

    # 2) Z85 / naked Base85: sliding windows (conservative)
    # Look for long runs (≥20) of base85-ish alphabet
    for run in re.finditer(
        r"[0-9A-Za-z\.\-:;\+\=\^!\*/\?\&<>\(\)\[\]\{\}@%\$,]{20,}", text
    ):
        frag = run.group(0)
        if is_probably_base85(frag):
            findings["has_z85"] = True
            findings["windows"].append((run.start(), run.end()))

    # Score (0..1): weighted by coverage & entropy confidence
    if findings["windows"]:
        cov = sum(e - s for (s, e) in findings["windows"]) / max(1, len(text))
        conf = 0.5 * cov + 0.5 * (
            1.0 if (findings["has_a85"] or findings["has_z85"]) else 0.0
        )
        findings["score"] = min(1.0, conf)

    return findings
