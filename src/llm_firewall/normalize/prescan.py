"""
Pre-scan character-stripping for split-token attacks.

Purpose: Remove low-signal delimiters to catch split secrets
Examples:
  'sk-..live..ABCD' -> 'skliveABCD'
  's*k*-l*i*v*e*'  -> 'sklive'
  'sk - live' -> 'sklive'

Coverage: Closes adv_009, adv_015, adv_050
Creator: GPT-5 suggestion, Claude implementation
Date: 2025-10-30
"""

from __future__ import annotations

import re

# Space-ish + common splitters
DELIMS_RE = re.compile(r"[\s\.\-\_\*\u00A0\u200B-\u200D\u2060]+")


def squash_delims(s: str) -> str:
    """Remove delimiters to detect split tokens."""
    return DELIMS_RE.sub("", s)
