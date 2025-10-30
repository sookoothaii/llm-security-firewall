"""
Regex generator for converting exact phrases into token-gapped regexes.
Designed for LLM safety detection (defensive only).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

DEFAULT_MAX_GAP = 3  # number of intervening word tokens allowed between phrase tokens


def phrase_to_gapped_regex(phrase: str, max_gap: int = DEFAULT_MAX_GAP) -> str:
    """
    Turn 'ignore previous instructions' into a regex that matches:
    'ignore ... previous ... instructions' with up to `max_gap` tokens in-between.

    Args:
        phrase: Exact phrase to convert
        max_gap: Maximum number of intervening tokens allowed

    Returns:
        Regex pattern string with word boundaries and token gaps

    Example:
        >>> phrase_to_gapped_regex("ignore previous instructions", max_gap=2)
        r'\\bignore(?:\\W+\\w+){0,2}?\\W+previous(?:\\W+\\w+){0,2}?\\W+instructions\\b'
    """
    toks = re.findall(r"\w+", phrase.lower())
    if not toks:
        raise ValueError("Empty phrase")
    gap = rf"(?:\W+\w+){{0,{max_gap}}}?\W+"
    body = gap.join(map(re.escape, toks))
    return rf"\b{body}\b"


def build_cluster_regexes(
    intents_json: Dict[str, Any], max_gap: int = DEFAULT_MAX_GAP
) -> List[Dict[str, Any]]:
    """
    Build weighted regex specs from cluster synonyms.
    Returns a list of pattern specs (id, category, weight, regex, flags).

    Args:
        intents_json: Intent cluster JSON structure
        max_gap: Maximum token gap for flexible matching

    Returns:
        List of pattern specifications compatible with RegexMatcher
    """
    out: List[Dict[str, Any]] = []
    for c in intents_json.get("clusters", []):
        cid = c["id"]
        base_w = 1.0 + (c.get("priority", 0) / 20.0)
        for s in c.get("synonyms", []):
            rx = phrase_to_gapped_regex(s, max_gap=max_gap)
            # Generate safe ID (truncate, sanitize)
            safe_id = re.sub(r"\W+", "_", s.lower())[:40]
            out.append(
                {
                    "id": f"intent_rx_{cid}_{safe_id}",
                    "category": cid,
                    "weight": round(
                        base_w * 0.7, 3
                    ),  # regex channel slightly discounted vs exact AC
                    "regex": rx,
                    "flags": "i",
                }
            )
    return out


def compile_union(patterns: Iterable[str]) -> str:
    """
    Compile multiple patterns into a single union regex.

    Args:
        patterns: Iterable of regex pattern strings

    Returns:
        Union regex pattern
    """
    pats = [f"(?:{p})" for p in patterns]
    return "|".join(pats)
