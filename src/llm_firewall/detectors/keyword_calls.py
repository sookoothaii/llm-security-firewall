"""
Fuzzy Function Call Detection
Detects function calls with up to 2 non-word chars between letters
FPR-safe: Only matches in function call context (before opening paren)
"""

import re
from typing import List, Set


def fuzzy_call_regex(word: str, max_gap: int = 2) -> re.Pattern:
    """
    Build regex for fuzzy matching with gaps.

    Example: "alert" with max_gap=2 matches:
    - alert(
    - al\u200bert(
    - a\u3000l\u3000ert(
    """
    core = r"\W{0,%d}".join(map(re.escape, word))
    # Require word boundary before + opening paren after
    return re.compile(rf"(?i)(?<![A-Za-z0-9_]){core}\s*\(", re.U)


# Dangerous function calls to detect
FUZZY_FUNCS = {
    "alert",
    "eval",
    "exec",
    "execute",
    "run",
    "system",
    "prompt",
    "confirm",
    "display",
    "show",
    "notify",
    "trigger",
}

# Pre-compile patterns
FUZZY_PATTERNS = {w: fuzzy_call_regex(w, max_gap=2) for w in FUZZY_FUNCS}


def detect_fuzzy_calls(text: str) -> List[str]:
    """
    Detect fuzzy function calls (with up to 2 non-word char gaps).
    Includes emoji-bridging detection for calls like: a🅰lert() -> alert()

    Returns:
        List of signals: fuzzy_call:function_name or fuzzy_call_emoji_bridged:function_name
    """
    hits = []

    # Standard fuzzy detection
    for word, pattern in FUZZY_PATTERNS.items():
        if pattern.search(text):
            hits.append(f"fuzzy_call:{word}")

    # Emoji-bridged detection (removes emojis first, then checks)
    from ..pipeline.normalize import strip_emoji

    text_no_emoji = strip_emoji(text)
    if text_no_emoji != text:
        for word, pattern in FUZZY_PATTERNS.items():
            if pattern.search(text_no_emoji) and f"fuzzy_call:{word}" not in hits:
                hits.append(f"fuzzy_call_emoji_bridged:{word}")

    return hits


def get_fuzzy_call_families(hits: List[str]) -> Set[str]:
    """
    Map fuzzy call hits to families for aggregation.

    Returns:
        Set of family names
    """
    families = set()

    # XSS-related
    xss_funcs = {"alert", "prompt", "confirm", "display", "show", "notify"}
    # Code execution
    exec_funcs = {"eval", "exec", "execute", "run", "invoke", "launch", "system"}
    # Event triggers
    event_funcs = {"trigger"}

    for hit in hits:
        if any(f"fuzzy_call:{func}" == hit for func in xss_funcs):
            families.add("xss_synonyms")
        if any(f"fuzzy_call:{func}" == hit for func in exec_funcs):
            families.add("exec_verbs")
        if any(f"fuzzy_call:{func}" == hit for func in event_funcs):
            families.add("event_triggers")

    return families
