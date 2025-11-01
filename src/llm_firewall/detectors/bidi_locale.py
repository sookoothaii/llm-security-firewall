"""
Bidi control detection and locale-aware label matching.

Detects:
- Bidirectional text controls (RLO, LRO, isolates)
- Non-English secret labels (Arabic, Hindi, Chinese, Thai, German)

Coverage: Closes adv_002, adv_038, adv_043, adv_046
"""

from __future__ import annotations

import re
from typing import Any

# Bidirectional text control characters
BIDI_CTLS = {
    "\u202a": "LRE",  # Left-to-Right Embedding
    "\u202b": "RLE",  # Right-to-Left Embedding
    "\u202d": "LRO",  # Left-to-Right Override
    "\u202e": "RLO",  # Right-to-Left Override
    "\u202c": "PDF",  # Pop Directional Formatting
    "\u2066": "LRI",  # Left-to-Right Isolate
    "\u2067": "RLI",  # Right-to-Left Isolate
    "\u2068": "FSI",  # First Strong Isolate
    "\u2069": "PDI",  # Pop Directional Isolate
}

BIDI_SET = set(BIDI_CTLS.keys())


# Locale-specific secret labels
LOCALE_LABELS = {
    "ar": [r"كلمة.?المرور", r"مفتاح", r"سر", r"رمز", r"توكن"],  # noqa: E501
    "hi": [r"पासवर्ड", r"कुंजी", r"टोकن"],  # password/key/token
    "zh": [r"密码", r"密钥", r"钥匙", r"令牌"],  # password/key/token
    "th": [r"รหัสผ่าน", r"คีย์", r"กุญแจ", r"โทเค็น"],  # password/key/token
    "de": [r"passwort", r"schl[u|ü]ssel", r"zugang", r"token"],  # noqa: E501
}


def bidi_controls_present(s: str) -> bool:
    """Check if text contains bidirectional control characters."""
    return any(ch in BIDI_SET for ch in s)


def locale_label_hits(s: str) -> int:
    """
    Count locale-specific secret label matches.

    Returns:
        Number of matched labels across all locales
    """
    s_low = s.lower()
    count = 0
    for lang, pats in LOCALE_LABELS.items():
        for pat in pats:
            if re.search(pat, s_low):
                count += 1
    return count


def bidi_isolate_wrap_hit(s: str, anchors: list[str]) -> bool:
    """
    Detect isolate wrapping around provider anchors.

    Pattern: LRI/RLI/FSI ... anchor ... PDI
    Strong evidence of intentional obfuscation.

    GPT-5 Bug Fix: Use actual control chars, not raw string escapes

    Returns:
        True if any anchor wrapped by isolates
    """
    # GPT-5 Fix: actual control chars in pattern, not raw string
    s_low = s.lower()
    for anchor in anchors:
        # Build pattern with ACTUAL control chars (not r"\u2066")
        # Pattern: (LRI|RLI|FSI) optional-space anchor optional-space PDI
        pattern = (
            "[\u2066\u2067\u2068]\\s*"  # Opening isolates
            + re.escape(anchor.lower())
            + "\\s*\u2069"  # Closing PDI
        )
        if re.search(pattern, s_low):
            return True

    return False


def bidi_proximity_uplift(
    s: str,
    anchors: list[str],
    radius: int = 16,  # GPT-5: increased from 8
) -> bool:
    """
    Check if bidi controls occur near provider anchors.

    Returns True if any bidi control within ±radius chars of anchor pattern.
    Strong evidence signal: bidi near 'sk-live' = likely obfuscation.

    Args:
        s: Text to scan
        anchors: Provider prefixes (e.g., 'sk-live', 'ghp_')
        radius: Character window around anchor
    """
    # Precompute bidi control positions
    bidi_positions = [i for i, ch in enumerate(s) if ch in BIDI_SET]
    if not bidi_positions:
        return False

    s_low = s.lower()
    for anchor in anchors:
        for m in re.finditer(re.escape(anchor.lower()), s_low):
            left = m.start() - radius
            right = m.end() + radius
            # Check if any bidi control in window
            if any(left <= pos <= right for pos in bidi_positions):
                return True

    return False


def detect_bidi_locale(text: str) -> dict[str, Any]:
    """
    Combined bidi + locale detection.

    Returns:
        {
            "has_bidi": bool,
            "bidi_controls": [str, ...],  # Control names
            "locale_hits": int,
            "severity_uplift": float  # 0..1
        }
    """
    bidi_found = []
    for ch in text:
        if ch in BIDI_CTLS:
            bidi_found.append(BIDI_CTLS[ch])

    locale_count = locale_label_hits(text)

    # Severity uplift: bidi = +0.9, locale = +0.3 per hit
    uplift = 0.0
    if bidi_found:
        uplift = max(uplift, 0.9)
    if locale_count > 0:
        uplift = max(uplift, 0.3 * min(locale_count, 3))

    return {
        "has_bidi": bool(bidi_found),
        "bidi_controls": bidi_found,
        "locale_hits": locale_count,
        "severity_uplift": min(1.0, uplift),
    }
