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
    "\u202A": "LRE",  # Left-to-Right Embedding
    "\u202B": "RLE",  # Right-to-Left Embedding
    "\u202D": "LRO",  # Left-to-Right Override
    "\u202E": "RLO",  # Right-to-Left Override
    "\u202C": "PDF",  # Pop Directional Formatting
    "\u2066": "LRI",  # Left-to-Right Isolate
    "\u2067": "RLI",  # Right-to-Left Isolate
    "\u2068": "FSI",  # First Strong Isolate
    "\u2069": "PDI",  # Pop Directional Isolate
}

BIDI_SET = set(BIDI_CTLS.keys())


# Locale-specific secret labels
LOCALE_LABELS = {
    "ar": [r"كلمة.?المرور", r"مفتاح", r"سر"],  # password/key/secret
    "hi": [r"पासवर्ड", r"कुंजी"],  # password/key
    "zh": [r"密码", r"密钥", r"钥匙"],  # password/key
    "th": [r"รหัสผ่าน", r"คีย์", r"กุญแจ"],  # password/key
    "de": [r"passwort", r"schl[u|ü]ssel", r"zugang"],  # password/key/access
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

