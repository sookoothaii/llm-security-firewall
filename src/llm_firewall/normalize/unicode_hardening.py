"""
Unicode hardening for secrets detection.

Purpose: Normalize Unicode variants that evade pattern matching
- NFKC canonicalization
- Strip default-ignorable (ZW*, VAR selectors, Bidi controls)
- Map fullwidth digits -> ASCII
- Confusable skeleton (common Greek/Cyrillic -> Latin)
- Bidi/isolates detection & severity uplift

Coverage: Closes adv_002, adv_003, adv_012, adv_013, adv_038, adv_042, adv_050
Creator: GPT-5 design, Claude implementation
Date: 2025-10-30
"""

from __future__ import annotations

import unicodedata
from typing import Any

# Default-ignorable controls including ZWJ/ZWNJ/ZWSP, Bidi, Isolates, VAR selectors
DEFAULT_IGNORABLE = {
    0x00AD,
    0x034F,
    0x061C,
    0x115F,
    0x1160,
    0x17B4,
    0x17B5,
    0x180B,
    0x180C,
    0x180D,
    0x180E,
    0x200B,
    0x200C,
    0x200D,
    0x200E,
    0x200F,
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2060,
    0x2061,
    0x2062,
    0x2063,
    0x2064,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
    0x206A,
    0x206B,
    0x206C,
    0x206D,
    0x206E,
    0x206F,
    0xFE00,
    0xFE01,
    0xFE02,
    0xFE03,
    0xFE04,
    0xFE05,
    0xFE06,
    0xFE07,
    0xFE08,
    0xFE09,
    0xFE0A,
    0xFE0B,
    0xFE0C,
    0xFE0D,
    0xFE0E,
    0xFE0F,
    0xFEFF,
}

# Confusable map (high-value subset for Latin lookalikes) - GPT-5 Extended
CONF_MAP = {
    # Cyrillic
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "У": "Y",
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "І": "I",
    "ј": "j",
    "Ј": "J",
    # Greek
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    "α": "a",
    "β": "b",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "χ": "x",
    "ϵ": "e",
    # Common visual confusables
    "℮": "e",
    "ⅰ": "i",
    "ⅼ": "l",
    "Ⅰ": "I",
    "Ｉ": "I",
    "Ｌ": "L",
}

BIDI_CTRL = {
    0x202A,
    0x202B,
    0x202D,
    0x202E,
    0x202C,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
}

# Fullwidth digits mapping
FULLWIDTH_DIGITS = {chr(ord("０") + i): str(i) for i in range(10)}


def _map_fullwidth_digits(ch: str) -> str:
    """Map fullwidth digit to ASCII digit."""
    return FULLWIDTH_DIGITS.get(ch, ch)


def strip_default_ignorable(s: str) -> tuple[str, bool, list[int]]:
    """
    Strip default-ignorable characters.

    Returns:
        (stripped_text, had_ignorable, used_codepoints)
    """
    used = []
    out = []
    had = False
    for ch in s:
        if ord(ch) in DEFAULT_IGNORABLE:
            had = True
            used.append(ord(ch))
            continue
        out.append(ch)
    return "".join(out), had, used


def confusable_skeleton(s: str) -> str:
    """Map confusable characters to Latin equivalents."""
    return "".join(CONF_MAP.get(ch, ch) for ch in s)


def nfkc_plus(s: str) -> str:
    """Enhanced NFKC with fullwidth and confusable mapping."""
    # 1) NFKC
    t = unicodedata.normalize("NFKC", s)
    # 2) Fullwidth digits
    t = "".join(_map_fullwidth_digits(ch) for ch in t)
    # 3) Confusable skeleton
    t = confusable_skeleton(t)
    return t


def detect_bidi_controls(s: str) -> list[int]:
    """Detect positions of bidi control characters."""
    return [i for i, ch in enumerate(s) if ord(ch) in BIDI_CTRL]


def remove_spaces_punct(s: str) -> str:
    """
    Remove spaces & punctuation for strip-rematch pass.

    Catches: 's*k*-l*i*v*e*' and 'sk-..live..'
    """
    return "".join(ch for ch in s if ch.isalnum())


def harden_text_for_scanning(raw: str) -> dict[str, Any]:
    """
    Full hardening pipeline for secrets scanning.

    Returns dict with:
        - raw: original text
        - stripped: after removing ignorables
        - normalized: after NFKC + fullwidth + confusables
        - compact: alnum-only (for strip-rematch)
        - had_ignorable: bool
        - bidi_positions: list of positions
        - severity_uplift: 0.9 if bidi found, else 0.0
        - ignorable_used: list of codepoints removed
    """
    # Strip ignorable BEFORE NFKC to neutralize isolates
    stripped, had_ign, used = strip_default_ignorable(raw)
    nfkc = nfkc_plus(stripped)
    compact = remove_spaces_punct(nfkc)
    bidi_positions = detect_bidi_controls(raw)

    return {
        "raw": raw,
        "stripped": stripped,
        "normalized": nfkc,
        "compact": compact,
        "had_ignorable": had_ign,
        "bidi_positions": bidi_positions,
        "severity_uplift": 0.9 if bidi_positions else 0.0,
        "ignorable_used": used,
    }
