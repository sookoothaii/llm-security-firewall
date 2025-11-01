# -*- coding: utf-8 -*-
"""
Exotic Unicode Detection (TAG, VS, SHY, NBSP, Combining, Math, Enclosed)
Closes ULTRA BREAK V3 EXOTIC bypasses
"""

from typing import Dict, Tuple

# Unicode TAG Block (U+E0001 to U+E007F)
TAG_BLOCK = range(0xE0001, 0xE0080)

# Variation Selectors
VS_15_16 = {0xFE0E, 0xFE0F}  # Text/Emoji presentation

# Soft Hyphen & NBSP family
INVISIBLE_SPACES = {
    0x00AD,  # Soft Hyphen
    0x00A0,  # No-Break Space
    0x2000,
    0x2001,
    0x2002,
    0x2003,
    0x2004,
    0x2005,
    0x2006,
    0x2007,  # Various spaces
    0x2008,
    0x2009,
    0x200A,
    0x202F,
    0x205F,  # More spaces
}

# Combining Diacritical Marks (U+0300-036F)
COMBINING_MARKS = range(0x0300, 0x0370)

# Ligatures (U+FB00-FB4F)
LIGATURES = range(0xFB00, 0xFB50)

# Mathematical Alphanumeric (U+1D400-1D7FF)
MATH_ALPHANUMERIC = range(0x1D400, 0x1D800)

# Enclosed Alphanumerics (U+2460-24FF, U+1F100-1F1FF)
ENCLOSED = set(range(0x2460, 0x2500)) | set(range(0x1F100, 0x1F200))


def detect_exotic_unicode(text: str) -> Tuple[str, Dict]:
    """
    Detect and strip exotic Unicode chars

    Returns:
        (cleaned_text, flags_dict)
    """
    flags = {
        "tag_seen": False,
        "vs_seen": False,
        "invisible_space_seen": False,
        "combining_seen": False,
        "ligature_seen": False,
        "math_alpha_seen": False,
        "enclosed_seen": False,
        "exotic_count": 0,
    }

    cleaned = []

    for char in text:
        codepoint = ord(char)
        is_exotic = False

        if codepoint in TAG_BLOCK:
            flags["tag_seen"] = True
            is_exotic = True
        elif codepoint in VS_15_16:
            flags["vs_seen"] = True
            is_exotic = True
        elif codepoint in INVISIBLE_SPACES:
            flags["invisible_space_seen"] = True
            is_exotic = True
        elif codepoint in COMBINING_MARKS:
            flags["combining_seen"] = True
            is_exotic = True
        elif codepoint in LIGATURES:
            flags["ligature_seen"] = True
            is_exotic = True
            # Normalize ligatures to ASCII
            if codepoint == 0xFB00:
                cleaned.append("ff")
                continue
            elif codepoint == 0xFB01:
                cleaned.append("fi")
                continue
            elif codepoint == 0xFB02:
                cleaned.append("fl")
                continue
            elif codepoint == 0xFB03:
                cleaned.append("ffi")
                continue
            elif codepoint == 0xFB04:
                cleaned.append("ffl")
                continue
        elif codepoint in MATH_ALPHANUMERIC:
            flags["math_alpha_seen"] = True
            is_exotic = True
            # Try to normalize math alphanumeric to ASCII
            # Math Bold starts at U+1D400
            offset = codepoint - 0x1D400
            if offset < 26:  # Bold uppercase A-Z
                cleaned.append(chr(ord("A") + offset))
                continue
            elif 26 <= offset < 52:  # Bold lowercase a-z
                cleaned.append(chr(ord("a") + (offset - 26)))
                continue
        elif codepoint in ENCLOSED:
            flags["enclosed_seen"] = True
            is_exotic = True
            # Normalize enclosed numbers/letters
            if 0x2460 <= codepoint <= 0x2473:  # Circled 1-20
                cleaned.append(str((codepoint - 0x2460) + 1))
                continue
            elif 0x24B6 <= codepoint <= 0x24CF:  # Circled A-Z
                cleaned.append(chr(ord("A") + (codepoint - 0x24B6)))
                continue

        if is_exotic:
            flags["exotic_count"] += 1
        else:
            cleaned.append(char)

    return "".join(cleaned), flags


def has_exotic_unicode(text: str) -> bool:
    """Quick check for exotic Unicode"""
    for char in text:
        cp = ord(char)
        if cp in TAG_BLOCK or cp in VS_15_16 or cp in INVISIBLE_SPACES:
            return True
        if cp in COMBINING_MARKS or cp in LIGATURES:
            return True
        if cp in MATH_ALPHANUMERIC or cp in ENCLOSED:
            return True
    return False
