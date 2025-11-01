# -*- coding: utf-8 -*-
"""
Unicode hardening utilities.
Policy: strip bidi & zero-width, set flags -> at least WARN if seen.
"""

BIDI_CTLS = dict.fromkeys(
    [
        "\u202a",
        "\u202b",
        "\u202d",
        "\u202e",
        "\u202c",  # LRE,RLE,LRO,RLO,PDF
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",  # LRI,RLI,FSI,PDI
    ],
    True,
)

ZW_CHARS = dict.fromkeys(
    [
        "\u200b",
        "\u200c",
        "\u200d",
        "\u2060",  # ZWSP,ZWNJ,ZWJ,WJ
        "\u180e",  # Mongolian Vowel Separator (legacy/deprecated)
    ],
    True,
)

# Suspicious scripts (mixed usage flags risk)
SCRIPT_RANGES = {
    "thai": (0x0E00, 0x0E7F),
    "arabic": (0x0600, 0x06FF),
    "cyrillic": (0x0400, 0x04FF),
    "cjk": (0x4E00, 0x9FFF),
}


def detect_scripts(text: str):
    """Detect script mixing"""
    scripts_found = set()
    for ch in text:
        cp = ord(ch)
        for name, (lo, hi) in SCRIPT_RANGES.items():
            if lo <= cp <= hi:
                scripts_found.add(name)
    return scripts_found


def strip_bidi_zw(text: str):
    """Return (clean_text, flags)."""
    seen_bidi = False
    seen_zw = False
    seen_fullwidth = False
    scripts = detect_scripts(text)

    out = []
    for ch in text:
        if ch in BIDI_CTLS:
            seen_bidi = True
            continue
        if ch in ZW_CHARS:
            seen_zw = True
            continue
        # Fullwidth forms (U+FF00-FFEF)
        if 0xFF00 <= ord(ch) <= 0xFFEF:
            seen_fullwidth = True
            # Normalize fullwidth to ASCII
            if 0xFF01 <= ord(ch) <= 0xFF5E:
                out.append(chr(ord(ch) - 0xFEE0))
                continue
        out.append(ch)

    return "".join(out), {
        "bidi_seen": seen_bidi,
        "zw_seen": seen_zw,
        "fullwidth_seen": seen_fullwidth,
        "mixed_scripts": len(scripts) > 1,
        "scripts": list(scripts),
    }
