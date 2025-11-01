# -*- coding: utf-8 -*-
r"""
JSON Unicode Escape Decoder (\uXXXX with Surrogate-Pair support)
Closes JSON-Unicode-Escape bypass (test_ultra_break_v2)
"""

import re
from typing import Dict, Tuple


def has_json_u_escapes(text: str) -> bool:
    r"""Quick check for \uXXXX patterns"""
    return "\\u" in text and bool(re.search(r"\\u[0-9a-fA-F]{4}", text))


def unescape_json_u(text: str) -> Tuple[bool, str, Dict]:
    r"""
    Decode JSON Unicode escapes (\uXXXX) including surrogate pairs

    Returns:
        (changed, decoded_text, metadata)
    """
    if not has_json_u_escapes(text):
        return False, text, {}

    changes = 0
    surrogate_pairs = 0

    def replace_escape(match):
        nonlocal changes, surrogate_pairs

        hex_val = match.group(1)
        codepoint = int(hex_val, 16)

        # Handle surrogate pairs (D800-DBFF + DC00-DFFF)
        if 0xD800 <= codepoint <= 0xDBFF:
            # High surrogate - need to find low surrogate
            surrogate_pairs += 1
            return match.group(0)  # Keep for now, handle in second pass

        changes += 1
        try:
            return chr(codepoint)
        except ValueError:
            return match.group(0)  # Invalid codepoint - keep escaped

    # First pass: decode simple escapes
    decoded = re.sub(r"\\u([0-9a-fA-F]{4})", replace_escape, text)

    # Second pass: handle surrogate pairs
    def replace_surrogate_pair(match):
        nonlocal surrogate_pairs
        high_hex = match.group(1)
        low_hex = match.group(2)

        high = int(high_hex, 16)
        low = int(low_hex, 16)

        # Calculate actual codepoint from surrogate pair
        # Formula: (high - 0xD800) * 0x400 + (low - 0xDC00) + 0x10000
        if 0xD800 <= high <= 0xDBFF and 0xDC00 <= low <= 0xDFFF:
            codepoint = (high - 0xD800) * 0x400 + (low - 0xDC00) + 0x10000
            try:
                return chr(codepoint)
            except ValueError:
                pass

        return match.group(0)

    # Look for \\uD[8-B][0-9A-F]{2}\\uD[C-F][0-9A-F]{2} (surrogate pair pattern)
    decoded = re.sub(
        r"\\u([dD][8-9a-bA-B][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})",
        replace_surrogate_pair,
        decoded,
    )

    changed = decoded != text

    metadata = {
        "json_u_escapes_found": changes,
        "surrogate_pairs": surrogate_pairs,
        "changed": changed,
    }

    return changed, decoded, metadata
