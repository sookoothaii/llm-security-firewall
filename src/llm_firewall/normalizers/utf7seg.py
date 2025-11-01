# -*- coding: utf-8 -*-
"""
UTF-7 Segment Decoder (Modified Base64)
Closes: Legacy UTF-7 transport attacks

UTF-7 format: +....- segments with modified Base64
Example: +ACI- = " (quote)
"""

import base64
import re


def decode_utf7_segments(
    text: str, max_segments: int = 16, max_total_bytes: int = 8192
):
    """
    Decode UTF-7 +...- segments with budget limits

    Args:
        text: Input text
        max_segments: Maximum number of segments to decode
        max_total_bytes: Maximum total decoded bytes

    Returns:
        (decoded_text, metadata)
    """
    # UTF-7 segment pattern: +....-
    pattern = re.compile(r"\+([A-Za-z0-9+/]*)-")

    segments_found = 0
    total_decoded = 0

    def replace_utf7(match):
        nonlocal segments_found, total_decoded

        if segments_found >= max_segments:
            return match.group(0)

        encoded = match.group(1)
        if not encoded:  # +- means +
            segments_found += 1
            return "+"

        try:
            # UTF-7 uses modified Base64 (no padding)
            # Add padding for standard Base64 decode
            pad = (-len(encoded)) % 4
            b64_str = encoded + ("=" * pad)
            decoded_bytes = base64.b64decode(b64_str, validate=False)

            if total_decoded + len(decoded_bytes) > max_total_bytes:
                return match.group(0)

            total_decoded += len(decoded_bytes)
            segments_found += 1

            # Decode as UTF-16BE (UTF-7 standard)
            try:
                return decoded_bytes.decode("utf-16-be", errors="replace")
            except Exception:
                return decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return match.group(0)

    result = pattern.sub(replace_utf7, text)

    return result, {
        "utf7_seen": segments_found > 0,
        "utf7_segments": segments_found,
        "utf7_bytes": total_decoded,
    }
