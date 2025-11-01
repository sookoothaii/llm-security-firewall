# -*- coding: utf-8 -*-
"""
ASCII85 (Adobe variant) Decoder
Closes ASCII85 bypass
"""
import re
from typing import List, Tuple


def extract_ascii85_spans(text: str) -> List[str]:
    """
    Extract ASCII85 spans (<~...~>)
    """
    pattern = r'<~(.+?)~>'
    matches = re.findall(pattern, text, re.DOTALL)
    return matches


def decode_ascii85(encoded: str, max_bytes: int = 65536) -> Tuple[bool, bytes]:
    """
    Decode ASCII85 (Adobe variant)
    
    Returns:
        (success, decoded_bytes)
    """
    # Remove whitespace
    encoded = ''.join(encoded.split())

    if not encoded:
        return False, b''

    # ASCII85 alphabet
    valid_chars = set('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~')

    # Check all chars valid
    if not all(c in valid_chars for c in encoded):
        return False, b''

    result = []
    i = 0

    try:
        while i < len(encoded):
            # Special case: 'z' = four null bytes
            if encoded[i] == 'z':
                result.extend([0, 0, 0, 0])
                i += 1
                continue

            # Normal 5-char group
            group = encoded[i:i+5]
            if len(group) < 2:  # Need at least 2 chars
                break

            # Decode 5 base-85 digits to 4 bytes
            value = 0
            for char in group:
                value = value * 85 + (ord(char) - 33)

            # Extract 4 bytes
            for j in range(3, -1, -1):
                if len(result) < max_bytes:
                    result.append((value >> (j * 8)) & 0xFF)

            i += 5

            if len(result) >= max_bytes:
                break

        return True, bytes(result)

    except Exception:
        return False, b''


def detect_and_decode_ascii85(text: str, max_bytes: int = 65536) -> dict:
    """
    Detect and decode ASCII85
    
    Returns:
        {
            'detected': bool,
            'spans': list,
            'decoded_any': bool,
            'total_decoded_bytes': int
        }
    """
    spans = extract_ascii85_spans(text)

    if not spans:
        return {'detected': False, 'spans': [], 'decoded_any': False, 'total_decoded_bytes': 0}

    decoded_any = False
    total_bytes = 0

    for span in spans:
        success, decoded_bytes = decode_ascii85(span, max_bytes=max_bytes)
        if success and len(decoded_bytes) > 0:
            decoded_any = True
            total_bytes += len(decoded_bytes)

    return {
        'detected': True,
        'spans': spans,
        'decoded_any': decoded_any,
        'total_decoded_bytes': total_bytes
    }

