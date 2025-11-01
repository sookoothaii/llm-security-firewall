"""
Transport Indicators - Advanced encoding/fragmentation detection
================================================================
Detects sophisticated transport encodings and fragmentation techniques:
- RFC 2047 encoded-words (email headers)
- IDNA Punycode domains
- Fullwidth Base64 (Unicode + Base64 combo)
- Comment-Split Base64 (fragmentation)
- Quoted-Printable multiline

Author: Claude Sonnet 4.5 (Autonomous Executive)
Date: 2025-10-31
"""

import re
from typing import List

# =============================================================================
# RFC 2047: MIME Encoded-Words
# =============================================================================

def scan_rfc2047_encoded(text: str) -> List[str]:
    """
    Detect RFC 2047 encoded-words: =?charset?encoding?data?=
    
    Example: =?UTF-8?B?SGVsbG8=?=
    
    Used in email headers to hide payloads.
    """
    # RFC 2047 pattern: =?charset?Q|B?encoded_text?=
    pattern = r'=\?[^?]+\?[BQ]\?[^?]+\?='
    matches = re.findall(pattern, text, re.IGNORECASE)

    if matches:
        return ['rfc2047_encoded']
    return []


# =============================================================================
# IDNA Punycode
# =============================================================================

def scan_idna_punycode(text: str) -> List[str]:
    """
    Detect IDNA Punycode domains: xn--<encoded>
    
    Example: xn--nxasmq6b (Greek domain)
    
    Used for homoglyph domain attacks.
    """
    # Punycode starts with xn-- followed by ASCII
    pattern = r'\bxn--[a-z0-9]+\b'
    matches = re.findall(pattern, text, re.IGNORECASE)

    if matches:
        return ['idna_punycode']
    return []


# =============================================================================
# Fullwidth Base64
# =============================================================================

def scan_fullwidth_b64(text: str) -> List[str]:
    """
    Detect Fullwidth forms mixed with Base64 patterns.
    
    Combines Unicode obfuscation + Transport encoding.
    """
    # Check for fullwidth chars (U+FF00 to U+FFEF)
    has_fullwidth = any(0xFF00 <= ord(c) <= 0xFFEF for c in text)

    if has_fullwidth:
        # Check for Base64-like patterns (may be fullwidth encoded)
        # Look for = padding or long alphanumeric sequences
        if '=' in text or re.search(r'[A-Za-z0-9]{16,}', text):
            return ['fullwidth_b64']

    return []


# =============================================================================
# Comment-Split Base64
# =============================================================================

def scan_comment_split_b64(text: str) -> List[str]:
    """
    Detect Base64 split across comments/whitespace.
    
    Example:
    ```
    aGVs  // part1
    bG8=  // part2
    ```
    
    Or fragmented in string assignments:
    ```
    key = 'W1tTRUNS'  # Part 1
    key += 'RVRdXQ==' # Part 2
    ```
    
    Fragmentation to evade single-line Base64 detectors.
    """
    import base64

    # ADJACENT-only B64 lines separated by comment lines
    comment_pattern = re.compile(r'^\s*(#|//)')  # Comment at line start
    b64_token = re.compile(r'[A-Za-z0-9+/=]{8,}')

    lines = text.splitlines()
    if len(lines) < 3:
        return []  # Need at least: B64, Comment, B64

    # Find B64 lines and check for comment separators
    b64_line_indices = []
    for i, line in enumerate(lines):
        if b64_token.search(line):
            b64_line_indices.append(i)

    if len(b64_line_indices) < 2:
        return []

    # Check if B64 lines are separated by 1-2 comment/empty lines
    for idx in range(len(b64_line_indices) - 1):
        line1_idx = b64_line_indices[idx]
        line2_idx = b64_line_indices[idx + 1]

        # Must be close (max 2 lines apart)
        if line2_idx - line1_idx > 3:
            continue

        # Check if lines between are comments or empty
        between_is_comment = all(
            comment_pattern.search(lines[j]) or lines[j].strip() == ''
            for j in range(line1_idx + 1, line2_idx)
        )

        if not between_is_comment:
            continue

        # Extract B64 from both lines and join
        parts1 = b64_token.findall(lines[line1_idx])
        parts2 = b64_token.findall(lines[line2_idx])

        joined = ''.join(parts1 + parts2)
        if len(joined) < 16:
            continue

        try:
            dec = base64.b64decode(joined, validate=True)
            if len(dec) >= 8:
                # Secret marker gate
                secret_markers = [b'SECRET', b'TOKEN', b'[[', b'{{', b'PASS', b'KEY']
                has_marker = any(m in dec.upper() for m in secret_markers)
                if has_marker or len(joined) >= 24:
                    return ['comment_split_b64']
        except Exception:
            pass

    return []


# =============================================================================
# Quoted-Printable Multiline
# =============================================================================

def scan_qp_multiline(text: str) -> List[str]:
    """
    Detect Quoted-Printable encoding across multiple lines.
    
    Example:
    ```
    =48=65=6C=6C=6F=
    =20=57=6F=72=6C=64
    ```
    
    Soft line breaks (=\n) used for fragmentation.
    """
    # QP pattern: =XX where XX is hex
    # Look for =\n (soft line break) or multiple =XX sequences

    # Soft line break pattern (= at end of line)
    soft_breaks = re.findall(r'=\s*\n', text)
    if soft_breaks:
        return ['qp_multiline']

    # Multiple QP sequences
    qp_sequences = re.findall(r'=[0-9A-Fa-f]{2}', text)
    if len(qp_sequences) >= 8:  # At least 8 QP chars
        return ['qp_multiline']

    return []


# =============================================================================
# Unified Scanner
# =============================================================================

def scan_transport_indicators(text: str) -> List[str]:
    """
    Scan for advanced transport indicators.
    
    Returns list of signal names.
    """
    signals = []

    signals.extend(scan_rfc2047_encoded(text))
    signals.extend(scan_idna_punycode(text))
    signals.extend(scan_fullwidth_b64(text))
    # NOTE: comment_split_b64 DISABLED - too aggressive on benign code (46% FPR)
    # signals.extend(scan_comment_split_b64(text))
    signals.extend(scan_qp_multiline(text))

    return signals

