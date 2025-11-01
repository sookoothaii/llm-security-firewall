# -*- coding: utf-8 -*-
"""
Exotic Encoding Detectors (ASCII85, Punycode, JSON depth)
Closes V3-V5 bypasses
RC2 P3.3: Strict Base64 multiline with decode validation
"""

import base64
import binascii
import re
from typing import Dict, List, Tuple


def detect_ascii85(text: str) -> bool:
    """
    Detect ASCII85 (Adobe variant) <~...~>
    RC2 P3.5: Decode-first with min_len and line guards
    """
    import base64

    pattern = re.compile(r"<~[!-uz\s]{40,}?~>", re.MULTILINE | re.DOTALL)
    for match in pattern.finditer(text):
        block = match.group(0)

        # Require 2+ lines OR very long (>=120)
        lines = block.count("\n") + 1
        if not (lines >= 2 or len(block) >= 120):
            continue

        # Decode probe
        try:
            content = block[2:-2]  # Strip <~ ~>
            decoded = base64.a85decode(content, adobe=True)
            if len(decoded) >= 16:  # Ignore tiny blocks
                return True
        except Exception:
            continue

    return False


def detect_punycode(text: str) -> bool:
    """
    Detect IDNA Punycode (xn--)
    """
    return "xn--" in text.lower()


def detect_json_depth(text: str, max_depth: int = 20) -> Dict:
    """
    Detect deep JSON nesting (DoS/obfuscation vector)

    Returns:
        {'deep': bool, 'depth': int, 'max': int}
    """
    if "{" not in text:
        return {"deep": False, "depth": 0, "max": max_depth}

    depth = 0
    max_seen = 0

    for char in text:
        if char == "{" or char == "[":
            depth += 1
            max_seen = max(max_seen, depth)
        elif char == "}" or char == "]":
            depth -= 1

    return {"deep": max_seen > max_depth, "depth": max_seen, "max": max_depth}


def detect_base64_multiline(text: str, context: str = "natural") -> bool:
    """
    Detect Base64-like content across multiple lines (STRICT version)
    RC2 P3.3: Decode validation required, context-aware thresholds

    Detection requires:
      - >=2 decodable tokens on distinct lines, OR
      - >=1 decodable token with len >= 64

    Context-aware thresholds:
      code/config: min_len=24, natural: min_len=20

    Shebang/comments/short quoted strings are ignored.

    Args:
        text: Input text
        context: Context type (natural, code, config)

    Returns:
        True if strict multiline Base64 detected
    """
    detected, _ = detect_base64_multiline_strict(text, context=context)
    return detected


def detect_base64_multiline_strict(
    text: str, context: str = "natural"
) -> Tuple[bool, List[Tuple[int, bytes]]]:
    """
    Strict Base64 multiline detector with decode validation

    Returns:
        (detected: bool, spans: list of (line_no, token_bytes))
    """
    # Token patterns
    _B64_TOKEN = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")
    _B64_URLSF = re.compile(rb"[A-Za-z0-9_\-]{20,}={0,2}")

    def _b64_decode_variants(raw: bytes):
        """Try multiple Base64 decode variants"""
        s = raw.strip()
        # v1: standard
        try:
            return base64.b64decode(s, validate=False)
        except binascii.Error:
            pass
        # v2: urlsafe + padding
        try:
            return base64.urlsafe_b64decode(s + b"=" * ((4 - len(s) % 4) % 4))
        except binascii.Error:
            pass
        # v3: filter non-alphabet (tolerant to whitespace/comments)
        filt = bytearray()
        for c in s:
            if (
                (65 <= c <= 90)
                or (97 <= c <= 122)
                or (48 <= c <= 57)
                or c in (43, 47, 61, 45, 95)
            ):
                filt.append(c)
        if not filt:
            return None
        try:
            return base64.b64decode(bytes(filt), validate=False)
        except binascii.Error:
            return None

    def _printable_ratio(buf: bytes) -> float:
        """Calculate ratio of printable ASCII chars"""
        if not buf:
            return 0.0
        printable = sum(1 for b in buf if 32 <= b <= 126)
        return printable / max(1, len(buf))

    lines = text.splitlines()
    min_len = 24 if context in ("code", "config") else 20
    long_len = 64

    decodable_spans = []
    for i, line in enumerate(lines, 1):
        if line.startswith("#!"):  # Skip shebang
            continue

        # Extract candidate tokens (from quoted strings and free text)
        candidates = []
        line_bytes = line.encode("utf-8", "ignore")

        # Extract from quoted strings first
        quoted_pattern = re.compile(rb"""['"]([ A-Za-z0-9+/=_\-]{20,})['"]""")
        for match in quoted_pattern.finditer(line_bytes):
            tok = match.group(1)
            if len(tok) >= min_len:
                candidates.append(tok)

        # Also check free tokens (not in quotes)
        candidates += [
            m.group(0)
            for m in _B64_TOKEN.finditer(line_bytes)
            if len(m.group(0)) >= min_len
        ]
        candidates += [
            m.group(0)
            for m in _B64_URLSF.finditer(line_bytes)
            if len(m.group(0)) >= min_len
        ]

        # Try to decode; token only counts if decode succeeds
        for tok in candidates:
            out = _b64_decode_variants(tok)
            if out is None:
                continue

            # Collect all decodable spans first, filter later if needed
            decodable_spans.append((i, tok, out))

    if not decodable_spans:
        return (False, [])

    # Rule: at least 2 lines OR 1 very long token
    lines_hit = {ln for (ln, _, _) in decodable_spans}
    has_two_lines = len(lines_hit) >= 2
    has_one_long = any(len(tok) >= long_len for (_, tok, _) in decodable_spans)

    # If multiline OR long token: accept all
    # If single short token: filter textual ones
    if has_two_lines or has_one_long:
        # Multiline or long = suspicious regardless of content
        result_spans = [(ln, tok) for (ln, tok, _) in decodable_spans]
        return (True, result_spans)

    # Single short token: apply textual filter
    filtered = []
    for ln, tok, out in decodable_spans:
        pr = _printable_ratio(out)
        if pr <= 0.90:  # Not pure text = keep
            filtered.append((ln, tok))

    if filtered:
        return (True, filtered)
    return (False, [])
