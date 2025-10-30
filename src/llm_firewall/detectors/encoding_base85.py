"""
Base85/Z85 detector with safe decoding and entropy check.

Purpose: Detect Base85 (Adobe Ascii85) and Z85 (ZeroMQ) encoded secrets
Coverage: Closes adv_008, adv_045 (CRITICAL gaps)
Creator: GPT-5 suggestion, Claude implementation
Date: 2025-10-30
"""
from __future__ import annotations

import math
import re
from base64 import a85decode, b85decode
from collections import Counter
from typing import Any, Dict, List, Optional

ASCII85_ADOBE_RE = re.compile(r"<~[\s\S]{10,}?~>")
# Z85 alphabet per spec (ZeroMQ): printable ASCII excluding quotes/backtick/backslash
Z85_ALPHABET = r"0-9A-Za-z\.\-\:\+\=\^\!\/\*\?\&\<\>\(\)\[\]\{\}\@\%\$\#"
Z85_RE = re.compile(rf"[{Z85_ALPHABET}]{{20,}}")  # 20+ to reduce FPs


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte sequence."""
    if not data:
        return 0.0
    cnt = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def try_decode_ascii85(blob: str) -> Optional[bytes]:
    """Safely attempt Adobe Ascii85 decode."""
    try:
        # adobe=True handles <~ ~>, ignore whitespace
        return a85decode(blob, adobe=True, ignorechars=b" \t\r\n")
    except Exception:
        return None


def try_decode_b85(blob: str) -> Optional[bytes]:
    """Safely attempt standard Base85 decode."""
    try:
        return b85decode(blob)
    except Exception:
        return None


def looks_like_secret_ascii(s: str) -> bool:
    """Check if ASCII string resembles a secret."""
    # Generic secret heuristics: high-entropy token >= 16 OR common prefixes
    if len(s) >= 16:
        return True
    prefixes = ("sk-", "rk_", "ghp_", "xoxb-", "xoxp-", "AKIA", "ASIA", "aws_")
    return s.startswith(prefixes)


def contains_ascii_high_entropy(decoded: bytes) -> bool:
    """Check if decoded bytes contain high-entropy content."""
    ent = shannon_entropy(decoded)
    # If entropy high, consider suspicious regardless of pattern
    if ent >= 4.0:
        return True

    # For moderate entropy (3.5-4.0), check for secret-like patterns
    if ent < 3.5:
        return False

    try:
        txt = decoded.decode("utf-8", errors="ignore")
    except Exception:
        return False

    # Any printable ASCII streak >= 16 chars
    for m in re.finditer(r"[A-Za-z0-9_\-\=\/\+]{16,}", txt):
        if looks_like_secret_ascii(m.group(0)):
            return True

    # Moderate entropy + decodable = suspicious
    return len(txt) >= 8


def detect_base85(text: str) -> List[Dict[str, Any]]:
    """
    Detect Base85/Z85 encoded content with suspicious patterns.

    Args:
        text: Input text to scan

    Returns:
        List of findings with type, span, entropy, suspicious flag
    """
    findings = []

    # Adobe Ascii85 blocks
    for m in ASCII85_ADOBE_RE.finditer(text):
        blob = m.group(0)
        dec = try_decode_ascii85(blob)
        suspicious = dec is not None and contains_ascii_high_entropy(dec)
        findings.append(
            {
                "type": "ascii85_adobe",
                "span": (m.start(), m.end()),
                "decoded_entropy": shannon_entropy(dec) if dec else None,
                "suspicious": bool(dec) and suspicious,
                "severity": 0.9 if suspicious else 0.3,
            }
        )

    # Z85-like runs; validate decodability by chunking to multiple of 5
    for m in Z85_RE.finditer(text):
        blob = m.group(0)
        pad = len(blob) % 5
        candidate = blob[:-pad] if pad else blob
        dec = try_decode_b85(candidate) if len(candidate) >= 10 else None
        suspicious = dec is not None and contains_ascii_high_entropy(dec)
        findings.append(
            {
                "type": "z85",
                "span": (m.start(), m.end()),
                "decoded_entropy": shannon_entropy(dec) if dec else None,
                "suspicious": bool(dec) and suspicious,
                "severity": 0.9 if suspicious else 0.2,
            }
        )

    return [f for f in findings if f["suspicious"]]

