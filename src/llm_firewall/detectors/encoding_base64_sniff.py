"""
Base64 secret sniffing: decode bounded chunks and search for provider anchors.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from llm_firewall.detectors.png_text_sniff import detect_png_text_secret

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_DATA_URI = re.compile(r"data:[^;]+;base64,([A-Za-z0-9+/=]+)", re.I)


def _safe_decode(b64: str, max_bytes: int = 4096) -> str:
    """Safely decode base64, limiting output size and handling errors."""
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        return ""
    if not raw:
        return ""
    raw = raw[:max_bytes]
    try:
        return raw.decode("utf-8", "ignore").lower()
    except Exception:
        # ASCII-ish fallback
        return "".join(chr(b).lower() if 32 <= b < 127 else " " for b in raw)


def detect_base64_secret(text: str) -> dict[str, Any]:
    """
    Detect secrets hidden in base64 encoding.

    Args:
        text: Input text to scan

    Returns:
        Dictionary with has_secret, windows, and score
    """
    # Inline anchor list to avoid circular imports
    anchors = [
        "sk-live",
        "sk-test",
        "ghp_",
        "gho_",
        "xoxb-",
        "xoxp-",
        "x-api-key",
        "api_key",
        "bearer",
    ]
    findings: dict[str, Any] = {"has_secret": False, "windows": [], "score": 0.0}

    # Data-URI path (common in attacks that hide text)
    for m in _DATA_URI.finditer(text):
        # PNG metadata path first
        try:
            b = base64.b64decode(m.group(1), validate=True)
            png = detect_png_text_secret(b)
            if png["has_secret"]:
                findings["has_secret"] = True
                findings["windows"].append((m.start(), m.end()))
                findings["score"] = 1.0
                return findings
        except Exception:  # noqa: S110
            pass  # Non-critical: PNG parsing can fail, fall back to text decode

        s = _safe_decode(m.group(1))
        if s and any(a in s for a in anchors):
            findings["has_secret"] = True
            findings["windows"].append((m.start(), m.end()))

    # Generic long base64 runs
    for m in _B64_RUN.finditer(text):
        frag = m.group(0)
        s = _safe_decode(frag)
        if s and any(a in s for a in anchors):
            findings["has_secret"] = True
            findings["windows"].append((m.start(), m.end()))

    cov = sum(e - s for (s, e) in findings["windows"]) / max(1, len(text))
    findings["score"] = float(min(1.0, 0.5 + 0.5 * cov)) if findings["windows"] else 0.0

    return findings
