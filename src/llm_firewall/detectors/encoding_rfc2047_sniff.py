"""RFC 2047 encoded-words detector."""

from __future__ import annotations

import base64
import quopri
import re
from typing import Any

PAT = re.compile(r"=\?([A-Za-z0-9\-]+)\?(B|Q)\?([A-Za-z0-9+/=_?\-]+)\?=", re.I)


def _decode(word: str) -> str:
    """Decode RFC 2047 encoded-word."""
    m = PAT.fullmatch(word)
    if not m:
        return ""
    _charset, enc, payload = m.groups()
    try:
        if enc.upper() == "B":
            raw = base64.b64decode(payload)
        else:  # Q encoding
            raw = quopri.decodestring(payload.replace("_", " ").encode())
        return raw.decode("utf-8", "ignore").lower()
    except Exception:
        return ""


def detect_rfc2047(text: str) -> dict[str, Any]:
    """
    Detect secrets in RFC 2047 encoded-words.

    Args:
        text: Input text to scan

    Returns:
        Dictionary with has_secret and windows
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

    hits = []
    for m in PAT.finditer(text):
        dec = _decode(m.group(0))
        if dec and any(a in dec for a in anchors):
            hits.append((m.start(), m.end()))

    return {"has_secret": bool(hits), "windows": hits}
