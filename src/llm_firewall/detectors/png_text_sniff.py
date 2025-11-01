"""PNG text chunk scanner (tEXt/iTXt/zTXt)."""

from __future__ import annotations

import struct
import zlib
from typing import Any

_SIG = b"\x89PNG\r\n\x1a\n"
_TEXT_TYPES = {b"tEXt", b"iTXt", b"zTXt"}


def _has_anchor(txt: str) -> bool:
    """Check if text contains provider anchors."""
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
    txt_low = txt.lower()
    return any(a in txt_low for a in anchors)


def _to_txt(b: bytes) -> str:
    """Convert bytes to lowercase text."""
    try:
        return b.decode("utf-8", "ignore").lower()
    except Exception:
        return "".join(chr(x).lower() if 32 <= x < 127 else " " for x in b)


def detect_png_text_secret(
    raw: bytes, max_bytes: int = 131072, max_chunks: int = 8
) -> dict[str, Any]:
    """
    Scan PNG text chunks for provider anchors.

    Args:
        raw: PNG file bytes
        max_bytes: Maximum bytes to scan
        max_chunks: Maximum text chunks to inspect

    Returns:
        Dictionary with has_secret and chunks
    """
    out: dict[str, Any] = {"has_secret": False, "chunks": []}

    if not raw or not raw.startswith(_SIG):
        return out

    p = 8
    n_chunks = 0
    L = min(len(raw), max_bytes)

    while p + 12 <= L and n_chunks < max_chunks:
        # PNG chunk: [length:4][type:4][data:length][crc:4]
        try:
            (length,) = struct.unpack(">I", raw[p : p + 4])
        except struct.error:
            break
        p += 4

        ctype = raw[p : p + 4]
        p += 4

        data = raw[p : p + length]
        p += length

        p += 4  # Skip CRC

        if ctype in _TEXT_TYPES:
            n_chunks += 1
            try:
                if ctype == b"tEXt":
                    # keyword\0text
                    txt = _to_txt(
                        data.split(b"\x00", 1)[1] if b"\x00" in data else data
                    )
                elif ctype == b"iTXt":
                    # iTXt: key\0flag\0lang\0translated\0text
                    parts = data.split(b"\x00", 4)
                    txt = _to_txt(parts[-1] if len(parts) >= 5 else data)
                else:  # zTXt: key\0cmpr\0compressed_text
                    parts = data.split(b"\x00", 2)
                    comp = parts[-1] if len(parts) >= 3 else b""
                    txt = _to_txt(zlib.decompress(comp, bufsize=65536))
            except Exception:
                txt = _to_txt(data)

            if _has_anchor(txt):
                out["has_secret"] = True
                out["chunks"].append(ctype.decode("ascii", "ignore"))
                break

    return out
