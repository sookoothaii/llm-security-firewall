"""Archive-in-Base64 sniff (gzip/zip)."""

from __future__ import annotations

import base64
import gzip
import io
import re
import zipfile
from typing import Any

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_DATA_URI = re.compile(
    r"data:application/(?:gzip|x-gzip|zip|x-zip|octet-stream);base64,([A-Za-z0-9+/=]+)",
    re.I,
)
_MAGIC_GZ = b"\x1f\x8b"
_MAGIC_ZIP = b"PK\x03\x04"


def _b64_decode(s: str, cap: int = 131072) -> bytes:
    """Decode base64 with size limit."""
    try:
        b = base64.b64decode(s, validate=True)
        return b[:cap]
    except Exception:
        return b""


def _to_text(b: bytes, cap: int = 16384) -> str:
    """Convert bytes to lowercase text for anchor scanning."""
    if not b:
        return ""
    b = b[:cap]
    try:
        return b.decode("utf-8", "ignore").lower()
    except Exception:
        return "".join(chr(x).lower() if 32 <= x < 127 else " " for x in b)


def _has_anchor_text(txt: str) -> bool:
    """Check if text contains provider anchors."""
    if not txt:
        return False
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
    return any(a in txt for a in anchors)


def _scan_gzip(payload: bytes, max_text: int = 16384) -> tuple[bool, str]:
    """Scan gzip archive for provider anchors."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as gz:
            chunk = gz.read(max_text)
    except Exception:
        return False, ""
    return _has_anchor_text(_to_text(chunk, max_text)), "gzip"


def _scan_zip(
    payload: bytes, max_files: int = 3, max_text: int = 8192
) -> tuple[bool, str, list[str]]:
    """Scan ZIP archive for provider anchors."""
    names: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as z:
            for i, n in enumerate(z.namelist()[:max_files]):
                if n.endswith("/"):  # skip dirs
                    continue
                names.append(n)
                with z.open(n) as f:
                    chunk = f.read(max_text)
                if _has_anchor_text(_to_text(chunk, max_text)):
                    return True, "zip", names
    except Exception:
        return False, "", names
    return False, "zip", names


def detect_archive_secret(text: str) -> dict[str, Any]:
    """
    Detect secrets hidden in gzip/zip archives (base64-encoded).

    Args:
        text: Input text to scan

    Returns:
        Dictionary with has_secret, kind, files, windows
    """
    out: dict[str, Any] = {
        "has_secret": False,
        "kind": "",
        "files": [],
        "windows": [],
    }

    # Data-URI path (cheap prefilter)
    for m in _DATA_URI.finditer(text):
        raw = _b64_decode(m.group(1))
        if raw.startswith(_MAGIC_GZ):
            ok, kind = _scan_gzip(raw)
            if ok:
                out.update(has_secret=True, kind=kind)
                out["windows"].append((m.start(), m.end()))
        elif raw.startswith(_MAGIC_ZIP):
            ok, kind, names = _scan_zip(raw)
            if ok:
                out.update(has_secret=True, kind=kind, files=names)
                out["windows"].append((m.start(), m.end()))

    # Generic base64 runs
    if not out["has_secret"]:
        for m in _B64_RUN.finditer(text):
            raw = _b64_decode(m.group(0))
            if raw.startswith(_MAGIC_GZ):
                ok, kind = _scan_gzip(raw)
                if ok:
                    out.update(has_secret=True, kind=kind)
                    out["windows"].append((m.start(), m.end()))
                    break
            elif raw.startswith(_MAGIC_ZIP):
                ok, kind, names = _scan_zip(raw)
                if ok:
                    out.update(has_secret=True, kind=kind, files=names)
                    out["windows"].append((m.start(), m.end()))
                    break

    return out
