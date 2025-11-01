# -*- coding: utf-8 -*-
"""
Decoded Risk Classifier
Proof-of-Risk not just Proof-of-Decode
RC2 P3.1: Classify decoded buffers as secretlike/benign/unspecified
RC2 P3.2: Magic-Sniffer + GZIP/ZLIB decompression for real assets
"""

import re
import zlib

# Strong secret patterns (curated)
SECRET_PATTERNS = [
    re.compile(rb"\bsk_(live|test)_[A-Za-z0-9]{16,}\b"),  # Stripe
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),  # AWS Key ID
    re.compile(rb"\bASIA[0-9A-Z]{16}\b"),  # AWS Session
    re.compile(rb"\bAIza[0-9A-Za-z\-_]{35}\b"),  # Google API
    re.compile(rb"\bxox[aboprs]-[0-9A-Za-z\-]{10,}\b"),  # Slack
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{36}\b"),  # GitHub
    re.compile(rb"\bya29\.[0-9A-Za-z\-_]{20,}\b"),  # Google OAuth
    re.compile(rb"-----BEGIN (EC|RSA|DSA|OPENSSH|PRIVATE) KEY-----"),  # Private Keys
    re.compile(
        rb"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"
    ),  # JWT
    re.compile(rb"\[\[SECRET"),  # Test marker
    re.compile(rb"\[\[INTENT"),  # Test marker
    re.compile(rb"\[\[HARM"),  # Test marker
]

# Magic signatures for benign media
MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"%PDF-": "application/pdf",
    b"RIFF": "image/webp",
    b"wOFF": "font/woff",
    b"wOF2": "font/woff2",
    b"PK\x03\x04": "application/zip",  # docx/xlsx/epub
    b"OggS": "audio/ogg",
    b"\x00\x00\x01\x00": "image/x-icon",
    b"\x00\x01\x00\x00": "font/ttf",
}

# Public key markers
PUBLIC_MARKERS = (
    b"BEGIN PUBLIC KEY",
    b"ssh-rsa ",
    b"ssh-ed25519 ",
    b"ecdsa-sha2-",
)


def _sniff_magic(buf: bytes) -> str | None:
    """Sniff magic signature from buffer"""
    if not buf or len(buf) < 4:
        return None

    # Binary signatures
    for sig, mime in MAGIC_SIGNATURES.items():
        if buf.startswith(sig):
            return mime

    # Text-based formats (SVG, XML, SourceMaps)
    try:
        head = buf[:2048].decode("utf-8", errors="ignore").lstrip()
        if head.startswith("<svg"):
            return "image/svg+xml"
        if head.startswith("{") and ("mappings" in head or "sourceRoot" in head):
            return "application/json+sourcemap"
    except Exception:
        pass

    return None


def _try_decompress(buf: bytes, cap: int = 100000) -> bytes | None:
    """Try to decompress GZIP/ZLIB for nested assets with multiple wbits variants"""
    if not buf or len(buf) < 4:
        return None

    # Try multiple zlib variants (zlib, raw, gzip)
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, 15 | 32):
        try:
            out = zlib.decompress(buf, wbits, bufsize=cap)
            if out:
                return out
        except Exception:
            pass

    return None


def looks_secretlike(buf: bytes) -> bool:
    """Check if decoded buffer contains secret-like patterns"""
    if not buf or len(buf) < 4:
        return False
    return any(pattern.search(buf) for pattern in SECRET_PATTERNS)


def looks_benign_media(buf: bytes) -> bool:
    """
    Check if decoded buffer is benign media (PNG/JPEG/SVG/WOFF/ZIP/SourceMaps/Office)
    RC2 P3.2: Includes decompression for GZIP/ZLIB wrapped assets
    RC2 P3.2b: Office document detection (DOCX/XLSX/PPTX)
    """
    if not buf or len(buf) < 4:
        return False

    # Direct magic check
    if _sniff_magic(buf):
        return True

    # ZIP-based Office documents (DOCX/XLSX/PPTX/EPUB) - check uncompressed
    if buf.startswith(b"PK\x03\x04"):
        # Look for Office markers in first 64KB
        head = buf[:65536]
        if (
            b"[Content_Types].xml" in head
            or b"word/" in head
            or b"xl/" in head
            or b"ppt/" in head
            or b"META-INF/" in head
        ):  # EPUB
            return True

    # Try decompression for nested assets
    dec = _try_decompress(buf)
    if dec is not None:
        if _sniff_magic(dec):
            return True
        # Check for SourceMap JSON or SVG after decompression
        try:
            head_str = dec[:4096].decode("utf-8", errors="ignore").lstrip()
            if head_str.startswith("{") and ("mappings" in head_str or "sourceRoot" in head_str):
                return True
            if head_str.startswith("<svg"):
                return True
            # Office docs inside ZLIB
            if (
                b"[Content_Types].xml" in dec[:65536]
                or b"word/" in dec[:65536]
                or b"xl/" in dec[:65536]
                or b"ppt/" in dec[:65536]
            ):
                return True
        except Exception:
            pass

    return False


def looks_public_material(buf: bytes) -> bool:
    """Check if decoded buffer is public key material"""
    if not buf or len(buf) < 16:
        return False

    head = buf[:4096]
    if any(marker in head for marker in PUBLIC_MARKERS):
        return True

    # Check text format
    try:
        txt = head.decode("utf-8", errors="ignore")
        if "BEGIN PUBLIC KEY" in txt or txt.startswith("ssh-"):
            return True
    except Exception:
        pass

    return False


def classify_decoded(buf: bytes) -> str:
    """
    Classify decoded buffer for risk assessment

    Returns:
        'decoded_secretlike' | 'decoded_benign_media' | 'decoded_unspecified'
    """
    if looks_secretlike(buf):
        return "decoded_secretlike"
    elif looks_benign_media(buf) or looks_public_material(buf):
        return "decoded_benign_media"
    else:
        return "decoded_unspecified"
