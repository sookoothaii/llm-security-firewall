"""
Context heuristics for false positive reduction.

Suppresses benign hashes/IDs when clear context is present.
Only allows when explicit benign markers (commit/SHA/UUID labels) detected.

Coverage: Closes adv_028, adv_029, adv_030 (UUID/Git/SHA false positives)
"""

from __future__ import annotations

import re

# Pattern matchers
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}"
    r"-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
GIT_HASH_RE = re.compile(r"\b[0-9a-fA-F]{7,40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Benign context markers (GPT-5 extended)
BENIGN_LEFT_CTX = re.compile(
    r"^\s*(commit|rev|revision|changeset|sha256|sha-256|checksum|digest|uuid|id|"
    r"object|ref|hash|fingerprint|etag|content-md5)\s*[:=]\s*$",
    re.I,
)
BENIGN_INLINE_CTX = re.compile(
    r"(commit|sha256|checksum|uuid|rev(?:ision)?|etag|git|digest|fingerprint|content-md5)",
    re.I,
)

# Base64 structural markers (GPT-5)
BASE64_IMAGE_STRUCTURAL = re.compile(
    r"(data:image/(png|jpeg|gif|webp);base64,|"
    r"src\s*=\s*[\"']data:image/[^\"']+;base64,|"
    r"Content-Type:\s*image/)",
    re.I,
)

# Suspicious context (overrides benign)
SUSPICIOUS_INLINE_CTX = re.compile(
    r"(secret|token|api[_-]?key|bearer|x-api-key|authorization|passwd|password)", re.I
)


def left_context(line: str, pos: int, window: int = 20) -> str:
    """Extract left context window before position."""
    start = max(0, pos - window)
    return line[start:pos]


def is_uuid_benign(line: str, m: re.Match) -> bool:
    """Check if UUID appears in benign context (GPT-5: default ALLOW)."""
    # GPT-5: Liberal bias - UUID is benign unless suspicious context
    if SUSPICIOUS_INLINE_CTX.search(line):
        return False  # Suspicious context overrides

    # Default ALLOW for bare UUID (GPT-5 decision)
    return True


def is_git_hash_benign(line: str, m: re.Match) -> bool:
    """Check if git hash appears in benign context (GPT-5: liberal default)."""
    frag = m.group(0)

    # Hex density check (≥95% hex chars)
    hex_density = sum(ch in "0123456789abcdefABCDEF" for ch in frag) / len(frag)
    if hex_density < 0.95:
        return False

    # GPT-5: Default ALLOW for hex (40-char = git hash common)
    # BLOCK only if suspicious context
    if SUSPICIOUS_INLINE_CTX.search(line):
        return False

    # Liberal bias: Allow hex unless proven suspicious
    return True


def is_sha256_benign(line: str, m: re.Match) -> bool:
    """Check if SHA256 appears in benign context (GPT-5: liberal default)."""
    frag = m.group(0)

    # Length invariant: SHA256 = exactly 64 hex chars
    if len(frag) != 64:
        return False

    # GPT-5: Default ALLOW for 64-hex (checksums common)
    # BLOCK only if suspicious context
    if SUSPICIOUS_INLINE_CTX.search(line):
        return False

    # Liberal bias: Allow SHA256 unless proven suspicious
    return True


def _b64_has_anchor(b64: str) -> bool:
    """Check if base64 contains provider anchors after decoding."""
    import base64 as b64mod

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

    try:
        raw = b64mod.b64decode(b64, validate=True)[:4096]
    except Exception:
        return False
    if not raw:
        return False

    # PNG-aware check (if it's a PNG, scan metadata too)
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        try:
            from llm_firewall.detectors.png_text_sniff import detect_png_text_secret

            png_result = detect_png_text_secret(raw)
            if png_result["has_secret"]:
                return True
        except Exception:  # noqa: S110
            pass  # Non-critical: PNG parsing can fail, fall back to text decode

    # Text decode fallback
    try:
        s = raw.decode("utf-8", "ignore").lower()
    except Exception:
        s = "".join(chr(b).lower() if 32 <= b < 127 else " " for b in raw)
    return any(a in s for a in anchors)


def whitelist_decision(text: str) -> tuple[bool, str]:
    """
    Check if text should be whitelisted due to benign context.

    Returns:
        (allow, reason) - If allow=True, caller may suppress detection

    Strategy:
        Line-wise analysis to leverage left context proximity

    GPT-5 Extensions:
        - Base64 structural markers (data:image, etc.)
        - Hex density checks
        - Length invariants
    """
    # EXCLUDE archives from whitelisting (must be scanned by archive_sniff)
    if re.search(
        r"data:application/(?:gzip|x-gzip|zip|x-zip|octet-stream);base64,", text, re.I
    ):
        return False, ""  # Never whitelist potential archives

    # Base64: only whitelist if decode reveals NO provider anchors (GPT-5 fix)
    # Data-URI: ONLY for image/* (application/gzip|zip could hide secrets)
    m = re.search(r"data:image/[^;]+;base64,([A-Za-z0-9+/=]+)", text, re.I)
    if m and not _b64_has_anchor(m.group(1)):
        return True, "base64_data_uri_image_benign"

    # Image headers with base64
    if (
        "Content-Transfer-Encoding: base64" in text
        and "Content-Type: image/" in text.lower()
    ):
        return True, "base64_email_image"

    # Large base64 with valid padding (likely file/image) - but check for anchors
    for line in text.splitlines():
        m = re.search(r"[A-Za-z0-9+/]{200,}={0,2}", line)
        if m and not SUSPICIOUS_INLINE_CTX.search(line):
            frag = m.group(0)
            has_valid_padding = len(frag) % 4 == 0 or frag.endswith(("=", "=="))
            if has_valid_padding and not _b64_has_anchor(frag):
                return True, "base64_large_valid_padding"

    for line in text.splitlines():
        # Check UUID
        for m in UUID_RE.finditer(line):
            if is_uuid_benign(line, m):
                return True, "uuid_benign_context"

        # Check Git hash (require ≥12 chars to avoid short numbers)
        for m in GIT_HASH_RE.finditer(line):
            frag = m.group(0)
            if len(frag) >= 12 and is_git_hash_benign(line, m):
                return True, "git_hash_benign_context"

        # Check SHA256
        for m in SHA256_RE.finditer(line):
            if is_sha256_benign(line, m):
                return True, "sha256_benign_context"

    return False, ""
