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
    re.I
)
BENIGN_INLINE_CTX = re.compile(
    r"(commit|sha256|checksum|uuid|rev(?:ision)?|etag|git|digest|fingerprint|content-md5)",
    re.I
)

# Base64 structural markers (GPT-5)
BASE64_IMAGE_STRUCTURAL = re.compile(
    r"(data:image/(png|jpeg|gif|webp);base64,|"
    r"src\s*=\s*[\"']data:image/[^\"']+;base64,|"
    r"Content-Type:\s*image/)",
    re.I
)

# Suspicious context (overrides benign)
SUSPICIOUS_INLINE_CTX = re.compile(
    r"(secret|token|api[_-]?key|bearer|x-api-key|authorization|passwd|password)",
    re.I
)


def left_context(line: str, pos: int, window: int = 20) -> str:
    """Extract left context window before position."""
    start = max(0, pos - window)
    return line[start:pos]


def is_uuid_benign(line: str, m: re.Match) -> bool:
    """Check if UUID appears in benign context."""
    lctx = left_context(line, m.start())
    # Check for suspicious keywords in left context FIRST
    if SUSPICIOUS_INLINE_CTX.search(lctx):
        return False
    if BENIGN_LEFT_CTX.search(lctx):
        return True
    if BENIGN_INLINE_CTX.search(line) and not SUSPICIOUS_INLINE_CTX.search(line):
        return True
    return False


def is_git_hash_benign(line: str, m: re.Match) -> bool:
    """Check if git hash appears in benign context (GPT-5 hex-density check)."""
    lctx = left_context(line, m.start())
    frag = m.group(0)

    # Hex density check (≥95% hex chars)
    hex_density = sum(ch in "0123456789abcdefABCDEF" for ch in frag) / len(frag)
    if hex_density < 0.95:
        return False

    # Check for suspicious keywords in left context FIRST
    if SUSPICIOUS_INLINE_CTX.search(lctx):
        return False
    if BENIGN_LEFT_CTX.search(lctx):
        return True
    if "commit" in line.lower() and not SUSPICIOUS_INLINE_CTX.search(line):
        return True
    return False


def is_sha256_benign(line: str, m: re.Match) -> bool:
    """Check if SHA256 appears in benign context (GPT-5 length-invariant)."""
    lctx = left_context(line, m.start())
    frag = m.group(0)

    # Length invariant: SHA256 = exactly 64 hex chars
    if len(frag) != 64:
        return False

    # Check for suspicious keywords FIRST
    if SUSPICIOUS_INLINE_CTX.search(lctx):
        return False

    if BENIGN_LEFT_CTX.search(lctx) or ("sha256" in line.lower()):
        if not SUSPICIOUS_INLINE_CTX.search(line):
            return True

    return False


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
    # Base64 structural allow (GPT-5)
    if BASE64_IMAGE_STRUCTURAL.search(text):
        if "Content-Transfer-Encoding: base64" in text or "data:image" in text:
            return True, "base64_image_structural"

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

