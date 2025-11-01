# -*- coding: utf-8 -*-
"""
Secret Pattern Detector
Distinguishes decoded_secretlike from decoded_benign_media
RC2 P2.7: Proof-of-Risk not just Proof-of-Decode
"""
import re

# Strong secret patterns (curated, non-exhaustive)
SECRET_PATTERNS = [
    re.compile(rb"\bsk_(live|test)_[A-Za-z0-9]{16,}\b"),                 # Stripe
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),                                # AWS Key ID
    re.compile(rb"\bASIA[0-9A-Z]{16}\b"),                                # AWS Session
    re.compile(rb"\bAIza[0-9A-Za-z\-_]{35}\b"),                          # Google API
    re.compile(rb"\bxox[aboprs]-[0-9A-Za-z\-]{10,}\b"),                  # Slack
    re.compile(rb"\bgh[oprsu]_[A-Za-z0-9]{36}\b"),                       # GitHub
    re.compile(rb"\bya29\.[0-9A-Za-z\-_]{20,}\b"),                       # Google OAuth
    re.compile(rb"-----BEGIN (EC|RSA|DSA|OPENSSH|PRIVATE) KEY-----"),    # Private Keys
    re.compile(rb"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),  # JWT
    re.compile(rb"\[\[SECRET"),                                          # Test marker
    re.compile(rb"\[\[INTENT"),                                          # Test marker
    re.compile(rb"\[\[HARM"),                                            # Test marker
]

# Benign media headers
MEDIA_PREFIXES = (
    b"\x89PNG",      # PNG
    b"\xff\xd8\xff", # JPEG
    b"GIF87a",       # GIF87
    b"GIF89a",       # GIF89
    b"RIFF",         # WebP/WAV
    b"<svg",         # SVG (UTF-8)
    b"<?xml",        # XML
)

# Public key markers
PUBLIC_MARKERS = (
    b"BEGIN PUBLIC KEY",
    b"ssh-rsa ",
    b"ssh-ed25519 ",
)


def classify_decoded(buf: bytes) -> dict:
    """
    Classify decoded buffer
    
    Returns:
        {
            'secretlike': bool,
            'benign_media': bool,
            'public_material': bool
        }
    """
    if not buf or len(buf) < 4:
        return {'secretlike': False, 'benign_media': False, 'public_material': False}

    # Check secret patterns
    secretlike = any(pattern.search(buf) for pattern in SECRET_PATTERNS)

    # Check benign media
    benign_media = any(buf.startswith(prefix) for prefix in MEDIA_PREFIXES)

    # Check public material
    public_material = any(marker in buf[:2048] for marker in PUBLIC_MARKERS)

    return {
        'secretlike': secretlike,
        'benign_media': benign_media,
        'public_material': public_material
    }

