# -*- coding: utf-8 -*-
"""
Armor/MIME Marker Detection
Closes: PGP-Armor, S/MIME, MIME boundary obfuscation

Heuristic markers for armored/encoded content
"""

import re


def scan_armor_markers(text: str):
    """
    Detect armor/MIME markers

    Returns:
        Flags for various armor types
    """
    # PGP Armor markers
    pgp_armor = any(
        ["-----BEGIN PGP" in text, "-----END PGP" in text, "BEGIN PGP MESSAGE" in text]
    )

    # S/MIME markers
    smime_ct = any(
        [
            "Content-Type: application/pkcs7" in text,
            "Content-Type: application/x-pkcs7" in text,
            "application/pkcs7-mime" in text.lower(),
        ]
    )

    # MIME boundary markers
    mime_boundary = bool(re.search(r"--[A-Za-z0-9_-]{10,}", text))

    # Multipart markers
    multipart = "Content-Type: multipart/" in text

    return {
        "pgp_armor": pgp_armor,
        "smime_ct": smime_ct,
        "mime_boundary": mime_boundary,
        "multipart": multipart,
        "any_armor": pgp_armor or smime_ct or mime_boundary,
    }
