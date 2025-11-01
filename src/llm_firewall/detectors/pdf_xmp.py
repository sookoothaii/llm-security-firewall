# -*- coding: utf-8 -*-
"""
PDF/XMP Heuristic Detection
Closes: PDF streams and XMP metadata obfuscation

Lightweight heuristics without full PDF parsing
"""

import re


def scan_pdf_xmp(text: str):
    """
    Detect PDF and XMP markers in text or Base64

    Returns:
        Flags for PDF/XMP presence
    """
    # Direct PDF markers
    pdf_marker = "%PDF-" in text

    # XMP/Adobe markers
    xmp_marker = any(
        [
            "x:xmpmeta" in text,
            'xmlns:x="adobe:ns:meta/' in text,
            "rdf:RDF" in text and "xap:" in text,
        ]
    )

    # Try Base64 decode if looks like b64
    b64_pattern = r"[A-Za-z0-9+/]{100,}={0,2}"
    b64_matches = re.findall(b64_pattern, text)

    pdf_in_b64 = False
    xmp_in_b64 = False

    for match in b64_matches[:3]:  # Check first 3 spans only (budget)
        try:
            import base64

            decoded = base64.b64decode(match, validate=False)
            decoded_str = decoded[:200].decode("latin-1", errors="ignore")

            if "%PDF-" in decoded_str:
                pdf_in_b64 = True
            if "x:xmpmeta" in decoded_str or "rdf:RDF" in decoded_str:
                xmp_in_b64 = True
        except Exception:
            continue

    return {
        "pdf": pdf_marker or pdf_in_b64,
        "xmp": xmp_marker or xmp_in_b64,
        "pdf_b64": pdf_in_b64,
        "xmp_b64": xmp_in_b64,
        "any_pdf_xmp": pdf_marker or xmp_marker or pdf_in_b64 or xmp_in_b64,
    }
