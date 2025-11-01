# -*- coding: utf-8 -*-
"""
Dense Alphabet Heuristic
Closes: Base91-like and custom dense encodings

Detects unusually dense character distributions
"""

import string


def dense_alphabet_flag(
    text: str, min_span_length: int = 30, density_threshold: float = 0.85
):
    """
    Detect dense alphabet spans (Base91-like encodings)

    Args:
        text: Input text
        min_span_length: Minimum contiguous span length
        density_threshold: Minimum ratio of printable symbols

    Returns:
        Detection flags
    """
    # Extended printable set (beyond Base64/85)
    DENSE_CHARS = set(
        string.ascii_letters + string.digits + "!#$%&()*+,-./:;<=>?@[]^_`{|}~\"'\\"
    )

    # Find contiguous dense spans
    dense_spans = []
    current_span = []

    for ch in text:
        if ch in DENSE_CHARS:
            current_span.append(ch)
        else:
            if len(current_span) >= min_span_length:
                dense_spans.append("".join(current_span))
            current_span = []

    # Check last span
    if len(current_span) >= min_span_length:
        dense_spans.append("".join(current_span))

    # Calculate density for each span
    high_density_spans = []
    for span in dense_spans:
        # Check character diversity (not just repeated chars)
        unique_chars = len(set(span))
        diversity = unique_chars / len(span)

        if diversity >= 0.3:  # At least 30% unique chars
            high_density_spans.append(span)

    return {
        "dense_seen": len(high_density_spans) > 0,
        "dense_span_count": len(high_density_spans),
        "max_span_length": max(len(s) for s in high_density_spans)
        if high_density_spans
        else 0,
    }
