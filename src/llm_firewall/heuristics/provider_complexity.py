"""
Provider-specific grammar validation with complexity checks.

GPT-5 Design: Combine structural validation with complexity metrics
to distinguish real provider keys from low-entropy fakes.

Coverage: Closes adv_011 (fake_provider_low_entropy)
"""
from __future__ import annotations

import zlib
from collections import Counter
from math import log2

# Provider-specific grammar specs (GPT-5)
PROVIDER_SPECS = {
    "sk-live": {"alphabet": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "min_len": 48, "max_len": 51},  # noqa: E501
    "sk-test": {"alphabet": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "min_len": 48, "max_len": 51},  # noqa: E501
    "ghp_": {"alphabet": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "min_len": 36, "max_len": 255},  # noqa: E501
    "gho_": {"alphabet": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "min_len": 36, "max_len": 255},  # noqa: E501
}


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits."""
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def compression_ratio(s: str) -> float:
    """Compression ratio (GPT-5: Kolmogorov proxy)."""
    if not s:
        return 1.0
    compressed = zlib.compress(s.encode())
    return len(compressed) / max(1, len(s))


def has_long_run(s: str, max_run: int = 3) -> bool:
    """Check for runs of identical characters (GPT-5)."""
    if len(s) < max_run + 1:
        return False

    run = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            run += 1
            if run > max_run:
                return True
        else:
            run = 1
    return False


def provider_grammar_ok(prefix: str, tail: str) -> bool:
    """Check if tail matches provider-specific grammar."""
    if prefix not in PROVIDER_SPECS:
        return False

    spec = PROVIDER_SPECS[prefix]

    # Length check
    if not (spec["min_len"] <= len(tail) <= spec["max_len"]):
        return False

    # Alphabet check
    alphabet_set = set(spec["alphabet"])
    if not all(ch in alphabet_set for ch in tail):
        return False

    return True


def is_strong_secret_provider(text: str) -> bool:
    """
    Detect high-confidence provider secrets (GPT-5 framework).

    Criteria:
    1. Provider grammar match (prefix + length + alphabet)
    2. NO long runs (max 3 identical chars)
    3. Sufficient unique chars (≥6)
    4. Complexity: Shannon ≥2.8 OR Compression ≥0.85

    Returns:
        True if all criteria met (strong evidence)
    """
    text_low = text.lower()

    for prefix in PROVIDER_SPECS.keys():
        idx = text_low.find(prefix)
        if idx >= 0:
            # Extract tail
            tail_start = idx + len(prefix)
            tail = text[tail_start:]
            tail_alnum = "".join(ch for ch in tail if ch.isalnum())

            # Check grammar
            if not provider_grammar_ok(prefix, tail_alnum):
                continue

            # Complexity checks (GPT-5)
            if has_long_run(tail_alnum, max_run=3):
                continue  # Too repetitive

            unique_chars = len(set(tail_alnum))
            if unique_chars < 6:
                continue  # Too few unique chars

            # Dual complexity metric (GPT-5)
            h = shannon_entropy(tail_alnum)
            cr = compression_ratio(tail_alnum)

            if h >= 2.8 or cr >= 0.85:
                return True  # Strong evidence

    return False


def is_weak_secret_provider(text: str) -> bool:
    """
    Detect weak/fake provider secrets.

    Has provider prefix + reasonable length, but fails complexity checks.
    Used for WARN (not BLOCK) + E-value accumulation.

    Returns:
        True if provider-like but low complexity
    """
    text_low = text.lower()

    for prefix in PROVIDER_SPECS.keys():
        idx = text_low.find(prefix)
        if idx >= 0:
            tail_start = idx + len(prefix)
            tail = text[tail_start:]
            tail_alnum = "".join(ch for ch in tail if ch.isalnum())

            # Reasonable length but NOT strong
            if 16 <= len(tail_alnum) <= PROVIDER_SPECS[prefix]["max_len"]:
                if not is_strong_secret_provider(text):
                    return True

    return False

