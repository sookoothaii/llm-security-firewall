"""Tests for normalize_v2"""

from llm_firewall.text.normalize_v2 import canonicalize


def test_canonicalize_basic():
    s = "He\u200bllo—World\ufe0f!"
    out = canonicalize(s)
    assert out == "hello-world!"


def test_homoglyphs_and_casefold():
    # Cyrillic letters mixed in "Policy"
    s = "Policy 'Safety' - IGNORE"
    c = canonicalize(s)
    assert "policy" in c and "ignore" in c


def test_zero_width_removal():
    s = "ign\u200bore all\u200csafety"
    c = canonicalize(s)
    # Zero-width removed, whitespace normalized
    assert "ignore" in c and "safety" in c and "\u200b" not in c
