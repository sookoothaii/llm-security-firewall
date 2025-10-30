"""
Test GuardNet Feature Extractor

Validates deterministic feature computation.
All features must be reproducible for given inputs.

Creator: Joerg Bollwahn
Date: 2025-10-30
"""

import pytest
from llm_firewall.guardnet.features.extractor import (
    base64_fraction,
    compute_features,
    features_to_vector,
    mixed_script_ratio,
    punct_burst_score,
    zwc_density,
)


def test_zwc_density_empty():
    """Test ZWC density on empty string."""
    assert zwc_density("") == 0.0


def test_zwc_density_no_zwc():
    """Test ZWC density on text without zero-width characters."""
    text = "Hello world"
    assert zwc_density(text) == 0.0


def test_zwc_density_with_zwc():
    """Test ZWC density on text with zero-width characters."""
    text = "Hello\u200Bworld\u200C"  # ZWSP + ZWNJ
    expected = 2 / len(text)
    assert zwc_density(text) == pytest.approx(expected)


def test_base64_fraction_no_base64():
    """Test base64 fraction on normal text."""
    text = "This is normal text"
    assert base64_fraction(text) == 0.0


def test_base64_fraction_with_base64():
    """Test base64 fraction on text with base64 sequences."""
    text = "Token: SGVsbG8gV29ybGQhIFRoaXMgaXM="  # "Hello World! This is" in base64 (24 chars + 1 padding)
    base64_len = len("SGVsbG8gV29ybGQhIFRoaXMgaXM=")
    expected = base64_len / len(text)
    assert base64_fraction(text) == pytest.approx(expected)


def test_base64_fraction_short_sequence():
    """Test that short sequences (<16 chars) are not detected as base64."""
    text = "Short: ABC123"
    assert base64_fraction(text) == 0.0


def test_mixed_script_ratio_latin_only():
    """Test mixed script ratio on Latin-only text."""
    text = "Hello World"
    assert mixed_script_ratio(text) == 0.0


def test_mixed_script_ratio_cyrillic():
    """Test mixed script ratio with Cyrillic characters."""
    text = "HelloПривет"  # Latin + Cyrillic
    latin = 5  # "Hello"
    cyrillic = 6  # "Привет"
    total = latin + cyrillic
    expected = cyrillic / total
    assert mixed_script_ratio(text) == pytest.approx(expected)


def test_mixed_script_ratio_no_alpha():
    """Test mixed script ratio on non-alphabetic text."""
    text = "12345!@#$%"
    assert mixed_script_ratio(text) == 0.0


def test_punct_burst_none():
    """Test punct burst on text without punctuation."""
    text = "Hello world"
    assert punct_burst_score(text) == 0.0


def test_punct_burst_single():
    """Test punct burst with single punctuation marks."""
    text = "Hello. World!"
    assert punct_burst_score(text) == 1.0


def test_punct_burst_consecutive():
    """Test punct burst with consecutive punctuation."""
    text = "What?!?! Really..."
    # "?!?!" = 4, "..." = 3
    assert punct_burst_score(text) == 4.0


def test_compute_features_all_zero():
    """Test compute_features with minimal inputs."""
    text = "Normal text"
    regex_hits = {}
    lid = "en"
    emb_ood_energy = 0.0
    ttl_delta_days = 0
    trust_tier = 0.5

    features = compute_features(text, regex_hits, lid, emb_ood_energy, ttl_delta_days, trust_tier)

    assert isinstance(features, dict)
    assert "zwc_density" in features
    assert "base64_frac" in features
    assert "mixed_script_ratio" in features
    assert "punct_burst" in features
    assert "emb_ood_energy" in features
    assert "ttl_delta_days" in features
    assert "trust_tier" in features
    assert "lid" in features
    assert "regex_hits" in features

    # All should be zero except trust_tier
    assert features["zwc_density"] == 0.0
    assert features["base64_frac"] == 0.0
    assert features["mixed_script_ratio"] == 0.0
    assert features["punct_burst"] == 0.0
    assert features["trust_tier"] == 0.5


def test_compute_features_with_obfuscation():
    """Test compute_features with obfuscated text."""
    text = "Hello\u200BПриветSGVsbG8gV29ybGQhIFRoaXMgaXM=!?!?"  # longer base64 (25 chars)
    regex_hits = {"intent/jailbreak": 2, "evasion/base64": 1}
    lid = "mixed"
    emb_ood_energy = 5.2
    ttl_delta_days = -10  # expired
    trust_tier = 0.3

    features = compute_features(text, regex_hits, lid, emb_ood_energy, ttl_delta_days, trust_tier)

    # Should detect obfuscation signals
    assert features["zwc_density"] > 0.0
    assert features["base64_frac"] > 0.0
    assert features["mixed_script_ratio"] > 0.0
    assert features["punct_burst"] > 0.0
    assert features["emb_ood_energy"] == 5.2
    assert features["ttl_delta_days"] == -10
    assert features["trust_tier"] == 0.3
    assert features["lid"] == "mixed"
    assert features["regex_hits"] == regex_hits


def test_features_to_vector():
    """Test features_to_vector conversion."""
    features = {
        "zwc_density": 0.1,
        "base64_frac": 0.2,
        "mixed_script_ratio": 0.3,
        "punct_burst": 4.0,
        "emb_ood_energy": 5.2,
        "ttl_delta_days": -10,
        "trust_tier": 0.5,
        "lid": "en",
        "regex_hits": {"intent/jailbreak": 2, "evasion/base64": 1},
    }

    category_keys = ["intent/jailbreak", "evasion/base64", "evasion/homoglyph"]

    vec = features_to_vector(features, category_keys)

    # Should have 7 base features + 3 regex categories = 10
    assert len(vec) == 10

    # Validate base features
    assert vec[0] == 0.1  # zwc_density
    assert vec[1] == 0.2  # base64_frac
    assert vec[2] == 0.3  # mixed_script_ratio
    assert vec[3] == 4.0  # punct_burst
    assert vec[4] == 5.2  # emb_ood_energy
    assert vec[5] == -10.0  # ttl_delta_days
    assert vec[6] == 0.5  # trust_tier

    # Validate regex hits
    assert vec[7] == 2.0  # intent/jailbreak
    assert vec[8] == 1.0  # evasion/base64
    assert vec[9] == 0.0  # evasion/homoglyph (not present)


def test_determinism():
    """Test that feature extraction is deterministic."""
    text = "Test\u200Btext!?!?"
    regex_hits = {"test": 1}
    lid = "en"
    emb_ood_energy = 1.5
    ttl_delta_days = 5
    trust_tier = 0.7

    features1 = compute_features(text, regex_hits, lid, emb_ood_energy, ttl_delta_days, trust_tier)
    features2 = compute_features(text, regex_hits, lid, emb_ood_energy, ttl_delta_days, trust_tier)

    # All features should be identical
    assert features1 == features2


if __name__ == "__main__":
    # Run tests manually
    test_zwc_density_empty()
    test_zwc_density_no_zwc()
    test_zwc_density_with_zwc()
    print("✓ ZWC density tests passed")

    test_base64_fraction_no_base64()
    test_base64_fraction_with_base64()
    test_base64_fraction_short_sequence()
    print("✓ Base64 fraction tests passed")

    test_mixed_script_ratio_latin_only()
    test_mixed_script_ratio_cyrillic()
    test_mixed_script_ratio_no_alpha()
    print("✓ Mixed script ratio tests passed")

    test_punct_burst_none()
    test_punct_burst_single()
    test_punct_burst_consecutive()
    print("✓ Punct burst tests passed")

    test_compute_features_all_zero()
    test_compute_features_with_obfuscation()
    print("✓ compute_features tests passed")

    test_features_to_vector()
    print("✓ features_to_vector test passed")

    test_determinism()
    print("✓ Determinism test passed")

    print("\nAll feature extractor tests passed!")

