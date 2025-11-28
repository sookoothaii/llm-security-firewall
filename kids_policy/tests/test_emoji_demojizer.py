#!/usr/bin/env python3
"""
Test: Emoji Demojizer (v2.0 - NEMESIS-04 Fix)
"""

from kids_policy.unicode_sanitizer import UnicodeSanitizer


def test_emoji_demojize():
    """Test that emojis are converted to text"""
    sanitizer = UnicodeSanitizer(enable_emoji_demojize=True)

    # Test emoji cipher (using Unicode escapes to avoid Windows encoding issues)
    text = "\U0001f52b \U0001f4a5 \U0001f92f \U0001fa78"  # pistol explosion exploding_head drop_of_blood
    sanitized, flags = sanitizer.sanitize(text)

    # Check that emojis were detected
    assert flags["has_emoji"] is True, f"Emojis should be detected. Flags: {flags}"

    # Check that output contains text (not emojis)
    # The demojized text should contain descriptive words
    assert (
        "pistol" in sanitized.lower()
        or "gun" in sanitized.lower()
        or "weapon" in sanitized.lower()
    ), f"Expected 'pistol', 'gun', or 'weapon' in output, got: {sanitized}"

    # Check that output contains violence-related words
    violence_words = ["pistol", "gun", "explosion", "blood", "head", "weapon"]
    assert any(word in sanitized.lower() for word in violence_words), (
        f"Expected violence-related words in output, got: {sanitized}"
    )


def test_emoji_demojize_disabled():
    """Test that emoji demojization can be disabled"""
    sanitizer = UnicodeSanitizer(enable_emoji_demojize=False)

    # Using Unicode escapes
    text = "\U0001f52b \U0001f4a5"
    sanitized, flags = sanitizer.sanitize(text)

    # Should not detect emojis if disabled
    assert flags["has_emoji"] is False, "Emojis should not be detected when disabled"
    # Original emojis should remain (or be unchanged) - check by Unicode code point
    assert "\U0001f52b" in sanitized or "\U0001f4a5" in sanitized, (
        "Emojis should remain when disabled"
    )
