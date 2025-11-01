"""Tests for advanced Unicode hardening (GPT-5 design)."""

import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.normalize.unicode_hardening import (  # noqa: E402
    confusable_skeleton,
    harden_text_for_scanning,
    nfkc_plus,
    remove_spaces_punct,
    strip_default_ignorable,
)


def test_fullwidth_digits_normalized():
    """Test fullwidth digit normalization (adv_012, adv_050)."""
    text = "sk-live-１２３４５６７８９０"
    result = harden_text_for_scanning(text)

    normalized = result["normalized"]
    assert "1234567890" in normalized, f"Should normalize fullwidth, got {normalized}"


def test_confusable_mapping():
    """Test confusable skeleton (adv_003)."""
    # Cyrillic 'Р' (P) and 'а' (a)
    text = "Рaѕѕwоrd"
    skeleton = confusable_skeleton(text)

    # Should map Cyrillic to Latin
    assert "P" in skeleton or "p" in skeleton, f"Should map Cyrillic, got {skeleton}"


def test_zero_width_stripped():
    """Test zero-width character removal."""
    text = "sk\u200d-live\u200b-ABCD"
    stripped, had, used = strip_default_ignorable(text)

    assert had is True, "Should detect zero-width"
    assert "sk-live-ABCD" in stripped, f"Should remove ZW, got {stripped}"


def test_bidi_isolates_detected():
    """Test bidi isolate detection (adv_013)."""
    text = "\u2067sk-live-ABCD\u2069"
    result = harden_text_for_scanning(text)

    assert result["had_ignorable"] is True
    assert result["severity_uplift"] >= 0.9, "Should have high uplift for isolates"


def test_strip_rematch_interleave():
    """Test strip-rematch catches interleave (adv_009, adv_044)."""
    # s*k*-l*i*v*e*
    text = "s*k*-l*i*v*e*-ABCD"
    compact = remove_spaces_punct(text)

    msg = f"Should remove interleave, got {compact}"
    assert "sklive" in compact or "sk-live" in compact, msg


def test_strip_rematch_punctuation():
    """Test strip-rematch catches punctuation split (adv_015)."""
    text = "sk-..live..ABCD"
    compact = remove_spaces_punct(text)

    assert "sklive" in compact, f"Should remove punctuation, got {compact}"


def test_spaces_plus_fullwidth():
    """Test combination attack (adv_050)."""
    text = "sk - live - ABCD１２３４EFGH５６７８"
    result = harden_text_for_scanning(text)

    normalized = result["normalized"]
    compact = result["compact"]

    # Normalized should have ASCII digits
    assert "1234" in normalized, f"Should normalize fullwidth, got {normalized}"

    # Compact should remove spaces
    assert "sklive" in compact, f"Should remove spaces, got {compact}"


def test_nfkc_plus_comprehensive():
    """Test full NFKC+ pipeline."""
    # Cyrillic + fullwidth + confusables
    text = "Рaｓｓwоrd１２３"
    result = nfkc_plus(text)

    # Should normalize everything
    assert "123" in result, f"Should have ASCII digits, got {result}"
    # Cyrillic should be mapped (at least partially)
    assert "a" in result or "P" in result, f"Should map confusables, got {result}"


def test_no_false_positive_clean_text():
    """Test clean text passes through."""
    text = "Normal English text with numbers 123"
    result = harden_text_for_scanning(text)

    assert result["severity_uplift"] == 0.0
    assert result["had_ignorable"] is False
    assert len(result["bidi_positions"]) == 0
