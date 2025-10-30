"""Tests for bidi proximity uplift."""
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.detectors.bidi_locale import bidi_proximity_uplift  # noqa: E402


def test_bidi_near_provider_prefix():
    """Test bidi control near sk-live triggers uplift (adv_013)."""
    # RLO near sk-live
    text = "prefix \u202E sk-live-ABCD \u202C suffix"

    result = bidi_proximity_uplift(text, ["sk-live"], radius=8)
    assert result is True, "Bidi near anchor should uplift"


def test_bidi_far_from_anchor_no_uplift():
    """Test bidi control far from anchor doesn't trigger."""
    # Bidi at position 5, sk-live at position 50
    text = "aaaa \u202E bbb " + ("x" * 40) + " sk-live-ABCD"

    result = bidi_proximity_uplift(text, ["sk-live"], radius=8)
    assert result is False, "Bidi far from anchor should not uplift"


def test_no_bidi_no_uplift():
    """Test clean text has no uplift."""
    text = "normal text with sk-live-ABCD"

    result = bidi_proximity_uplift(text, ["sk-live"], radius=8)
    assert result is False

