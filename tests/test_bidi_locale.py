"""Tests for Bidi controls and locale-aware labels."""
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.detectors.bidi_locale import (  # noqa: E402
    bidi_controls_present,
    detect_bidi_locale,
    locale_label_hits,
)


def test_bidi_controls_flag():
    """Test bidi control detection."""
    # RLO (Right-to-Left Override)
    text_rlo = "\u202E abc \u202C"
    assert bidi_controls_present(text_rlo) is True

    # FSI (First Strong Isolate)
    text_fsi = "\u2068 test \u2069"
    assert bidi_controls_present(text_fsi) is True

    # Clean text
    assert bidi_controls_present("normal text") is False


def test_bidi_rlo_wrap():
    """Test RLO wrap attack (adv_002)."""
    text = "\u202E dcb a0987654321-FEDCBA-evil sk-live-"

    assert bidi_controls_present(text) is True
    result = detect_bidi_locale(text)

    assert result["has_bidi"] is True
    assert result["severity_uplift"] >= 0.9, "Bidi should uplift severity"


def test_locale_labels_arabic():
    """Test Arabic password label (adv_046)."""
    text = "الآن مفتاح sk-live-ABCD"

    hits = locale_label_hits(text)
    assert hits >= 1, "Should detect Arabic 'key' label"


def test_locale_labels_hindi():
    """Test Hindi password label (adv_043)."""
    text = "पासवर्ड: Secr3t!!; key: sk-live-ABCD"

    hits = locale_label_hits(text)
    assert hits >= 1, "Should detect Hindi password"


def test_locale_labels_chinese():
    """Test Chinese password label."""
    text = "密码: sk-live-ABCD1234"

    hits = locale_label_hits(text)
    assert hits >= 1, "Should detect Chinese password"


def test_detect_bidi_locale_combined():
    """Test combined bidi + locale detection."""
    text = "\u202E密码 sk-live\u202C"

    result = detect_bidi_locale(text)
    assert result["has_bidi"] is True
    assert result["locale_hits"] >= 1
    assert result["severity_uplift"] >= 0.9, "Should have high uplift"


def test_no_false_positive():
    """Test clean text has no hits."""
    text = "This is normal English text."

    assert bidi_controls_present(text) is False
    assert locale_label_hits(text) == 0

    result = detect_bidi_locale(text)
    assert result["severity_uplift"] == 0.0

