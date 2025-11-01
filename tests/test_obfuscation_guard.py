import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.text.obfuscation_guard import analyze_obfuscation


def test_obfuscation_signals_detected():
    text = (
        "Hello\u200bWorld %41%42%43%44%45%46 api_key=XYZ "
        "H4sIAAAAAAAA/8tIzcnJVwjPL8pJAQAA//8BAAD//w== "
        "Confuse: aоe (Latin 'a','e' + Cyrillic 'о')"
    )
    f = analyze_obfuscation(text)
    assert f.zwc_count >= 1
    assert f.url_encoded_spans >= 1, (
        f"Expected URL-encoded spans ≥1, got {f.url_encoded_spans}"
    )
    assert f.base64_spans >= 1 and f.gzip_magic_in_base64 is True
    assert "latin" in f.mixed_scripts and "cyrillic" in f.mixed_scripts
    assert f.confusables_suspected is True
    assert 0.0 <= f.severity <= 1.0


def test_clean_text_low_severity():
    text = "This is normal English text with no obfuscation."
    f = analyze_obfuscation(text)
    assert f.zwc_count == 0
    assert f.bidi_count == 0
    assert f.mixed_script_ratio == 0.0
    assert f.confusables_suspected is False
    assert f.base64_spans == 0
    assert f.severity < 0.1


def test_bidi_controls_detected():
    text = "Text with\u202abidi\u202ccontrols"
    f = analyze_obfuscation(text)
    assert f.bidi_count >= 2


def test_mixed_scripts_cyrillic_greek():
    text = "LatinАБВΑΒΓ"  # Latin + Cyrillic + Greek
    f = analyze_obfuscation(text)
    assert f.mixed_script_ratio > 0.0
    assert "latin" in f.mixed_scripts
    assert "cyrillic" in f.mixed_scripts
    assert "greek" in f.mixed_scripts


def test_hex_run_detected():
    text = "Payload: 48656c6c6f20576f726c640a"  # "Hello World\n" in hex
    f = analyze_obfuscation(text)
    assert f.hex_spans >= 1


def test_rot13_suspected():
    text = "uryyb jbeyq"  # "hello world" in ROT13
    f = analyze_obfuscation(text)
    assert f.rot13_suspected is True


def test_severity_calculation_bounded():
    # Extreme case with all obfuscation signals
    text = "\u200b" * 100 + "ABC%41%42%43" + "AAAA" * 50 + "uryyb"
    f = analyze_obfuscation(text)
    assert 0.0 <= f.severity <= 1.0


if __name__ == "__main__":
    test_obfuscation_signals_detected()
    print("✓ test_obfuscation_signals_detected passed")

    test_clean_text_low_severity()
    print("✓ test_clean_text_low_severity passed")

    test_bidi_controls_detected()
    print("✓ test_bidi_controls_detected passed")

    test_mixed_scripts_cyrillic_greek()
    print("✓ test_mixed_scripts_cyrillic_greek passed")

    test_hex_run_detected()
    print("✓ test_hex_run_detected passed")

    test_rot13_suspected()
    print("✓ test_rot13_suspected passed")

    test_severity_calculation_bounded()
    print("✓ test_severity_calculation_bounded passed")

    print("\nAll obfuscation guard tests passed!")
