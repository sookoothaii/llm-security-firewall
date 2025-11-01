# -*- coding: utf-8 -*-
"""
RC2 P3.1 Mini-Tests
Quick validation of placement-aware Unicode + Proof-of-Risk
"""

import sys
from pathlib import Path

repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "src"))

from llm_firewall.policy.risk_weights_v2 import decide_action
from llm_firewall.preprocess.context import classify_context


def _test_action(text: str, expected_actions: tuple) -> None:
    """Helper to test firewall action"""
    ctx = classify_context(text)

    # Inline detector runner (simplified for tests)
    from llm_firewall.detectors.unicode_exotic import detect_exotic_unicode
    from llm_firewall.normalizers.decoded_risk import classify_decoded
    from llm_firewall.normalizers.encoding_chain import try_decode_chain

    hits = []

    # Decode
    decoded, stages, _, buf = try_decode_chain(text)
    if stages >= 1:
        hits.append(f"chain_decoded_{stages}_stages")
        if buf:
            risk_class = classify_decoded(buf)
            hits.append(risk_class)

    # Exotic Unicode
    _, exotic_flags = detect_exotic_unicode(text)
    if exotic_flags["ligature_seen"]:
        hits.append("unicode_ligature_seen")
    if exotic_flags["math_alpha_seen"]:
        hits.append("unicode_math_alpha_seen")
    if exotic_flags["enclosed_seen"]:
        hits.append("unicode_enclosed_seen")

    # Mixed scripts (for homoglyph detection)
    from llm_firewall.detectors.unicode_hardening import strip_bidi_zw

    _, flags = strip_bidi_zw(text)
    if flags.get("mixed_scripts"):
        hits.append("mixed_scripts")

    action, risk, contrib = decide_action(hits, ctx, text=text)

    assert action in expected_actions, (
        f"Expected {expected_actions}, got {action} (risk={risk:.2f}, hits={hits})"
    )


def test_media_b64_is_pass_or_warn_in_code():
    """Benign media Base64 should pass or warn (not block)"""
    # PNG header in Base64
    text = """/* PNG image */
iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==
"""
    _test_action(text, ("PASS", "WARN"))


def test_secretlike_blocks_in_code():
    """Decoded secret-like content should block"""
    import base64

    secret = b"sk_live_XXXXXXXXXXXXXXXX"
    encoded = base64.b64encode(secret).decode()
    text = f"# Config\nAPI_KEY={encoded}"
    _test_action(text, ("BLOCK",))


def test_exotic_in_comment_neutralized():
    """Exotic Unicode in comments should be neutralized"""
    text = """
# Comment with ligatures: ﬀ ﬁ ﬂ
# Math symbols: 𝑨 𝒙
# Enclosed: Ⓐ Ⓑ
def normal_function():
    pass
"""
    _test_action(text, ("PASS", "WARN"))


def test_exotic_in_identifier_is_warn_or_block():
    """Exotic Unicode in identifiers should warn or block"""
    text = """
int 𝐱𝟙 = 1;  // Math bold
var 𝑷𝒘 = 2;  // Math script
"""
    _test_action(text, ("WARN", "BLOCK"))


def test_mixed_script_identifier_blocks():
    """Mixed-script identifiers (Cyrillic homoglyphs) should warn/block"""
    # Contains Cyrillic 'a' (U+0430) which looks like Latin 'a'
    text = """
int раssword = 1;  // Cyrillic 'a' in 'password'
"""
    _test_action(text, ("WARN", "BLOCK"))


def test_bidi_natural_blocks():
    """Bidi controls in natural text should block"""
    from llm_firewall.detectors.unicode_hardening import strip_bidi_zw

    text = "Normal text\u202eRIGHT-TO-LEFT OVERRIDE hidden"
    ctx = classify_context(text)

    _, flags = strip_bidi_zw(text)
    hits = []
    if flags.get("bidi_seen"):
        hits.append("bidi_controls")

    action, risk, _ = decide_action(hits, ctx, text=text)
    assert action in ("WARN", "BLOCK"), (
        f"Bidi should warn/block in natural, got {action}"
    )


if __name__ == "__main__":
    print("Running RC2 P3.1 Mini-Tests...")

    try:
        test_media_b64_is_pass_or_warn_in_code()
        print("[OK] test_media_b64_is_pass_or_warn_in_code")
    except AssertionError as e:
        print(f"[X] test_media_b64_is_pass_or_warn_in_code: {e}")

    try:
        test_secretlike_blocks_in_code()
        print("[OK] test_secretlike_blocks_in_code")
    except AssertionError as e:
        print(f"[X] test_secretlike_blocks_in_code: {e}")

    try:
        test_exotic_in_comment_neutralized()
        print("[OK] test_exotic_in_comment_neutralized")
    except AssertionError as e:
        print(f"[X] test_exotic_in_comment_neutralized: {e}")

    try:
        test_exotic_in_identifier_is_warn_or_block()
        print("[OK] test_exotic_in_identifier_is_warn_or_block")
    except AssertionError as e:
        print(f"[X] test_exotic_in_identifier_is_warn_or_block: {e}")

    try:
        test_mixed_script_identifier_blocks()
        print("[OK] test_mixed_script_identifier_blocks")
    except AssertionError as e:
        print(f"[X] test_mixed_script_identifier_blocks: {e}")

    try:
        test_bidi_natural_blocks()
        print("[OK] test_bidi_natural_blocks")
    except AssertionError as e:
        print(f"[X] test_bidi_natural_blocks: {e}")

    print("\nRC2 P3.1 Mini-Tests COMPLETE")
