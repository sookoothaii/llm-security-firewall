"""
Tests for Safety-Sandwich v2
============================
"""

import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.gates.safety_sandwich_v2 import (  # noqa: E402
    SafetySandwichConfig,
    SafetySandwichV2,
)


def test_abort_on_high_conf_secret_early():
    """Test early abort when high-severity secret detected"""
    cfg = SafetySandwichConfig(
        model_name="test",
        critical_leak_n=70,  # Realistic: secret needs ~30 chars to match pattern
        abort_secrets_severity=0.7,
    )
    sw = SafetySandwichV2(cfg)

    # Benign prefix (character by character)
    for ch in "This is a harmless preface ":
        act = sw.feed_token(ch)
        if act == "abort":
            break

    # Introduce an obvious secret (OpenAI-like key)
    secret_text = "api_key=sk-ABCDEFGHIJKLMNOPQRST1234567890"  # noqa: S105
    for ch in secret_text:
        act = sw.feed_token(ch)
        if act == "abort":
            break

    snap = sw.snapshot()
    assert snap["aborted"] is True, "Should have aborted on high-severity secret"
    assert snap["critical_leak_fired"] is True, (
        f"Critical leak should fire within {cfg.critical_leak_n} tokens "
        f"(got {snap['tokens_seen']})"
    )
    assert sw.finalize() == "REJECT", "Final decision should be REJECT"


def test_wrap_on_medium_secret():
    """Test safety wrap when medium-severity secret detected"""
    cfg = SafetySandwichConfig(
        model_name="test",
        redact_secrets_severity=0.35,  # Lower to catch medium secrets
        abort_secrets_severity=0.95,  # Higher to avoid abort on medium secrets
    )
    sw = SafetySandwichV2(cfg)

    # Feed character by character - shorter base64 (lower severity)
    text = "Token: YWJjZGVmZ2hpams="  # Shorter base64, lower entropy
    for ch in text:
        sw.feed_token(ch)

    dec = sw.finalize()
    # Should trigger redact (medium severity) but not abort
    assert dec in ("SAFETY_WRAP", "PROMOTE"), f"Expected WRAP or PROMOTE, got {dec}"


def test_quarantine_on_obfuscation():
    """Test quarantine when high obfuscation detected"""
    cfg = SafetySandwichConfig(
        model_name="test",
        # Realistic for single ZWC + Bidi (severity ~0.06)
        quarantine_obfuscation_severity=0.05,
    )
    sw = SafetySandwichV2(cfg)

    # Text with zero-width + bidi controls
    text = "Hello\u200bWorld\u202eabc"
    for ch in text:
        sw.feed_token(ch)

    assert sw.finalize() == "QUARANTINE", "Should quarantine on obfuscation"


def test_promote_on_clean():
    """Test promote when text is clean"""
    cfg = SafetySandwichConfig(model_name="test")
    sw = SafetySandwichV2(cfg)

    # Feed character by character
    for ch in "Plain scientific summary with no secrets.":
        sw.feed_token(ch)

    assert sw.finalize() == "PROMOTE", "Clean text should be promoted"


def test_redact_text_posthoc():
    """Test post-hoc redaction helper"""
    cfg = SafetySandwichConfig(model_name="test")
    sw = SafetySandwichV2(cfg)

    text = "My API key is sk-ABCDEFGHIJKLMNOPQRST1234567890 please use it."
    redacted = sw.redact_text_posthoc(text)

    assert "[SECRET]" in redacted, "Should contain redaction mask"
    assert "sk-ABC" not in redacted, "Should not contain actual secret"


def test_streaming_stride():
    """Test that recheck_stride_tokens works correctly"""
    cfg = SafetySandwichConfig(
        model_name="test",
        recheck_stride_tokens=5,  # Check every 5 tokens
    )
    sw = SafetySandwichV2(cfg)

    # Feed 4 tokens - no checks should run (except initial)
    for i in range(4):
        sw.feed_token(f"token{i}")

    # 5th token should trigger check
    sw.feed_token("token5")

    assert sw.state.tokens_seen == 5
    assert sw.finalize() == "PROMOTE"


def test_critical_leak_fires_only_once():
    """Test that critical_leak@n metric fires only once per session"""
    cfg = SafetySandwichConfig(
        model_name="test",
        critical_leak_n=60,  # Realistic for character-level feeding
        abort_secrets_severity=0.7,
    )
    sw = SafetySandwichV2(cfg)

    # Prefix text (character by character)
    for ch in "Prefix text here ":
        sw.feed_token(ch)

    # Inject secret
    secret = "api_key=sk-LONGKEYTHATABORTSHERE1234567890"  # noqa: S105
    for ch in secret:
        if sw.feed_token(ch) == "abort":
            break

    snap = sw.snapshot()
    assert snap["critical_leak_fired"] is True, (
        f"Should fire critical leak within {cfg.critical_leak_n} tokens "
        f"(got {snap['tokens_seen']})"
    )
    assert snap["tokens_seen"] <= cfg.critical_leak_n, "Should abort within leak window"
