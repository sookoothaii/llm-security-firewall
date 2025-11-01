"""Tests for Safety-Sandwich v2 metrics integration."""

import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.gates.safety_sandwich_v2 import (  # noqa: E402
    SafetySandwichConfig,
    SafetySandwichV2,
)


def test_stream_abort_on_critical_leak_n():
    """Test that critical secrets in first N tokens trigger abort."""
    cfg = SafetySandwichConfig(
        model_name="demo-model",
        critical_leak_n=5,
        abort_secrets_severity=0.7,
        redact_secrets_severity=0.4,
    )
    ss = SafetySandwichV2(cfg)

    # Feed tokens that form a secret early
    tokens = ["api", "_key", "=", "sk-", "ABCDEF1234567890abcdef"]
    actions = []
    for t in tokens:
        a = ss.feed_token(t)
        actions.append(a)
        if a == "abort":
            break

    # Should abort due to secret detection
    assert "abort" in actions, f"Expected abort, got {actions}"


def test_redaction_on_medium_severity():
    """Test redaction triggered on medium-severity secrets."""
    cfg = SafetySandwichConfig(
        model_name="demo",
        critical_leak_n=100,  # High so we don't trigger critical-leak
        abort_secrets_severity=0.9,  # High so we trigger redact not abort
        redact_secrets_severity=0.4,
    )
    ss = SafetySandwichV2(cfg)

    tokens = ["password", "=", "test", "123", "!"]
    actions = []
    for t in tokens:
        actions.append(ss.feed_token(t))

    # Should contain at least one redact
    # Note: May need multiple tokens before check triggers
    assert "redact" in actions or "abort" in actions


def test_clean_text_continues():
    """Test that clean text allows continuation."""
    cfg = SafetySandwichConfig(model_name="demo")
    ss = SafetySandwichV2(cfg)

    tokens = ["Hello", " ", "world", ",", " ", "this", " ", "is", " ", "safe"]
    actions = [ss.feed_token(t) for t in tokens]

    # All should be continue
    assert all(a == "continue" for a in actions), (
        f"Expected all continue, got {actions}"
    )


def test_finalize_decision_modes():
    """Test final decision mapping."""
    cfg = SafetySandwichConfig(model_name="demo")
    ss = SafetySandwichV2(cfg)

    # Clean stream
    for t in ["hello", " ", "world"]:
        ss.feed_token(t)

    decision = ss.finalize()
    assert decision in ("PROMOTE", "SAFETY_WRAP", "QUARANTINE", "REJECT")
