"""Tests for deceptive empathy filter."""

import pytest
import yaml
from pathlib import Path

from src.layer15.deceptive_empathy import DeceptiveEmpathyFilter


@pytest.fixture
def cfg():
    """Load Layer 15 config."""
    cfg_path = Path(__file__).parent.parent.parent / "config" / "layer15.yaml"
    return yaml.safe_load(cfg_path.read_text(encoding='utf-8'))


def test_rewrite_transparency_en(cfg):
    """Test rewriting adds transparency statement (English)."""
    f = DeceptiveEmpathyFilter(cfg["deceptive_empathy_filter"])
    out, changed = f.rewrite(
        "Oh dear friend, I see you. As your friend I will always be here.",
        lang="en"
    )
    
    assert changed is True
    assert "I'm an AI system" in out
    assert "friend" not in out.lower()  # stripped


def test_rewrite_transparency_de(cfg):
    """Test rewriting adds transparency statement (German)."""
    f = DeceptiveEmpathyFilter(cfg["deceptive_empathy_filter"])
    out, changed = f.rewrite(
        "Ich sehe dich. Als dein Freund bin ich hier.",
        lang="de"
    )
    
    assert changed is True
    assert "KI-System" in out


def test_no_change_when_clean(cfg):
    """Test clean text passes through unchanged."""
    f = DeceptiveEmpathyFilter(cfg["deceptive_empathy_filter"])
    out, changed = f.rewrite(
        "I can provide information about coping strategies.",
        lang="en"
    )
    
    assert changed is False
    assert out.startswith("I can provide")


def test_scan_detects_generic_empathy(cfg):
    """Test scan detects generic empathy phrases."""
    f = DeceptiveEmpathyFilter(cfg["deceptive_empathy_filter"])
    
    assert f.scan("I hear you") is True
    assert f.scan("I feel you") is True
    assert f.scan("I am here with you") is True


def test_scan_detects_false_self_disclosure(cfg):
    """Test scan detects false self-disclosure."""
    f = DeceptiveEmpathyFilter(cfg["deceptive_empathy_filter"])
    
    assert f.scan("In my experience as a therapist") is True
    assert f.scan("I also struggle with this") is True


def test_scan_clean_text(cfg):
    """Test scan returns False for clean text."""
    f = DeceptiveEmpathyFilter(cfg["deceptive_empathy_filter"])
    
    assert f.scan("Here is some information") is False
    assert f.scan("You can try these strategies") is False
