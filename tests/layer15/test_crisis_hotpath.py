"""Tests for crisis detection hotpath."""

import pytest
import yaml
from pathlib import Path

from src.layer15.crisis import CrisisDetector


@pytest.fixture
def cfg():
    """Load Layer 15 config."""
    cfg_path = Path(__file__).parent.parent.parent / "config" / "layer15.yaml"
    return yaml.safe_load(cfg_path.read_text(encoding='utf-8'))


def test_crisis_regex_high_self_harm_en(cfg):
    """Test regex detects self-harm language (English)."""
    c = CrisisDetector(cfg["crisis_detection"])
    level, meta = c.decide("I want to kill myself.")
    
    assert level == "high"
    assert meta["reason"] in ("regex_hard", "ml_high")


def test_crisis_regex_high_self_harm_de(cfg):
    """Test regex detects self-harm language (German)."""
    c = CrisisDetector(cfg["crisis_detection"])
    level, meta = c.decide("Ich will mich umbringen.")
    
    assert level == "high"
    assert meta["reason"] in ("regex_hard", "ml_high")


def test_crisis_regex_high_abuse(cfg):
    """Test regex detects abuse disclosure."""
    c = CrisisDetector(cfg["crisis_detection"])
    level, meta = c.decide("He hurt me and I'm not safe at home.")
    
    assert level == "high"
    assert meta["reason"] in ("regex_hard", "ml_high")


def test_crisis_resource_card_us(cfg):
    """Test resource card for US."""
    c = CrisisDetector(cfg["crisis_detection"])
    card = c.resource_card("US")
    
    assert card["language"] == "en"
    assert "988" in card["hotline"]
    assert "911" in card["emergency"]
    assert "988lifeline.org" in card["url"]


def test_crisis_resource_card_de(cfg):
    """Test resource card for Germany."""
    c = CrisisDetector(cfg["crisis_detection"])
    card = c.resource_card("DE")
    
    assert card["language"] == "de"
    assert "112" in card["emergency"]
    assert "TelefonSeelsorge" in card["hotline"]


def test_crisis_resource_card_th(cfg):
    """Test resource card for Thailand."""
    c = CrisisDetector(cfg["crisis_detection"])
    card = c.resource_card("TH")
    
    assert card["language"] == "en"
    assert "1323" in card["hotline"]
    assert "191" in card["emergency"]


def test_crisis_benign_input(cfg):
    """Test benign input returns low level."""
    c = CrisisDetector(cfg["crisis_detection"])
    level, meta = c.decide("I'm feeling sad today but I'll be okay.")
    
    assert level == "low"
    assert meta["reason"] == "none"


def test_crisis_ml_scores_fallback(cfg):
    """Test ML scores work with regex fallback."""
    c = CrisisDetector(cfg["crisis_detection"])
    scores = c.ml_scores("I'm thinking about suicide.")
    
    assert "self_harm" in scores
    assert "abuse" in scores
    assert "unsafe_env" in scores
    assert 0 <= scores["self_harm"] <= 1
