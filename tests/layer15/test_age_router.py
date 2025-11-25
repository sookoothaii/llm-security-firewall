"""Tests for age-aware routing."""

import pytest
import yaml
from pathlib import Path

from src.layer15.age_router import AgeRouter


@pytest.fixture
def cfg():
    """Load Layer 15 config."""
    cfg_path = Path(__file__).parent.parent.parent / "config" / "layer15.yaml"
    return yaml.safe_load(cfg_path.read_text(encoding="utf-8"))


def test_age_router_known_band(cfg):
    """Test known age band returns valid policy."""
    r = AgeRouter(cfg["age_router"])
    p = r.get("A6_8")

    assert p.max_tokens <= 200
    assert 0.8 <= p.temperature <= 0.9
    assert p.reading_grade == 2
    assert p.require_bullet_points is True


def test_age_router_all_bands(cfg):
    """Test all configured bands are accessible."""
    r = AgeRouter(cfg["age_router"])

    bands = ["A6_8", "A9_11", "A12_14", "A15_17"]
    for band in bands:
        p = r.get(band)
        assert p.max_tokens > 0
        assert 0 < p.temperature <= 1.0
        assert p.reading_grade >= 0


def test_age_router_unknown_band(cfg):
    """Test unknown band raises KeyError."""
    r = AgeRouter(cfg["age_router"])

    with pytest.raises(KeyError, match="Unknown age band"):
        r.get("A3_5")


def test_age_policy_constraints(cfg):
    """Test policy constraints increase with age."""
    r = AgeRouter(cfg["age_router"])

    p_young = r.get("A6_8")
    p_old = r.get("A15_17")

    # Older bands allow more tokens and complexity
    assert p_old.max_tokens > p_young.max_tokens
    assert p_old.reading_grade > p_young.reading_grade
