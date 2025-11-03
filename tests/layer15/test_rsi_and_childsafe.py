"""Tests for RSI metrics and ChildSafe aggregation."""

import pytest
import yaml
from pathlib import Path

from src.layer15.rsi_childsafe import RSIMetrics, ChildSafeAggregator


@pytest.fixture
def cfg():
    """Load Layer 15 config."""
    cfg_path = Path(__file__).parent.parent.parent / "config" / "layer15.yaml"
    return yaml.safe_load(cfg_path.read_text(encoding='utf-8'))


def test_rsi_formula_bounds(cfg):
    """Test RSI formula stays within 0-1 bounds."""
    m = RSIMetrics(cfg["rsi_childsafe"])
    
    assert 0.0 <= m.rsi(0.10, 0.20) <= 1.0
    assert 0.0 <= m.rsi(0.90, 0.00) <= 1.0
    assert 0.0 <= m.rsi(0.00, 0.90) <= 1.0


def test_rsi_higher_defect_increases_score(cfg):
    """Test higher defect rate increases RSI."""
    m = RSIMetrics(cfg["rsi_childsafe"])
    
    rsi_low_defect = m.rsi(0.10, 0.20)
    rsi_high_defect = m.rsi(0.90, 0.20)
    
    assert rsi_high_defect > rsi_low_defect


def test_rsi_higher_refusal_decreases_score(cfg):
    """Test higher refusal rate decreases RSI."""
    m = RSIMetrics(cfg["rsi_childsafe"])
    
    rsi_low_refusal = m.rsi(0.50, 0.10)
    rsi_high_refusal = m.rsi(0.50, 0.80)
    
    assert rsi_low_refusal > rsi_high_refusal


def test_childsafe_vector_updates(cfg):
    """Test ChildSafe vector updates correctly."""
    agg = ChildSafeAggregator({"childsafe_dimensions": 3})
    
    agg.update([0.4, 0.6, 0.8])
    agg.update([0.6, 0.4, 0.2])
    
    d = agg.as_dict()
    assert d["n"] == 2
    assert len(d["vector"]) == 3
    assert 0.4 <= d["vector"][0] <= 0.6  # average of 0.4 and 0.6
    assert 0.4 <= d["vector"][1] <= 0.6  # average of 0.6 and 0.4
    assert 0.2 <= d["vector"][2] <= 0.8  # average of 0.8 and 0.2


def test_childsafe_nine_dimensions(cfg):
    """Test ChildSafe with 9 dimensions."""
    agg = ChildSafeAggregator(cfg["rsi_childsafe"])
    
    scores = [0.5, 0.6, 0.7, 0.8, 0.9, 0.4, 0.3, 0.2, 0.1]
    agg.update(scores)
    
    d = agg.as_dict()
    assert d["dimensions"] == 9
    assert len(d["vector"]) == 9
    assert d["n"] == 1


def test_childsafe_dimension_mismatch(cfg):
    """Test ChildSafe raises error on dimension mismatch."""
    agg = ChildSafeAggregator({"childsafe_dimensions": 9})
    
    with pytest.raises(ValueError, match="Dimension mismatch"):
        agg.update([0.5, 0.6, 0.7])  # Only 3 instead of 9


def test_childsafe_running_average(cfg):
    """Test ChildSafe computes running average correctly."""
    agg = ChildSafeAggregator({"childsafe_dimensions": 2})
    
    agg.update([1.0, 0.0])
    assert agg.vector == [1.0, 0.0]
    
    agg.update([0.0, 1.0])
    assert agg.vector == [0.5, 0.5]  # average
    
    agg.update([0.0, 0.0])
    assert abs(agg.vector[0] - 0.333) < 0.01  # (1.0 + 0.0 + 0.0) / 3
    assert abs(agg.vector[1] - 0.333) < 0.01  # (0.0 + 1.0 + 0.0) / 3
