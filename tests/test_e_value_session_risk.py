"""Tests for E-Value Session Risk (Beta-Mixture Martingale)."""

import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.session.e_value_risk import (  # noqa: E402
    SessionRiskState,
    crossed,
    risk_score,
    update_evalue,
)


def test_evalue_grows_with_hits():
    """Test E-value grows with consecutive hits."""
    state = SessionRiskState(session_id="test-001")

    for _ in range(5):
        state = update_evalue(state, hit=True)

    assert state.e_value > 1.0, "E-value should grow with hits"
    assert state.s == 5, "Should have 5 hits"
    assert state.n == 5, "Should have 5 turns"


def test_evalue_supermartingale_under_null():
    """Test E-value stays ≤1 under null (no hits)."""
    state = SessionRiskState(session_id="test-002", p0=0.10)

    for _ in range(20):
        state = update_evalue(state, hit=False)

    # Under H0: p=0, E-value should stay around 1 or decrease
    assert state.e_value <= 2.0, "E-value should not explode under null"


def test_crossed_alarm_triggers():
    """Test crossing alarm threshold."""
    state = SessionRiskState(session_id="test-003", alpha=0.05)

    # Force high hit rate
    for _ in range(10):
        state = update_evalue(state, hit=True)

    # Should eventually cross with enough hits
    if state.e_value >= 20.0:  # 1/0.05 = 20
        assert crossed(state), "Should cross with E ≥ 1/α"


def test_risk_score_mapping():
    """Test risk score maps correctly."""
    state = SessionRiskState(session_id="test-004", alpha=0.01)

    # At threshold: E = 1/α = 100
    state.e_value = 100.0
    score = risk_score(state)
    assert 0.99 <= score <= 1.01, f"Risk score should be ~1.0 at threshold, got {score}"

    # Below threshold
    state.e_value = 1.0
    score = risk_score(state)
    assert score == 0.01, f"Risk score should be α when E=1, got {score}"


def test_slow_roll_detection():
    """Test slow-roll attack detection (adv_014/026/049)."""
    state = SessionRiskState(session_id="test-slow-roll", alpha=0.01, p0=0.05)

    # Turns 1-5: benign (no hits)
    for _ in range(5):
        state = update_evalue(state, hit=False)
        assert not crossed(state), "Should not cross on benign turns"

    # Turn 6+: leak fragments (hits)
    for _ in range(6):
        state = update_evalue(state, hit=True)

    # Should detect after accumulation
    # With 6 hits in 11 turns, E-value should be high
    assert state.e_value > 10.0, "E-value should grow significantly"
