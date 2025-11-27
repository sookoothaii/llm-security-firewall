"""Tests for Gray Zone Stochasticity MSG Guard.

Tests based on Gemini 3 Pro Preview recommendations (2025-11-26).
"""

import pytest
from typing import Dict, Tuple, Any
from llm_firewall.gates.msg_guard_grayzone import (
    msg_decide_grayzone,
    _get_perturbations,
    PERTURBATION_POOL,
)


def mock_scan_fn(text: str, meta: Dict[str, Any]) -> Tuple[str, float, Dict]:
    """Mock scan function for testing."""
    # Simulate risk scoring based on keywords
    risk = 0.0
    if "jailbreak" in text.lower() or "ignore" in text.lower():
        risk = 0.85  # Gray Zone
    elif "attack" in text.lower() or "hack" in text.lower():
        risk = 0.95  # Danger Zone
    elif "hello" in text.lower():
        risk = 0.30  # Safe Zone

    action = "BLOCK" if risk >= 0.90 else ("WARN" if risk >= 0.70 else "PASS")

    return (action, risk, {"test_contrib": "mock"})


def test_safe_zone_deterministic():
    """Test Safe Zone (0.0-0.70) returns deterministic PASS quickly."""
    text = "Hello, how are you?"
    meta = {}

    action, risk, contrib = msg_decide_grayzone(mock_scan_fn, text, meta)

    assert action == "PASS"
    assert risk < 0.70
    assert contrib["zone"] == "safe"
    assert "deterministic" in contrib["msg_guard"].lower()


def test_danger_zone_deterministic():
    """Test Danger Zone (0.90-1.0) returns deterministic BLOCK quickly."""
    text = "This is an attack attempt"
    meta = {}

    action, risk, contrib = msg_decide_grayzone(mock_scan_fn, text, meta)

    assert action == "BLOCK"
    assert risk >= 0.90
    assert contrib["zone"] == "danger"
    assert "deterministic" in contrib["msg_guard"].lower()


def test_gray_zone_stochastic():
    """Test Gray Zone (0.71-0.89) activates stochastic MSG."""
    text = "This is a jailbreak attempt"
    meta = {}

    action, risk, contrib = msg_decide_grayzone(mock_scan_fn, text, meta)

    assert contrib["zone"] == "gray"
    assert "Gray Zone" in contrib["msg_guard"]
    assert "perturbation_count" in contrib
    assert contrib["perturbation_count"] >= 3  # Should use multiple perturbations


def test_perturbation_pool_size():
    """Test perturbation pool has sufficient diversity."""
    assert len(PERTURBATION_POOL) >= 50, "Pool should have 50+ variations"


def test_perturbation_selection():
    """Test random perturbation selection works."""
    text = "Test input"

    # Run multiple times to check randomness
    results = []
    for _ in range(10):
        perts = _get_perturbations(text, count=5)
        results.append(tuple(sorted(perts)))

    # Should have some variation (not all identical)
    unique_results = len(set(results))
    assert unique_results > 1, "Perturbations should vary between calls"


def test_backward_compatibility():
    """Test backward compatibility with existing msg_decide signature."""
    from llm_firewall.gates.msg_guard import msg_decide

    text = "Hello world"
    meta = {}

    # Should work with same signature
    action, risk, contrib = msg_decide(mock_scan_fn, text, meta)

    assert isinstance(action, str)
    assert isinstance(risk, float)
    assert isinstance(contrib, dict)


def test_critical_signals_override():
    """Test critical signals trigger immediate block even in Gray Zone."""

    def critical_scan_fn(text: str, meta: Dict) -> Tuple[str, float, Dict]:
        return ("BLOCK", 0.75, {"base64_secret": True})

    text = "Suspicious input"
    meta = {}

    action, risk, contrib = msg_decide_grayzone(critical_scan_fn, text, meta)

    # Critical signals should override Gray Zone logic
    assert contrib["zone"] == "gray"
    # Should still process but with lower threshold


def test_performance_safe_zone():
    """Test Safe Zone has minimal overhead (early exit)."""
    import time

    text = "Hello"  # Safe Zone
    meta = {}

    start = time.perf_counter()
    msg_decide_grayzone(mock_scan_fn, text, meta)
    duration = time.perf_counter() - start

    # Should be fast (< 10ms for safe zone)
    assert duration < 0.01, f"Safe Zone should be fast, took {duration * 1000:.2f}ms"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
