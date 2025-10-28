"""Tests for risk stacking"""

import numpy as np
import pytest

try:
    from llm_firewall.risk.stacking import fit_aggregator
    HAS_SKLEARN = True
except Exception:
    HAS_SKLEARN = False


@pytest.mark.skipif(not HAS_SKLEARN, reason="scikit-learn not available")
def test_fit_and_decide_shapes():
    X = np.array([
        [1.0, 0.9, 0.0, 0.9],  # clear unsafe
        [0.0, 0.1, 0.0, 0.1],  # clear safe
        [0.5, 0.6, 0.0, 0.6],
        [0.2, 0.3, 0.0, 0.3],
    ])
    y = np.array([1, 0, 1, 0], dtype=int)
    agg = fit_aggregator(X, y, tau_block=0.85, epsilon=0.05, alpha=0.1)
    block, p = agg.decide(X)
    assert block.shape == (4,) and p.shape == (4,)
    assert (p >= 0.0).all() and (p <= 1.0).all()


@pytest.mark.skipif(not HAS_SKLEARN, reason="scikit-learn not available")
def test_conformal_floor():
    X = np.array([[1.0, 0.9, 0.0, 0.9], [0.0, 0.1, 0.0, 0.1]])
    y = np.array([1, 0], dtype=int)
    agg = fit_aggregator(X, y, tau_block=0.85, epsilon=0.05, alpha=0.1)
    # q_alpha should be computed
    assert agg.q_alpha_ is not None

