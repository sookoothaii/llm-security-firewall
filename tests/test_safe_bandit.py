import pathlib
import sys

import numpy as np

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.calibration.safe_bandit import (
    evaluate_threshold,
    optimize_threshold_offline,
    safe_ucb_simulation,
)


def test_offline_optim_fpr_constraint():
    rng = np.random.default_rng(7)
    # attacks: lower scores (harder to detect) than benign
    att = rng.normal(loc=0.3, scale=0.1, size=1000).clip(0,1)
    ben = rng.normal(loc=0.8, scale=0.1, size=4000).clip(0,1)
    s = np.concatenate([att, ben])
    y = np.concatenate([np.ones(len(att)), np.zeros(len(ben))]).astype(int)

    m = optimize_threshold_offline(s, y, fpr_max=0.01)
    assert m.fpr <= 0.01 + 1e-6
    # With reasonable separation we expect low ASR
    assert m.asr < 0.25

def test_safe_ucb_simulation_safe_choice():
    rng = np.random.default_rng(11)
    att = rng.normal(0.35, 0.12, size=1500).clip(0,1)
    ben = rng.normal(0.85, 0.10, size=4500).clip(0,1)
    s = np.concatenate([att, ben])
    y = np.concatenate([np.ones(len(att)), np.zeros(len(ben))]).astype(int)
    grid = list(np.linspace(0.05, 0.95, 19))
    out = safe_ucb_simulation(s, y, grid, fpr_max=0.01, horizon=1500, seed=1337)
    assert out.fpr <= 0.02  # loose upper bound due to randomness

def test_evaluate_threshold_basic():
    scores = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9])
    labels = np.array([1, 1, 1, 0, 0, 0])  # 1=attack, 0=benign

    # Threshold 0.5: attacks (0.1,0.2,0.3) bypass, benign (0.7,0.8,0.9) blocked
    m = evaluate_threshold(scores, labels, thr=0.5)
    assert m.asr == 1.0  # all attacks bypass
    assert m.fpr == 0.0  # no benign bypass

def test_optimize_threshold_no_valid_threshold():
    # All scores overlap completely - no threshold can satisfy FPR constraint
    rng = np.random.default_rng(42)
    s = rng.uniform(0.4, 0.6, size=1000)
    y = rng.integers(0, 2, size=1000)

    # Very strict FPR constraint
    m = optimize_threshold_offline(s, y, fpr_max=0.001)
    # Should fallback to most conservative (min score)
    assert m.threshold == s.min()

if __name__ == "__main__":
    test_offline_optim_fpr_constraint()
    print("✓ test_offline_optim_fpr_constraint passed")

    test_safe_ucb_simulation_safe_choice()
    print("✓ test_safe_ucb_simulation_safe_choice passed")

    test_evaluate_threshold_basic()
    print("✓ test_evaluate_threshold_basic passed")

    test_optimize_threshold_no_valid_threshold()
    print("✓ test_optimize_threshold_no_valid_threshold passed")

    print("\nAll safe bandit tests passed!")

