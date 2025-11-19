"""Tests for Weighted Mondrian Conformal Prediction."""

import pathlib
import random
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.calibration.weighted_mondrian import (  # noqa: E402
    MondrianConfig,
    WeightedMondrianConformal,
)


def test_weighted_calibration():
    """Test weighted calibration with importance weights."""
    cfg = MondrianConfig(
        alpha=0.1, gamma=0.99, bins=64, min_weight=15.0, min_stratum_weight=15.0
    )
    wmc = WeightedMondrianConformal(cfg)

    # Calibrate with weighted samples
    residuals = [
        (0.2, "biomed", "age_0_12"),
        (0.4, "biomed", "age_0_12"),
        (0.6, "biomed", "age_0_12"),
    ] * 50  # 150 samples

    # Different importance weights
    weights = [1.5, 1.0, 0.5] * 50

    wmc.calibrate(residuals, weights)

    # Check threshold is computed
    threshold = wmc.get_threshold_stratified("biomed", "age_0_12", alpha=0.1)
    assert 0.0 <= threshold <= 1.0, f"Threshold should be in [0,1], got {threshold}"

    # Higher-weighted samples should influence threshold more
    # Since we upweight low scores (0.2 -> 1.5), threshold should be lower
    assert 0.3 <= threshold <= 0.7, f"Expected threshold ~0.4-0.6, got {threshold}"


def test_mondrian_stratification():
    """Test per-stratum coverage with Mondrian stratification."""
    wmc = WeightedMondrianConformal(
        MondrianConfig(alpha=0.1, gamma=0.97, bins=128, min_weight=30.0, min_stratum_weight=30.0)
    )

    # Two strata with different score distributions
    for _ in range(100):
        # Stratum A: low scores
        wmc.update_online("security", random.uniform(0.1, 0.4), 1.0, "stratum_a")
        # Stratum B: high scores
        wmc.update_online("security", random.uniform(0.6, 0.9), 1.0, "stratum_b")

    # Thresholds should differ by stratum
    thr_a = wmc.get_threshold_stratified("security", "stratum_a", alpha=0.1)
    thr_b = wmc.get_threshold_stratified("security", "stratum_b", alpha=0.1)

    assert thr_a < thr_b, f"Stratum A threshold {thr_a} should be < B {thr_b}"
    assert 0.2 <= thr_a <= 0.5, f"Stratum A threshold out of range: {thr_a}"
    assert 0.7 <= thr_b <= 1.0, f"Stratum B threshold out of range: {thr_b}"


def test_online_update():
    """Test online update mechanism with decay."""
    cfg = MondrianConfig(alpha=0.1, gamma=0.99, bins=64, min_weight=15.0, min_stratum_weight=10.0)
    wmc = WeightedMondrianConformal(cfg)

    # Initial calibration
    for _ in range(80):
        wmc.update_online("finance", 0.3, 1.0, "low_risk")

    thr_before = wmc.get_threshold_stratified("finance", "low_risk", alpha=0.1)

    # Feed high scores -> threshold should increase
    for _ in range(150):
        wmc.update_online("finance", 0.8, 1.0, "low_risk")

    thr_after = wmc.get_threshold_stratified("finance", "low_risk", alpha=0.1)

    assert thr_after > thr_before, (
        f"Threshold should increase after high scores: "
        f"{thr_before} -> {thr_after}"
    )


def test_coverage_guarantee():
    """Test empirical coverage approximates target alpha."""
    wmc = WeightedMondrianConformal(
        MondrianConfig(alpha=0.1, gamma=0.98, bins=256, min_weight=100.0, min_stratum_weight=100.0)
    )

    # Calibration set
    n_cal = 500
    for _ in range(n_cal):
        score = random.betavariate(2, 5)  # skewed distribution
        wmc.update_online("medical", score, 1.0, "general")

    # Test set
    threshold = wmc.get_threshold_stratified("medical", "general", alpha=0.1)
    n_test = 1000
    n_nonconforming = 0

    for _ in range(n_test):
        score = random.betavariate(2, 5)
        if wmc.is_nonconforming("medical", score, "general", alpha=0.1):
            n_nonconforming += 1

    empirical_error = n_nonconforming / n_test

    # Allow wide tolerance for binomial variance + decay effects
    # Conformal prediction with decay can be conservative (lower empirical error)
    # Target: 0.0 <= empirical_error <= 0.15 (conservative OK for safety)
    assert 0.0 <= empirical_error <= 0.15, (
        f"Empirical error {empirical_error:.3f} should be <= 0.15 (target 0.1, conservative OK)"
    )


def test_covariate_shift_adaptation():
    """Test adaptation to covariate shift via importance weighting."""
    wmc = WeightedMondrianConformal(
        MondrianConfig(alpha=0.1, gamma=0.99, bins=128, min_weight=20.0, min_stratum_weight=20.0)
    )

    # Calibration: train distribution (low scores)
    for _ in range(120):
        score = random.uniform(0.1, 0.5)
        wmc.update_online("nlp", score, weight=1.0, stratum="train_dist")

    thr_unweighted = wmc.get_threshold_stratified("nlp", "train_dist", alpha=0.1)

    # Now adapt to test distribution (high scores) via importance weights
    # Simulate density ratio: p_test / p_train ~ 2.0 for high scores
    for _ in range(120):
        score = random.uniform(0.5, 0.9)
        # Importance weight = p_test(x) / p_train(x) ~ 2.0
        wmc.update_online("nlp", score, weight=2.0, stratum="test_dist")

    thr_weighted = wmc.get_threshold_stratified("nlp", "test_dist", alpha=0.1)

    # Weighted threshold should be higher (adapted to test distribution)
    assert thr_weighted > thr_unweighted, (
        f"Weighted threshold {thr_weighted} should be > unweighted {thr_unweighted}"
    )
    assert thr_weighted >= 0.6, (
        f"Adapted threshold should reflect high-score distribution: {thr_weighted}"
    )


def test_integration_with_base():
    """Test integration with base OnlineConformalCalibrator API."""
    cfg = MondrianConfig(
        alpha=0.15, gamma=0.97, bins=64, min_weight=30.0, min_stratum_weight=20.0
    )
    wmc = WeightedMondrianConformal(cfg)

    # Batch calibration
    residuals = [
        (random.uniform(0.0, 1.0), "bucket_a", "stratum_1")
        for _ in range(50)
    ]
    wmc.calibrate(residuals)

    # Online updates
    for _ in range(50):
        wmc.update_online(
            "bucket_b", random.uniform(0.0, 1.0), weight=1.0, stratum="stratum_2"
        )

    # Get thresholds
    thr_a1 = wmc.get_threshold_stratified("bucket_a", "stratum_1")
    thr_b2 = wmc.get_threshold_stratified("bucket_b", "stratum_2")

    assert 0.0 <= thr_a1 <= 1.0
    assert 0.0 <= thr_b2 <= 1.0

    # P-values
    pval_a = wmc.p_value_stratified("bucket_a", "stratum_1", score=0.95)
    pval_b = wmc.p_value_stratified("bucket_b", "stratum_2", score=0.05)

    assert 0.0 <= pval_a <= 1.0
    assert 0.0 <= pval_b <= 1.0

    # Predict intervals
    lower, upper = wmc.predict_interval(
        "bucket_a", x_features={"stratum": "stratum_1"}, alpha=0.15
    )
    assert lower == 0.0  # scores are non-negative
    assert 0.0 <= upper <= 1.0

    # Statistics
    stats = wmc.get_statistics()
    assert stats["n_buckets"] >= 2
    assert stats["n_strata"] >= 2
    assert "bucket_a" in stats["bucket_stats"]
    assert "bucket_b" in stats["bucket_stats"]


def test_fallback_hierarchy():
    """Test fallback from stratum -> bucket -> global."""
    cfg = MondrianConfig(
        alpha=0.1,
        gamma=0.97,
        bins=64,
        min_weight=60.0,
        min_stratum_weight=40.0,
        enable_cross_stratum_fallback=True,
    )
    wmc = WeightedMondrianConformal(cfg)

    # Empty stratum -> should use global fallback (conservative)
    thr_empty = wmc.get_threshold_stratified("new_bucket", "new_stratum", alpha=0.1)
    assert thr_empty >= 0.9, f"Empty stratum should use conservative: {thr_empty}"

    # Feed global data (enough for global calibrator)
    for _ in range(200):
        wmc.update_online("new_bucket", random.uniform(0.2, 0.6), 1.0, "stratum_x")

    # Different stratum has NO data -> should fallback to global
    thr_fallback = wmc.get_threshold_stratified("new_bucket", "stratum_y", alpha=0.1)
    # Should use global (from stratum_x) or conservative
    assert 0.2 <= thr_fallback <= 1.0, f"Should use fallback (global or conservative): {thr_fallback}"

    # Feed enough data to stratum
    for _ in range(150):
        wmc.update_online("new_bucket", random.uniform(0.7, 0.9), 1.0, "stratum_y")

    # Now stratum should be used
    thr_stratum = wmc.get_threshold_stratified("new_bucket", "stratum_y", alpha=0.1)
    assert thr_stratum > 0.7, f"Stratum with enough data should be used: {thr_stratum}"


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])

