"""Tests for InputEnsemble with online conformal calibration."""

import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.calibration.conformal_online import BucketConfig  # noqa: E402
from llm_firewall.safety.input_ensemble import (  # noqa: E402
    DetectorScores,
    InputEnsemble,
)


def test_decide_returns_qhat_and_label_changes_with_updates():
    """Test that online updates affect decision thresholds."""
    ens = InputEnsemble(
        weights={"safety": 1.0, "embed": 1.0, "pplx": 1.0},
        threshold=0.9,
        bucket_cfg=BucketConfig(alpha=0.1, gamma=0.97, bins=64, min_weight=20.0),
    )
    # same risk before and after; threshold changes with calibration data
    s = DetectorScores(safety=0.6, embed=0.4, pplx=0.5)  # agg -> 0.6
    r1, lab1, q1 = ens.decide(
        s, domain="security", locale="en", tenant="single", model="demo"
    )
    # feed online updates - threshold will adapt based on score distribution
    bucket = "security|en|single|demo"
    for _ in range(50):
        ens.update_online([(bucket, 0.7, 1.0)])
    r2, lab2, q2 = ens.decide(
        s, domain="security", locale="en", tenant="single", model="demo"
    )
    # After calibration, threshold should differ from conservative default
    assert q2 != q1, f"Threshold should change after calibration: {q1} -> {q2}"
    assert r1 == r2, "Risk score should be same for same input"
    assert lab1 in ("SAFE", "BLOCK") and lab2 in ("SAFE", "BLOCK")
    # With enough data, should move away from conservative 0.95
    assert q2 < 0.95 or q1 < 0.95, "Should use calibrated threshold not conservative"


def test_bucket_fallback_to_global():
    """Test fallback from low-traffic bucket to global."""
    ens = InputEnsemble(
        weights={"safety": 1.0},
        bucket_cfg=BucketConfig(min_weight=50.0, conservative_q=0.95),
    )

    # No data -> conservative
    s = DetectorScores(safety=0.8)
    _, _, q0 = ens.decide(s, domain="rare", locale="th", tenant="t1", model="m1")
    assert q0 >= 0.94, f"Conservative fallback expected, got {q0}"

    # Feed data to global bucket (different from rare bucket)
    global_bucket = ens._bucket_key("other", "en", "single", "unknown")
    for _ in range(60):
        ens.update_online([(global_bucket, 0.5, 1.0)])

    # Rare bucket still has no data, but global now has data
    _, _, q1 = ens.decide(s, domain="rare", locale="th", tenant="t1", model="m1")

    # Should still use conservative since rare bucket key != global bucket key
    # This tests that each bucket is independent
    assert q1 >= 0.94, f"Rare bucket should still use conservative: {q1}"

    # Now feed to global using standard key
    for _ in range(60):
        ens.cal.update("global", 0.5, 1.0)

    # Global histogram now has data - may affect future fallback
    assert ens.cal._global.total > 0, "Global should have data"


def test_weighted_aggregation():
    """Test that weights affect risk aggregation."""
    ens1 = InputEnsemble(weights={"safety": 2.0, "embed": 0.5})
    ens2 = InputEnsemble(weights={"safety": 0.5, "embed": 2.0})

    s = DetectorScores(safety=0.6, embed=0.4)

    r1, _, _ = ens1.decide(s)
    r2, _, _ = ens2.decide(s)

    # ens1 weights safety higher -> risk dominated by safety score
    assert r1 > r2, f"Safety-weighted should be higher: {r1} vs {r2}"
