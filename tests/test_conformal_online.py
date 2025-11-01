"""Tests for online conformal calibration."""

import pathlib
import random
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.calibration.conformal_online import (  # noqa: E402
    BucketConfig,
    OnlineConformalCalibrator,
)


def test_threshold_fallbacks_and_decay():
    """Test threshold fallback logic and decay mechanism."""
    cfg = BucketConfig(
        alpha=0.1, gamma=0.9, bins=64, min_weight=50.0, conservative_q=0.95
    )
    oc = OnlineConformalCalibrator(cfg)

    # low traffic -> conservative
    thr0 = oc.get_threshold("biomed")
    assert 0.94 <= thr0 <= 1.0, f"Conservative threshold should be ~0.95, got {thr0}"

    # feed global only
    for _ in range(60):
        oc.update("global", random.uniform(0.0, 0.8))
    thrg = oc.get_threshold("biomed")
    assert 0.1 <= thrg <= 0.95, f"Global fallback should work, got {thrg}"

    # now fill bucket with higher scores -> higher threshold
    for _ in range(200):
        oc.update("biomed", random.uniform(0.3, 0.9))
    thrb = oc.get_threshold("biomed")
    assert thrb >= thrg, f"Bucket threshold {thrb} should be >= global {thrg}"


def test_pvalue_and_reject():
    """Test p-value calculation and rejection logic."""
    oc = OnlineConformalCalibrator(
        BucketConfig(alpha=0.1, gamma=0.97, bins=128, min_weight=20.0)
    )
    for _ in range(100):
        oc.update("security", 0.2)
        oc.update("security", 0.4)
        oc.update("security", 0.6)
    # typical threshold near upper tail
    thr = oc.get_threshold("security", alpha=0.1)
    assert 0.4 <= thr <= 0.7, f"Threshold should be mid-range, got {thr}"
    assert not oc.is_nonconforming("security", 0.3, 0.1)
    assert oc.is_nonconforming("security", 0.95, 0.1)
    # p-value is tail prob => small for large score
    assert oc.p_value("security", 0.95) < 0.2


def test_bulk_update():
    """Test bulk update convenience method."""
    oc = OnlineConformalCalibrator()
    items = [
        ("bucket_a", 0.3, 1.0),
        ("bucket_a", 0.5, 1.0),
        ("bucket_b", 0.7, 1.0),
    ]
    oc.bulk_update(items)
    # Should not raise and buckets should have data
    assert oc._hist("bucket_a").total > 0
    assert oc._hist("bucket_b").total > 0
