"""Tests for GuardNet metrics exporter."""

import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))

from llm_firewall.metrics.guardnet_exporter import (  # noqa: E402
    GuardNetMetrics,
)


def test_metrics_no_raise():
    """Test that metrics collection doesn't raise exceptions."""
    m = GuardNetMetrics("test", cov_threshold=0.5)
    # Should not raise and update internal gauges
    m.observe_batch([0.1, 0.9], [0.4, 0.8])


def test_metrics_low_coverage_detection():
    """Test low coverage detection."""
    m = GuardNetMetrics("test", cov_threshold=0.6)
    # 2 out of 4 below threshold
    m.observe_batch([0.1, 0.2, 0.3, 0.4], [0.5, 0.7, 0.4, 0.8])
