# English-only code
"""GuardNet Prometheus metrics exporter."""

from __future__ import annotations

from typing import Iterable

try:
    from prometheus_client import Counter, Gauge

    _HAS_PROMETHEUS = True
except Exception:  # pragma: no cover
    _HAS_PROMETHEUS = False

    class _Noop:
        def __init__(self, *_, **__):
            pass

        def labels(self, *_, **__):
            return self

        def inc(self, *_, **__):
            pass

        def set(self, *_, **__):
            pass

    # Type stubs for when prometheus_client unavailable
    Counter = _Noop  # type: ignore
    Gauge = _Noop  # type: ignore

_G_INFER = Counter("guardnet_inferences_total", "GuardNet inferences", ["model"])
_G_LOW_COV = Counter(
    "guardnet_low_coverage_total",
    "GuardNet low coverage decisions",
    ["model"],
)
_G_RISK_MEAN = Gauge(
    "guardnet_risk_overall_mean",
    "Mean risk_overall over window",
    ["model"],
)
_G_COV_MEAN = Gauge("guardnet_coverage_mean", "Mean coverage over window", ["model"])
_G_LOW_COV_FRAC = Gauge(
    "guardnet_low_coverage_fraction",
    "Fraction of low-coverage outputs",
    ["model"],
)


class GuardNetMetrics:
    """Prometheus metrics collector for GuardNet inference."""

    def __init__(self, model: str, cov_threshold: float = 0.6):
        """Initialize metrics collector.

        Args:
            model: Model name for labeling
            cov_threshold: Coverage threshold for low-coverage detection
        """
        self.model = model
        self.cov_threshold = cov_threshold

    def observe_batch(self, risks: Iterable[float], coverages: Iterable[float]) -> None:
        """Record batch of inference results.

        Args:
            risks: Risk scores [0,1]
            coverages: Coverage scores [0,1]
        """
        r = list(risks)
        c = list(coverages)
        n = max(1, len(r))
        low = sum(1 for x in c if x < self.cov_threshold)
        _G_INFER.labels(self.model).inc(n)
        _G_LOW_COV.labels(self.model).inc(low)
        _G_RISK_MEAN.labels(self.model).set(sum(r) / n)
        _G_COV_MEAN.labels(self.model).set(sum(c) / n)
        _G_LOW_COV_FRAC.labels(self.model).set(low / n)
