# calibration/conformal_online.py
"""
Online, bucketed, exponentially-weighted conformal calibration.

Assumptions:
- Nonconformity scores s in [0, 1] (upstream must normalize).
- Per-bucket histograms with exponential time-decay (gamma).
- Low-traffic fallback to global; ultimate fallback to conservative quantile.
"""

from __future__ import annotations

import bisect
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional, Tuple


@dataclass
class BucketConfig:
    """Configuration for bucketed conformal calibration."""

    alpha: float = 0.1  # target error rate, 1 - coverage
    gamma: float = 0.97  # per-update decay factor (0<gamma<1)
    bins: int = 256  # histogram resolution
    min_weight: float = 200.0  # min effective mass to trust bucket
    conservative_q: float = 0.95  # fallback threshold if not enough data


@dataclass
class _Hist:
    edges: list  # List of float bin edges
    mass: list = field(default_factory=list)
    total: float = 0.0
    last_decay_ts: float = field(default_factory=time.time)

    def __post_init__(self):
        if not self.mass:
            self.mass = [0.0 for _ in self.edges]

    def decay(self, gamma: float, steps: int = 1) -> None:
        """Apply exponential decay to all bins."""
        if gamma >= 1.0:
            return
        g = gamma**steps
        self.mass = [m * g for m in self.mass]
        self.total *= g

    def add(self, x: float, w: float = 1.0) -> None:
        """Add score to histogram with weight."""
        x = 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)
        # right-closed binning: edges are bin-right edges in [0,1], len = B
        idx = bisect.bisect_left(self.edges, x)
        idx = min(max(idx, 0), len(self.mass) - 1)
        self.mass[idx] += w
        self.total += w

    def quantile(self, q: float) -> float:
        """Compute weighted quantile."""
        if self.total <= 0.0:
            return 1.0
        target = q * self.total
        c = 0.0
        for i, m in enumerate(self.mass):
            c += m
            if c >= target:
                # return bin right edge as conservative estimate
                return self.edges[i]
        return 1.0


class OnlineConformalCalibrator:
    """
    Exponentially-weighted, bucketed conformal calibrator.

    API:
      - update(bucket, score) -> None
      - get_threshold(bucket, alpha=None) -> float
      - p_value(bucket, score) -> float   (weighted tail estimate)
      - is_nonconforming(bucket, score, alpha=None) -> bool
    """

    def __init__(self, cfg: Optional[BucketConfig] = None):
        """Initialize calibrator with config."""
        self.cfg = cfg or BucketConfig()
        # right-edges for bins in [0,1]
        self._edges = [(i + 1) / self.cfg.bins for i in range(self.cfg.bins)]
        self._buckets: Dict[str, _Hist] = {}
        self._global: _Hist = _Hist(self._edges)

    # --- internal helpers ---
    def _hist(self, key: str) -> _Hist:
        if key not in self._buckets:
            self._buckets[key] = _Hist(self._edges)
        return self._buckets[key]

    def _decay_all(self) -> None:
        # simple per-update decay (no wall-clock dependency to avoid clock skew)
        for h in self._buckets.values():
            h.decay(self.cfg.gamma, 1)
        self._global.decay(self.cfg.gamma, 1)

    # --- public API ---
    def update(self, bucket: str, score: float, weight: float = 1.0) -> None:
        """Add a nonconformity score to bucket and global with decay."""
        self._decay_all()
        h = self._hist(bucket)
        h.add(score, weight)
        self._global.add(score, weight)

    def get_threshold(self, bucket: str, alpha: Optional[float] = None) -> float:
        """Return q-hat threshold for given bucket at level alpha (upper quantile)."""
        a = self.cfg.alpha if alpha is None else alpha
        a = max(min(a, 0.5), 1e-6)  # sanity
        # we want (1 - alpha) coverage => quantile at q = 1 - alpha
        q = 1.0 - a
        h = self._hist(bucket)
        # choose bucket if enough mass, else global, else conservative
        if h.total >= self.cfg.min_weight:
            return h.quantile(q)
        if self._global.total >= self.cfg.min_weight:
            return self._global.quantile(q)
        return self.cfg.conservative_q

    def p_value(self, bucket: str, score: float) -> float:
        """Weighted p-value = P(S >= score) using histogram tail."""
        h = self._hist(bucket)
        if h.total < self.cfg.min_weight and self._global.total >= self.cfg.min_weight:
            h = self._global
        if h.total <= 0.0:
            return 1.0
        # tail mass at/above score
        idx = bisect.bisect_left(self._edges, min(max(score, 0.0), 1.0))
        tail = sum(h.mass[idx:])
        return tail / max(h.total, 1e-9)

    def is_nonconforming(
        self, bucket: str, score: float, alpha: Optional[float] = None
    ) -> bool:
        """True if score exceeds calibrated threshold (reject at level alpha)."""
        thr = self.get_threshold(bucket, alpha)
        return score > thr

    # convenience: multi-bucket update
    def bulk_update(self, items: Iterable[Tuple[str, float, float]]) -> None:
        """
        items: iterable of (bucket, score, weight)
        """
        for b, s, w in items:
            self.update(b, s, w)
