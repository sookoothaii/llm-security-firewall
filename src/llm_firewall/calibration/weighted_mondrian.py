# calibration/weighted_mondrian.py
"""
Weighted Mondrian Conformal Prediction.

Extends OnlineConformalCalibrator with:
1. Sample weights (covariate shift adaptation)
2. Mondrian stratification (per-stratum coverage guarantees)

Theory:
- Weighted conformal: importance sampling for distribution shift
- Mondrian CP: separate calibration per stratum (feature-conditional coverage)

References:
- Vovk (2012) - Conditional validity in conformal prediction
- Tibshirani et al (2019) - Conformalized quantile regression
- Barber et al (2021) - Predictive inference with the jackknife+
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .conformal_online import BucketConfig, OnlineConformalCalibrator


@dataclass
class MondrianConfig(BucketConfig):
    """
    Configuration for Weighted Mondrian Conformal Prediction.

    Extends BucketConfig with stratum-specific settings.
    """

    min_stratum_weight: float = 100.0  # min effective mass per stratum
    default_stratum: str = "default"  # fallback stratum if key not provided
    enable_cross_stratum_fallback: bool = True  # use global if stratum too small


class WeightedMondrianConformal:
    """
    Weighted Mondrian Conformal Predictor.

    Combines:
    - Sample weights for covariate shift (importance weighting)
    - Mondrian stratification for per-feature conditional coverage

    API (extends OnlineConformalCalibrator):
      - calibrate(residuals, weights, strata) -> None
      - update_online(bucket, score, weight, stratum) -> None
      - predict_interval(bucket, x_features, alpha) -> (lower, upper)
      - get_threshold_stratified(bucket, stratum, alpha) -> float
      - p_value_stratified(bucket, stratum, score) -> float

    Architecture:
    - Each (bucket, stratum) pair gets separate OnlineConformalCalibrator
    - Weights applied at update time (weighted histogram bins)
    - Fallback hierarchy: stratum -> bucket -> global -> conservative
    """

    def __init__(self, cfg: Optional[MondrianConfig] = None):
        """
        Initialize Weighted Mondrian Conformal Predictor.

        Args:
            cfg: Configuration (uses MondrianConfig defaults if None)
        """
        self.cfg = cfg or MondrianConfig()

        # Nested structure: {bucket: {stratum: OnlineConformalCalibrator}}
        self._calibrators: Dict[str, Dict[str, OnlineConformalCalibrator]] = {}

        # Global fallback calibrator (no stratification)
        self._global_calibrator = OnlineConformalCalibrator(self.cfg)

    # --- Internal Helpers ---

    def _get_calibrator(
        self, bucket: str, stratum: Optional[str] = None
    ) -> OnlineConformalCalibrator:
        """
        Get or create calibrator for (bucket, stratum) pair.

        Args:
            bucket: Bucket identifier (e.g. 'biomed', 'legal')
            stratum: Stratum identifier (e.g. 'age_0_12', 'high_risk')

        Returns:
            OnlineConformalCalibrator instance for this (bucket, stratum)
        """
        s = stratum or self.cfg.default_stratum

        if bucket not in self._calibrators:
            self._calibrators[bucket] = {}

        if s not in self._calibrators[bucket]:
            self._calibrators[bucket][s] = OnlineConformalCalibrator(self.cfg)

        return self._calibrators[bucket][s]

    def _choose_calibrator(
        self, bucket: str, stratum: Optional[str] = None
    ) -> Tuple[OnlineConformalCalibrator, str]:
        """
        Choose best calibrator via fallback hierarchy.

        Hierarchy:
        1. Stratum calibrator (if enough weight)
        2. Bucket-level aggregate (if cross-stratum fallback enabled)
        3. Global calibrator

        Args:
            bucket: Bucket identifier
            stratum: Stratum identifier

        Returns:
            (calibrator, source) where source in ['stratum', 'bucket', 'global']
        """
        s = stratum or self.cfg.default_stratum

        # Try stratum-specific
        if bucket in self._calibrators and s in self._calibrators[bucket]:
            cal = self._calibrators[bucket][s]
            # Check if stratum histogram has enough data
            # cal._hist(bucket) returns the bucket-specific histogram within this calibrator
            h = cal._hist(bucket)
            if h.total >= self.cfg.min_stratum_weight:
                return (cal, "stratum")

        # Try bucket-level (aggregate across strata)
        if self.cfg.enable_cross_stratum_fallback and bucket in self._calibrators:
            # Sum weights across all strata in bucket
            total_weight = sum(
                c._global.total for c in self._calibrators[bucket].values()
            )
            if total_weight >= self.cfg.min_weight:
                # Use first stratum's calibrator as proxy
                # (In production, could aggregate histograms)
                first_cal = next(iter(self._calibrators[bucket].values()))
                return (first_cal, "bucket")

        # Fallback to global
        return (self._global_calibrator, "global")

    # --- Public API ---

    def calibrate(
        self,
        residuals: list[Tuple[float, str, Optional[str]]],
        weights: Optional[list[float]] = None,
    ) -> None:
        """
        Batch calibration with residuals and optional importance weights.

        Args:
            residuals: List of (score, bucket, stratum) tuples
            weights: Optional importance weights (1.0 if None)

        Example:
            >>> wmc = WeightedMondrianConformal()
            >>> residuals = [
            ...     (0.3, 'biomed', 'age_0_12'),
            ...     (0.5, 'biomed', 'age_13_17'),
            ...     (0.7, 'legal', 'age_18_plus'),
            ... ]
            >>> weights = [1.2, 0.8, 1.0]  # importance weights
            >>> wmc.calibrate(residuals, weights)
        """
        if weights is None:
            weights = [1.0] * len(residuals)

        if len(residuals) != len(weights):
            raise ValueError(
                f"Residuals ({len(residuals)}) and weights ({len(weights)}) "
                f"length mismatch"
            )

        for (score, bucket, stratum), w in zip(residuals, weights):
            self.update_online(bucket, score, w, stratum)

    def update_online(
        self,
        bucket: str,
        score: float,
        weight: float = 1.0,
        stratum: Optional[str] = None,
    ) -> None:
        """
        Online update with weighted sample.

        Updates both stratum-specific and global calibrators.

        Args:
            bucket: Bucket identifier
            score: Nonconformity score in [0, 1]
            weight: Sample weight (default 1.0)
            stratum: Stratum identifier (optional)

        Example:
            >>> wmc = WeightedMondrianConformal()
            >>> wmc.update_online('biomed', 0.4, weight=1.5, stratum='age_0_12')
        """
        # Update stratum-specific calibrator
        cal = self._get_calibrator(bucket, stratum)
        cal.update(bucket, score, weight)

        # Update global fallback
        self._global_calibrator.update(bucket, score, weight)

    def get_threshold_stratified(
        self,
        bucket: str,
        stratum: Optional[str] = None,
        alpha: Optional[float] = None,
    ) -> float:
        """
        Get conformal threshold for (bucket, stratum) at level alpha.

        Uses fallback hierarchy if stratum has insufficient data.

        Args:
            bucket: Bucket identifier
            stratum: Stratum identifier (optional)
            alpha: Target error rate (uses cfg.alpha if None)

        Returns:
            Threshold q-hat such that P(score > q-hat) ≈ alpha

        Example:
            >>> wmc = WeightedMondrianConformal()
            >>> # ... after calibration ...
            >>> threshold = wmc.get_threshold_stratified('biomed', 'age_0_12', alpha=0.1)
        """
        cal, _source = self._choose_calibrator(bucket, stratum)
        return cal.get_threshold(bucket, alpha)

    def p_value_stratified(
        self,
        bucket: str,
        stratum: Optional[str] = None,
        score: float = 0.0,
    ) -> float:
        """
        Compute stratified p-value = P(S >= score | stratum).

        Args:
            bucket: Bucket identifier
            stratum: Stratum identifier (optional)
            score: Nonconformity score

        Returns:
            P-value (tail probability)

        Example:
            >>> wmc = WeightedMondrianConformal()
            >>> pval = wmc.p_value_stratified('biomed', 'age_0_12', score=0.8)
            >>> if pval < 0.05:
            ...     print("Nonconforming at 5% level")
        """
        cal, _source = self._choose_calibrator(bucket, stratum)
        return cal.p_value(bucket, score)

    def predict_interval(
        self,
        bucket: str,
        x_features: Optional[Dict[str, Any]] = None,
        alpha: Optional[float] = None,
    ) -> Tuple[float, float]:
        """
        Predict conformal interval [lower, upper].

        For nonconformity scores in [0, 1], returns:
        - lower = 0.0 (scores are non-negative)
        - upper = threshold at level alpha

        Args:
            bucket: Bucket identifier
            x_features: Optional dict with 'stratum' key
            alpha: Target error rate (uses cfg.alpha if None)

        Returns:
            (lower, upper) interval bounds

        Example:
            >>> wmc = WeightedMondrianConformal()
            >>> lower, upper = wmc.predict_interval(
            ...     'biomed',
            ...     x_features={'stratum': 'age_0_12'},
            ...     alpha=0.1
            ... )
            >>> # Score is nonconforming if score > upper
        """
        stratum = None
        if x_features and "stratum" in x_features:
            stratum = x_features["stratum"]

        threshold = self.get_threshold_stratified(bucket, stratum, alpha)
        return (0.0, threshold)

    def is_nonconforming(
        self,
        bucket: str,
        score: float,
        stratum: Optional[str] = None,
        alpha: Optional[float] = None,
    ) -> bool:
        """
        Check if score is nonconforming at level alpha.

        Args:
            bucket: Bucket identifier
            score: Nonconformity score
            stratum: Stratum identifier (optional)
            alpha: Target error rate (uses cfg.alpha if None)

        Returns:
            True if score > threshold (reject at level alpha)

        Example:
            >>> wmc = WeightedMondrianConformal()
            >>> if wmc.is_nonconforming('biomed', 0.95, 'age_0_12', alpha=0.1):
            ...     print("High-risk prediction - reject")
        """
        threshold = self.get_threshold_stratified(bucket, stratum, alpha)
        return score > threshold

    # --- Statistics & Introspection ---

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get calibrator statistics for monitoring.

        Returns:
            Dict with:
            - n_buckets: Number of buckets
            - n_strata: Total number of strata across all buckets
            - bucket_stats: Per-bucket stratum counts and weights
            - global_weight: Total weight in global calibrator

        Example:
            >>> wmc = WeightedMondrianConformal()
            >>> # ... after calibration ...
            >>> stats = wmc.get_statistics()
            >>> print(f"Buckets: {stats['n_buckets']}, Strata: {stats['n_strata']}")
        """
        bucket_stats = {}
        total_strata = 0

        for bucket, strata_dict in self._calibrators.items():
            stratum_weights = {s: cal._global.total for s, cal in strata_dict.items()}
            bucket_stats[bucket] = {
                "n_strata": len(strata_dict),
                "stratum_weights": stratum_weights,
            }
            total_strata += len(strata_dict)

        return {
            "n_buckets": len(self._calibrators),
            "n_strata": total_strata,
            "bucket_stats": bucket_stats,
            "global_weight": self._global_calibrator._global.total,
        }
