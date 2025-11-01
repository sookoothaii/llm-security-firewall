"""
Input Ensemble with Conformal Risk Stacking
============================================

Replaces simple majority voting with calibrated risk aggregation.

Problem: 2/3 majority voting collapses when detectors are correlated.
Solution: Per-detector q-hat calibration + weighted max aggregation.

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from llm_firewall.aggregate.conformal_stacker import (
    AggregationConfig,
    ConformalRiskStacker,
)
from llm_firewall.calibration.conformal_online import (
    BucketConfig,
    OnlineConformalCalibrator,
)
from llm_firewall.core.types import JudgeReport, RiskScore, Severity, TaxonomyRisk
from llm_firewall.metrics.registry import NONCONF_UPDATES, QHAT_CURRENT


@dataclass
class InputDetectorResult:
    """Result from a single input detector."""

    detector_name: str
    is_threat: bool
    confidence: float
    risk_score: float
    category: Optional[str] = None
    reason: Optional[str] = None


class InputEnsembleConformal:
    """
    Conformal ensemble for input detectors.

    Treats each detector (Safety, Embedding, Perplexity) as a "judge"
    and aggregates via Conformal Risk Stacking.
    """

    def __init__(self, qhat_provider, config: Optional[AggregationConfig] = None):
        """
        Initialize conformal input ensemble.

        Args:
            qhat_provider: Function(detector_name, coverage) -> q-hat
            config: Aggregation config (default: coverage=0.90)
        """
        self.config = config or AggregationConfig(
            coverage=0.90,
            bands=[0.1, 0.2, 0.4, 0.7, 0.9],
            abstain_band="S2",
            deny_band="S3",
            weights={
                "safety_validator": 1.0,
                "embedding_detector": 0.8,
                "perplexity_detector": 0.7,
            },
        )

        self.stacker = ConformalRiskStacker(self.config, qhat_provider)

    def aggregate(
        self, results: List[InputDetectorResult]
    ) -> Tuple[bool, str, RiskScore]:
        """
        Aggregate input detector results.

        Args:
            results: Results from individual detectors

        Returns:
            (is_safe, reason, aggregated_risk)
        """
        # Convert detector results to JudgeReports
        judge_reports: List[JudgeReport] = []

        for result in results:
            # Map detector result to judge report
            severity = Severity.HIGH if result.is_threat else Severity.NONE

            overall_risk = RiskScore(
                value=result.risk_score,
                band="unknown",  # Will be assigned by stacker
                severity=severity,
                calibrated=False,
                method=result.detector_name,
            )

            categories = {}
            if result.category:
                categories[result.category] = overall_risk

            report = JudgeReport(
                name=result.detector_name,
                version="1.0",
                latency_ms=0.0,  # Already measured externally
                risks=TaxonomyRisk(categories=categories, overall=overall_risk),
                notes=result.reason,
            )

            judge_reports.append(report)

        # Aggregate via conformal stacker
        agg = self.stacker.aggregate(judge_reports)

        # Determine if safe
        is_safe = agg.overall.band < self.config.deny_band

        # Build reason string
        threat_detectors = [
            r.name for r in judge_reports if r.risks.overall.severity >= Severity.MEDIUM
        ]

        if threat_detectors:
            reason = f"Conformal ensemble: Risk {agg.overall.value:.3f} (band {agg.overall.band}). Detectors flagged: {', '.join(threat_detectors)}"
        else:
            reason = f"Conformal ensemble: Safe (risk {agg.overall.value:.3f}, band {agg.overall.band})"

        return is_safe, reason, agg.overall


def input_qhat_provider(detector_name: str, coverage: float) -> float:
    """
    Q-hat provider for input detectors.

    Conservative defaults - should be learned from calibration data.

    Args:
        detector_name: Name of detector
        coverage: Target coverage (e.g., 0.90)

    Returns:
        q-hat value
    """
    # Default q-hat values per detector
    defaults = {
        "safety_validator": 0.25,  # Pattern-based, conservative
        "embedding_detector": 0.35,  # Semantic, more variable
        "perplexity_detector": 0.40,  # Statistical, most variable
    }

    base = defaults.get(detector_name, 0.5)

    # Scale by coverage (higher coverage = higher q-hat)
    scaled = base * (1.0 / (1.0 - coverage))

    return scaled


# --- Simple Online-Conformal Wrapper (alternative to full ConformalRiskStacker) ---


@dataclass
class DetectorScores:
    """Simple detector scores for lightweight ensemble."""

    safety: Optional[float] = None
    embed: Optional[float] = None
    pplx: Optional[float] = None


class InputEnsemble:
    """
    Weighted-max aggregator with online, bucketed conformal thresholds.
    Assumes detector scores are nonconformity scores in [0,1].

    Alternative to InputEnsembleConformal for simpler use cases.
    """

    def __init__(
        self,
        weights: Dict[str, float],
        threshold: float = 0.75,  # used only as last-resort fallback
        bucket_cfg: Optional[BucketConfig] = None,
    ):
        """Initialize simple ensemble with online conformal calibration."""
        self.w = weights
        self.threshold = threshold
        self.cal = OnlineConformalCalibrator(bucket_cfg or BucketConfig())

    def _aggregate(self, s: DetectorScores) -> float:
        vals = []
        if s.safety is not None:
            vals.append(self.w.get("safety", 1.0) * s.safety)
        if s.embed is not None:
            vals.append(self.w.get("embed", 1.0) * s.embed)
        if s.pplx is not None:
            vals.append(self.w.get("pplx", 1.0) * s.pplx)
        return max(vals) if vals else 0.0

    def _bucket_key(self, domain: str, locale: str, tenant: str, model: str) -> str:
        domain = (domain or "other").lower()
        locale = (locale or "und").lower()
        tenant = (tenant or "single").lower()
        model = (model or "unknown").lower()
        return f"{domain}|{locale}|{tenant}|{model}"

    def decide(
        self,
        scores: DetectorScores,
        *,
        domain: str = "other",
        locale: str = "en",
        tenant: str = "single",
        model: str = "unknown",
        alpha: Optional[float] = None,
    ) -> Tuple[float, str, float]:
        """
        Make decision using online-calibrated threshold.

        Returns:
            (risk, label, qhat_used)
        """
        risk = self._aggregate(scores)
        bucket = self._bucket_key(domain, locale, tenant, model)
        qhat = self.cal.get_threshold(bucket, alpha=alpha)
        QHAT_CURRENT.labels(bucket=bucket).set(qhat)
        label = "BLOCK" if risk > qhat else "SAFE"
        return risk, label, qhat

    def update_online(
        self,
        bucket_items: Iterable[Tuple[str, float, float]],
    ) -> None:
        """
        Shadow-mode training signal.

        Args:
            bucket_items: iterable of (bucket_key, score_in_[0,1], weight)
        """
        for b, s, w in bucket_items:
            self.cal.update(b, s, weight=w)
            NONCONF_UPDATES.labels(bucket=b).inc()
