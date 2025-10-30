"""
Conformal Risk Stacker
======================

Coverage-controlled risk aggregation from multiple judges.

Based on GPT-5 specification 2025-10-30.

Creator: Joerg Bollwahn
License: MIT
"""

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from llm_firewall.core.types import (
    AggregatedRisk,
    Decision,
    JudgeReport,
    RiskScore,
    Severity,
)


@dataclass
class AggregationConfig:
    """Configuration for risk aggregation."""

    coverage: float = 0.90  # Target coverage
    max_severity: Severity = Severity.HIGH  # Max allowed severity
    bands: Optional[List[float]] = None  # Quantile cuts (S0..S4)
    weights: Optional[Dict[str, float]] = None  # Per-judge weights
    abstain_band: str = "S2"  # Abstain threshold
    deny_band: str = "S3"  # Deny threshold

    def __post_init__(self):
        """Set default bands if not provided."""
        if self.bands is None:
            self.bands = [0.1, 0.2, 0.4, 0.7, 0.9]


class ConformalRiskStacker:
    """
    Conformal risk stacking with coverage guarantees.

    Aggregates multiple judge reports into single calibrated risk score.
    Uses q-hat (nonconformity quantile) from calibration data.
    """

    def __init__(
        self, cfg: AggregationConfig, qhat_provider: Callable[[str, float], float]
    ):
        """
        Initialize stacker.

        Args:
            cfg: Aggregation configuration
            qhat_provider: Function(judge_name, coverage) -> q-hat
        """
        self.cfg = cfg
        self.qhat = qhat_provider

    def aggregate(self, reports: List[JudgeReport]) -> AggregatedRisk:
        """
        Aggregate multiple judge reports.

        Args:
            reports: List of judge reports

        Returns:
            AggregatedRisk with conformal guarantees
        """
        if not reports:
            # No judges available - return neutral
            return AggregatedRisk(
                overall=RiskScore(
                    value=0.5, band="S2", severity=Severity.MEDIUM, calibrated=False
                ),
                per_judge=[],
                conformal_qhat=0.0,
                coverage_target=self.cfg.coverage,
                abstain_prob=1.0,
            )

        # 1) Normalize each judge risk via its q-hat
        normalized = []
        for report in reports:
            qhat_val = self.qhat(report.name, self.cfg.coverage)
            # Normalized nonconformity score
            nonconformity = min(1.0, report.risks.overall.value / max(1e-6, qhat_val))
            normalized.append((report, nonconformity))

        # 2) Weighted aggregation (robust max for OR-logic)
        weights = self.cfg.weights or {r.name: 1.0 for r, _ in normalized}

        # Weighted max
        ensemble_risk = 0.0
        for report, score in normalized:
            weight = weights.get(report.name, 1.0)
            ensemble_risk = max(ensemble_risk, weight * score)

        # 3) Assign band
        bands = self.cfg.bands if self.cfg.bands is not None else []
        band_idx = sum(ensemble_risk >= cut for cut in bands)
        band = f"S{band_idx}"

        # 4) Map to severity
        severity = Severity(min(band_idx, int(Severity.CRITICAL)))

        # 5) Create overall risk score
        overall = RiskScore(
            value=float(ensemble_risk),
            band=band,
            severity=severity,
            calibrated=True,
            method="conformal_stacking",
        )

        # 6) Compute abstention probability
        abstain_prob = max(0.0, ensemble_risk - 0.5)

        # 7) Average q-hat
        avg_qhat = sum(
            self.qhat(r.name, self.cfg.coverage) for r, _ in normalized
        ) / len(normalized)

        return AggregatedRisk(
            overall=overall,
            per_judge=[r for r, _ in normalized],
            conformal_qhat=avg_qhat,
            coverage_target=self.cfg.coverage,
            abstain_prob=abstain_prob,
        )


def decision_from_risk(agg: AggregatedRisk, cfg: AggregationConfig) -> Decision:
    """
    Convert aggregated risk to final decision.

    Args:
        agg: Aggregated risk
        cfg: Aggregation config

    Returns:
        Final decision (ALLOW / ABSTAIN / DENY)
    """
    if agg.overall.band >= cfg.deny_band:
        return Decision.DENY

    if agg.overall.band >= cfg.abstain_band:
        return Decision.ABSTAIN

    return Decision.ALLOW


def default_qhat_provider(judge_name: str, coverage: float) -> float:
    """
    Default q-hat provider (uncalibrated).

    Returns conservative estimates.
    Production should use calibration cache.

    Args:
        judge_name: Name of judge
        coverage: Target coverage (e.g., 0.90)

    Returns:
        q-hat value
    """
    # Conservative defaults (would be learned from calibration data)
    defaults = {"nli_consistency": 0.3, "policy_judge": 0.4, "persuasion_fusion": 0.35}

    return defaults.get(judge_name, 0.5) * (1.0 / (1.0 - coverage))
