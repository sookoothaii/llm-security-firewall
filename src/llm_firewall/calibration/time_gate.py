"""
Temporal Awareness Gate - Time-sensitive Evidence Validation
Purpose: Detect and penalize stale evidence based on domain-specific TTLs
Creator: Joerg Bollwahn
Date: 2025-10-30

Key Insight: Many hallucinations are temporal - static trust scores miss this.
This gate applies domain-specific TTL and penalties for outdated claims.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Tuple

# ISO-8601 duration parser (subset: PnYnMnD format only)
_ISO_DUR_PATTERN = re.compile(
    r"^P(?:(?P<years>\d+)Y)?(?:(?P<months>\d+)M)?(?:(?P<days>\d+)D)?$"
)


def parse_iso_8601_duration(duration: str) -> Tuple[int, int, int]:
    """
    Parse ISO-8601 duration string (subset: years, months, days only).

    Args:
        duration: ISO-8601 duration string (e.g., "P18M", "P2Y6M", "P365D")

    Returns:
        Tuple of (years, months, days)

    Raises:
        ValueError: If format is invalid

    Examples:
        >>> parse_iso_8601_duration("P18M")
        (0, 18, 0)
        >>> parse_iso_8601_duration("P2Y6M15D")
        (2, 6, 15)
    """
    match = _ISO_DUR_PATTERN.match(duration)
    if not match:
        raise ValueError(f"Invalid ISO-8601 duration format: {duration}")

    years = int(match.group("years") or 0)
    months = int(match.group("months") or 0)
    days = int(match.group("days") or 0)

    return years, months, days


def duration_to_days(years: int, months: int, days: int) -> int:
    """
    Convert duration components to total days.

    Uses Gregorian calendar averages:
    - 1 year = 365.2425 days
    - 1 month = 30.44 days (365.2425 / 12)

    Args:
        years: Number of years
        months: Number of months
        days: Number of days

    Returns:
        Total days (rounded to nearest integer)
    """
    year_days = round(years * 365.2425)
    month_days = round(months * 30.44)
    return year_days + month_days + days


@dataclass(frozen=True)
class TemporalDecision:
    """
    Temporal freshness decision.

    Attributes:
        stale: True if evidence exceeds domain TTL
        risk_uplift: Risk penalty to apply (0.0 if fresh)
        delta_days: Age of evidence in days
        ttl_days: Required TTL for domain
        in_grace_period: True if within grace period
    """

    stale: bool
    risk_uplift: float
    delta_days: int
    ttl_days: int
    in_grace_period: bool = False


class TimeAwarenessGate:
    """
    Domain-aware temporal freshness gate.

    Enforces time-to-live (TTL) requirements per domain and applies
    risk penalties for stale evidence. Supports optional grace period.

    Design Philosophy:
    - Static trust scores miss temporal dimension
    - Medical/policy domains require recent evidence
    - Stale but high-trust sources can still hallucinate

    Example:
        >>> gate = TimeAwarenessGate({"biomed": "P18M"}, stale_penalty=0.25)
        >>> decision = gate.evaluate(claim_time, source_time, "biomed")
        >>> if decision.stale:
        ...     risk_score += decision.risk_uplift
    """

    def __init__(
        self,
        ttl_map: Dict[str, str],
        stale_penalty: float = 0.25,
        grace_period_days: int = 0,
        grace_penalty: float = 0.10,
    ):
        """
        Initialize temporal gate.

        Args:
            ttl_map: Domain -> ISO-8601 duration mapping
            stale_penalty: Risk uplift for stale evidence
            grace_period_days: Grace period after TTL (optional)
            grace_penalty: Reduced penalty within grace period

        Raises:
            ValueError: If TTL is invalid or <= 0 days
        """
        if not 0 <= stale_penalty <= 1:
            raise ValueError("stale_penalty must be in [0,1]")
        if not 0 <= grace_penalty <= 1:
            raise ValueError("grace_penalty must be in [0,1]")
        if grace_period_days < 0:
            raise ValueError("grace_period_days must be >= 0")

        self._ttl_days: Dict[str, int] = {}
        for domain, iso_duration in ttl_map.items():
            years, months, days = parse_iso_8601_duration(iso_duration)
            total_days = duration_to_days(years, months, days)
            if total_days <= 0:
                raise ValueError(f"TTL must be > 0 days for domain '{domain}'")
            self._ttl_days[domain] = total_days

        self.stale_penalty = float(stale_penalty)
        self.grace_period_days = int(grace_period_days)
        self.grace_penalty = float(grace_penalty)

    def ttl_days(self, domain: str) -> int:
        """
        Get required TTL for domain in days.

        Raises:
            KeyError: If domain not configured
        """
        if domain not in self._ttl_days:
            raise KeyError(f"Unknown domain '{domain}' - configure TTL first")
        return self._ttl_days[domain]

    def evaluate(
        self, claim_time: datetime, source_time: datetime, domain: str
    ) -> TemporalDecision:
        """
        Evaluate temporal freshness.

        Args:
            claim_time: When claim is being made
            source_time: When source was created/published
            domain: Domain category (must be configured)

        Returns:
            TemporalDecision with stale flag and risk uplift

        Raises:
            KeyError: If domain not configured
            ValueError: If claim_time < source_time (time travel)
        """
        if claim_time < source_time:
            raise ValueError("claim_time cannot be before source_time")

        ttl = self.ttl_days(domain)
        delta_seconds = (claim_time - source_time).total_seconds()
        delta_days = int(delta_seconds // 86400)

        # Check if stale
        is_stale = delta_days > ttl

        # Apply grace period if configured
        in_grace = False
        if is_stale and self.grace_period_days > 0:
            grace_end = ttl + self.grace_period_days
            if delta_days <= grace_end:
                in_grace = True
                risk_uplift = self.grace_penalty
            else:
                risk_uplift = self.stale_penalty
        else:
            risk_uplift = self.stale_penalty if is_stale else 0.0

        return TemporalDecision(
            stale=is_stale,
            risk_uplift=risk_uplift,
            delta_days=delta_days,
            ttl_days=ttl,
            in_grace_period=in_grace,
        )

    def configured_domains(self) -> list[str]:
        """Return list of configured domains."""
        return list(self._ttl_days.keys())


