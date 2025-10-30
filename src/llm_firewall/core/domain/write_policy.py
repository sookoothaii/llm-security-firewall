"""
Write-Path Policy Engine - Domain Logic
Purpose: Prevent memory poisoning via policy-based write control
Creator: Joerg Bollwahn
Date: 2025-10-30

Pure domain logic - no infrastructure dependencies.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class WriteDecisionType(Enum):
    """Write decision types."""

    ALLOW = "allow"  # Write permitted
    DENY = "deny"  # Write rejected
    QUARANTINE = "quarantine"  # Two-man rule required


class QuarantineReason(Enum):
    """Reasons for quarantine."""

    LOW_TRUST = "low_trust"  # Source trust below threshold
    SHORT_TTL = "short_ttl"  # TTL too short for domain
    CIRCULAR_REF = "circular_ref"  # Circular reference detected
    HIGH_RISK_DOMAIN = "high_risk_domain"  # Domain requires dual approval
    ANOMALOUS_PATTERN = "anomalous_pattern"  # Statistical anomaly


@dataclass(frozen=True)
class WriteDecision:
    """
    Immutable write decision.

    Attributes:
        decision_type: Allow, deny, or quarantine
        reason: Human-readable justification
        quarantine_reason: Specific quarantine reason if applicable
        confidence: Decision confidence [0,1]
        metadata: Additional context
    """

    decision_type: WriteDecisionType
    reason: str
    quarantine_reason: Optional[QuarantineReason] = None
    confidence: float = 1.0
    metadata: Optional[Dict[str, Any]] = None

    def __post_init__(self) -> None:
        """Validate decision."""
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be in [0,1]")
        if (
            self.decision_type == WriteDecisionType.QUARANTINE
            and not self.quarantine_reason
        ):
            raise ValueError("quarantine decisions must have quarantine_reason")


@dataclass
class SourceMetadata:
    """
    Source metadata for write policy evaluation.

    Attributes:
        url: Source URL (None for internal/KB)
        trust: Trust score [0,1]
        domain: Domain category (biomed, policy, tech, etc.)
        created_at: Source creation timestamp
        ttl_expiry: Time-to-live expiry (None = no expiry)
        is_self_authored: True if self-created
        circular_refs: List of circular reference IDs
    """

    url: Optional[str]
    trust: float
    domain: str
    created_at: datetime
    ttl_expiry: Optional[datetime] = None
    is_self_authored: bool = False
    circular_refs: Optional[list[str]] = None

    def __post_init__(self) -> None:
        """Validate metadata."""
        if not 0 <= self.trust <= 1:
            raise ValueError("trust must be in [0,1]")


class WritePathPolicy:
    """
    Write-path policy engine - pure business logic.

    Evaluates write requests against policy rules:
    - Trust thresholds (domain-specific)
    - TTL requirements (time-sensitive domains)
    - Self-authorship prevention (MINJA-style attacks)
    - Circular reference detection
    - High-risk domain gating (BIO, POLICY, SECURITY)
    """

    def __init__(
        self,
        trust_threshold: float = 0.7,
        min_ttl_hours: int = 168,  # 7 days default
        high_risk_domains: Optional[set[str]] = None,
        domain_ttl_overrides: Optional[dict[str, int]] = None,
    ):
        """
        Initialize policy engine.

        Args:
            trust_threshold: Global trust threshold (can be overridden per domain)
            min_ttl_hours: Minimum TTL in hours
            high_risk_domains: Domains requiring two-man rule (BIO, POLICY, SECURITY)
            domain_ttl_overrides: Domain-specific TTL requirements (in hours)
        """
        if not 0 <= trust_threshold <= 1:
            raise ValueError("trust_threshold must be in [0,1]")
        if min_ttl_hours < 0:
            raise ValueError("min_ttl_hours must be >= 0")

        self.trust_threshold = trust_threshold
        self.min_ttl_hours = min_ttl_hours
        self.high_risk_domains = high_risk_domains or {"biomed", "policy", "security"}
        self.domain_ttl_overrides = domain_ttl_overrides or {
            "biomed": 18 * 30 * 24,  # 18 months
            "policy": 6 * 30 * 24,  # 6 months
            "tech": 12 * 30 * 24,  # 12 months
        }

    def evaluate(
        self, source: SourceMetadata, now: Optional[datetime] = None
    ) -> WriteDecision:
        """
        Evaluate write request against policy.

        Args:
            source: Source metadata
            now: Current time (default: UTC now)

        Returns:
            WriteDecision with allow/deny/quarantine
        """
        if now is None:
            now = datetime.now(timezone.utc)

        # Rule 1: Self-authored content always denied (MINJA prevention)
        if source.is_self_authored:
            return WriteDecision(
                decision_type=WriteDecisionType.DENY,
                reason="self-authored content forbidden (MINJA prevention)",
                confidence=1.0,
                metadata={"rule": "self_authored_check"},
            )

        # Rule 2: Circular references trigger quarantine
        if source.circular_refs:
            return WriteDecision(
                decision_type=WriteDecisionType.QUARANTINE,
                reason=(
                    f"circular references detected: {len(source.circular_refs)} cycles"
                ),
                quarantine_reason=QuarantineReason.CIRCULAR_REF,
                confidence=0.9,
                metadata={"rule": "circular_ref_check", "cycles": source.circular_refs},
            )

        # Rule 3: Trust threshold (domain-aware)
        if source.trust < self.trust_threshold:
            return WriteDecision(
                decision_type=WriteDecisionType.QUARANTINE,
                reason=(
                    f"trust {source.trust:.3f} < threshold {self.trust_threshold:.3f}"
                ),
                quarantine_reason=QuarantineReason.LOW_TRUST,
                confidence=0.85,
                metadata={"rule": "trust_check", "trust": source.trust},
            )

        # Rule 4: TTL requirements (domain-specific)
        required_ttl_hours = self.domain_ttl_overrides.get(
            source.domain, self.min_ttl_hours
        )
        if source.ttl_expiry is not None:
            ttl_remaining = (source.ttl_expiry - now).total_seconds() / 3600
            if ttl_remaining < required_ttl_hours:
                return WriteDecision(
                    decision_type=WriteDecisionType.QUARANTINE,
                    reason=(
                        f"TTL {ttl_remaining:.1f}h < required {required_ttl_hours}h "
                        f"for domain {source.domain}"
                    ),
                    quarantine_reason=QuarantineReason.SHORT_TTL,
                    confidence=0.8,
                    metadata={
                        "rule": "ttl_check",
                        "ttl_remaining_hours": ttl_remaining,
                        "required_hours": required_ttl_hours,
                    },
                )

        # Rule 5: High-risk domains require two-man rule
        if source.domain in self.high_risk_domains:
            return WriteDecision(
                decision_type=WriteDecisionType.QUARANTINE,
                reason=f"domain {source.domain} requires dual approval",
                quarantine_reason=QuarantineReason.HIGH_RISK_DOMAIN,
                confidence=1.0,
                metadata={"rule": "high_risk_domain", "domain": source.domain},
            )

        # All checks passed
        return WriteDecision(
            decision_type=WriteDecisionType.ALLOW,
            reason="all policy checks passed",
            confidence=1.0,
            metadata={"trust": source.trust, "domain": source.domain},
        )

    def get_domain_ttl_hours(self, domain: str) -> int:
        """Get required TTL for domain in hours."""
        return self.domain_ttl_overrides.get(domain, self.min_ttl_hours)

    def is_high_risk_domain(self, domain: str) -> bool:
        """Check if domain requires two-man rule."""
        return domain in self.high_risk_domains
