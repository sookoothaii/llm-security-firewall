"""
Tests for Write-Path Policy Engine
Creator: Joerg Bollwahn
Date: 2025-10-30
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.llm_firewall.core.domain.write_policy import (
    QuarantineReason,
    SourceMetadata,
    WriteDecision,
    WriteDecisionType,
    WritePathPolicy,
)


class TestSourceMetadata:
    """Test SourceMetadata validation."""

    def test_valid_metadata(self):
        """Valid metadata should not raise."""
        meta = SourceMetadata(
            url="https://example.com",
            trust=0.8,
            domain="tech",
            created_at=datetime.now(timezone.utc),
        )
        assert meta.trust == 0.8
        assert meta.domain == "tech"

    def test_trust_out_of_range(self):
        """Trust outside [0,1] should raise."""
        with pytest.raises(ValueError, match="trust must be in"):
            SourceMetadata(
                url=None,
                trust=1.5,
                domain="tech",
                created_at=datetime.now(timezone.utc),
            )

        with pytest.raises(ValueError, match="trust must be in"):
            SourceMetadata(
                url=None,
                trust=-0.1,
                domain="tech",
                created_at=datetime.now(timezone.utc),
            )


class TestWriteDecision:
    """Test WriteDecision validation."""

    def test_valid_allow_decision(self):
        """Valid allow decision."""
        decision = WriteDecision(
            decision_type=WriteDecisionType.ALLOW,
            reason="all checks passed",
            confidence=1.0,
        )
        assert decision.decision_type == WriteDecisionType.ALLOW
        assert decision.quarantine_reason is None

    def test_valid_quarantine_decision(self):
        """Valid quarantine decision with reason."""
        decision = WriteDecision(
            decision_type=WriteDecisionType.QUARANTINE,
            reason="low trust",
            quarantine_reason=QuarantineReason.LOW_TRUST,
            confidence=0.85,
        )
        assert decision.decision_type == WriteDecisionType.QUARANTINE
        assert decision.quarantine_reason == QuarantineReason.LOW_TRUST

    def test_quarantine_without_reason_raises(self):
        """Quarantine decision without reason should raise."""
        with pytest.raises(ValueError, match="quarantine decisions must have"):
            WriteDecision(
                decision_type=WriteDecisionType.QUARANTINE,
                reason="low trust",
                # Missing quarantine_reason
            )

    def test_confidence_out_of_range(self):
        """Confidence outside [0,1] should raise."""
        with pytest.raises(ValueError, match="confidence must be in"):
            WriteDecision(
                decision_type=WriteDecisionType.ALLOW, reason="test", confidence=1.5
            )


class TestWritePathPolicy:
    """Test WritePathPolicy evaluation."""

    def test_initialization_defaults(self):
        """Test default initialization."""
        policy = WritePathPolicy()
        assert policy.trust_threshold == 0.7
        assert policy.min_ttl_hours == 168
        assert "biomed" in policy.high_risk_domains
        assert policy.domain_ttl_overrides["biomed"] == 18 * 30 * 24

    def test_initialization_custom(self):
        """Test custom initialization."""
        policy = WritePathPolicy(
            trust_threshold=0.85,
            min_ttl_hours=100,
            high_risk_domains={"custom_domain"},
            domain_ttl_overrides={"custom": 200},
        )
        assert policy.trust_threshold == 0.85
        assert policy.min_ttl_hours == 100
        assert "custom_domain" in policy.high_risk_domains

    def test_self_authored_denied(self):
        """Self-authored content should be denied."""
        policy = WritePathPolicy()
        source = SourceMetadata(
            url=None,
            trust=1.0,
            domain="tech",
            created_at=datetime.now(timezone.utc),
            is_self_authored=True,
        )

        decision = policy.evaluate(source)
        assert decision.decision_type == WriteDecisionType.DENY
        assert "self-authored" in decision.reason.lower()
        assert decision.confidence == 1.0

    def test_circular_ref_quarantine(self):
        """Circular references should trigger quarantine."""
        policy = WritePathPolicy()
        source = SourceMetadata(
            url="https://example.com",
            trust=0.9,
            domain="tech",
            created_at=datetime.now(timezone.utc),
            circular_refs=["ref1", "ref2"],
        )

        decision = policy.evaluate(source)
        assert decision.decision_type == WriteDecisionType.QUARANTINE
        assert decision.quarantine_reason == QuarantineReason.CIRCULAR_REF
        assert "circular" in decision.reason.lower()

    def test_low_trust_quarantine(self):
        """Low trust should trigger quarantine."""
        policy = WritePathPolicy(trust_threshold=0.7)
        source = SourceMetadata(
            url="https://example.com",
            trust=0.5,  # Below threshold
            domain="tech",
            created_at=datetime.now(timezone.utc),
        )

        decision = policy.evaluate(source)
        assert decision.decision_type == WriteDecisionType.QUARANTINE
        assert decision.quarantine_reason == QuarantineReason.LOW_TRUST
        assert "trust" in decision.reason.lower()

    def test_short_ttl_quarantine(self):
        """Short TTL should trigger quarantine."""
        policy = WritePathPolicy(min_ttl_hours=168)  # 7 days
        now = datetime.now(timezone.utc)
        source = SourceMetadata(
            url="https://example.com",
            trust=0.9,
            domain="tech",
            created_at=now,
            ttl_expiry=now + timedelta(hours=24),  # Only 1 day - too short
        )

        decision = policy.evaluate(source, now=now)
        assert decision.decision_type == WriteDecisionType.QUARANTINE
        assert decision.quarantine_reason == QuarantineReason.SHORT_TTL
        assert "ttl" in decision.reason.lower()

    def test_domain_specific_ttl(self):
        """Domain-specific TTL requirements."""
        policy = WritePathPolicy()
        now = datetime.now(timezone.utc)

        # Biomed requires 18 months
        source_biomed = SourceMetadata(
            url="https://example.com",
            trust=0.9,
            domain="biomed",
            created_at=now,
            ttl_expiry=now + timedelta(days=365),  # 1 year - too short for biomed
        )

        decision = policy.evaluate(source_biomed, now=now)
        assert decision.decision_type == WriteDecisionType.QUARANTINE
        assert decision.quarantine_reason == QuarantineReason.SHORT_TTL

        # Tech requires 12 months (1 year should pass)
        source_tech = SourceMetadata(
            url="https://example.com",
            trust=0.9,
            domain="tech",
            created_at=now,
            ttl_expiry=now + timedelta(days=365),  # 1 year
        )

        decision_tech = policy.evaluate(source_tech, now=now)
        assert decision_tech.decision_type == WriteDecisionType.ALLOW

    def test_high_risk_domain_quarantine(self):
        """High-risk domains should require two-man rule."""
        policy = WritePathPolicy()
        source = SourceMetadata(
            url="https://example.com",
            trust=0.95,
            domain="biomed",  # High-risk domain
            created_at=datetime.now(timezone.utc),
        )

        decision = policy.evaluate(source)
        assert decision.decision_type == WriteDecisionType.QUARANTINE
        assert decision.quarantine_reason == QuarantineReason.HIGH_RISK_DOMAIN
        assert "dual approval" in decision.reason.lower()

    def test_all_checks_pass_allow(self):
        """Source passing all checks should be allowed."""
        policy = WritePathPolicy()
        now = datetime.now(timezone.utc)
        source = SourceMetadata(
            url="https://example.com",
            trust=0.9,
            domain="general",  # Not high-risk
            created_at=now,
            ttl_expiry=now + timedelta(days=365),  # Sufficient TTL
            is_self_authored=False,
            circular_refs=None,
        )

        decision = policy.evaluate(source, now=now)
        assert decision.decision_type == WriteDecisionType.ALLOW
        assert "passed" in decision.reason.lower()
        assert decision.confidence == 1.0

    def test_get_domain_ttl_hours(self):
        """Test domain TTL lookup."""
        policy = WritePathPolicy()
        assert policy.get_domain_ttl_hours("biomed") == 18 * 30 * 24
        assert policy.get_domain_ttl_hours("tech") == 12 * 30 * 24
        assert policy.get_domain_ttl_hours("unknown") == 168  # Default

    def test_is_high_risk_domain(self):
        """Test high-risk domain check."""
        policy = WritePathPolicy()
        assert policy.is_high_risk_domain("biomed")
        assert policy.is_high_risk_domain("policy")
        assert policy.is_high_risk_domain("security")
        assert not policy.is_high_risk_domain("tech")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
