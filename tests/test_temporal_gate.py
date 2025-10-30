"""
Tests for Temporal Awareness Gate
Creator: Joerg Bollwahn
Date: 2025-10-30
"""

from datetime import datetime, timedelta, timezone

import pytest

from src.llm_firewall.calibration.time_gate import (
    TimeAwarenessGate,
    duration_to_days,
    parse_iso_8601_duration,
)


class TestIsoDurationParsing:
    """Test ISO-8601 duration parsing."""

    def test_parse_months_only(self):
        """Parse months-only duration."""
        y, m, d = parse_iso_8601_duration("P18M")
        assert (y, m, d) == (0, 18, 0)

    def test_parse_years_and_months(self):
        """Parse years + months."""
        y, m, d = parse_iso_8601_duration("P2Y6M")
        assert (y, m, d) == (2, 6, 0)

    def test_parse_all_components(self):
        """Parse years + months + days."""
        y, m, d = parse_iso_8601_duration("P2Y6M15D")
        assert (y, m, d) == (2, 6, 15)

    def test_parse_days_only(self):
        """Parse days-only."""
        y, m, d = parse_iso_8601_duration("P365D")
        assert (y, m, d) == (0, 0, 365)

    def test_parse_invalid_format_raises(self):
        """Invalid format should raise."""
        with pytest.raises(ValueError, match="Invalid ISO-8601"):
            parse_iso_8601_duration("invalid")

        with pytest.raises(ValueError):
            parse_iso_8601_duration("18M")  # Missing 'P' prefix


class TestDurationToDays:
    """Test duration conversion to days."""

    def test_years_to_days(self):
        """1 year ≈ 365.2425 days."""
        days = duration_to_days(1, 0, 0)
        assert 365 <= days <= 366

    def test_months_to_days(self):
        """18 months ≈ 548 days."""
        days = duration_to_days(0, 18, 0)
        assert 540 <= days <= 550

    def test_combined_duration(self):
        """2 years + 6 months + 15 days."""
        days = duration_to_days(2, 6, 15)
        expected = 2 * 365.2425 + 6 * 30.44 + 15
        assert abs(days - expected) < 2  # Allow rounding


class TestTimeAwarenessGate:
    """Test TimeAwarenessGate evaluation."""

    def test_initialization_with_valid_ttl(self):
        """Valid TTL map should initialize."""
        gate = TimeAwarenessGate({"tech": "P12M", "biomed": "P18M"}, stale_penalty=0.25)
        assert gate.ttl_days("tech") > 0
        assert gate.ttl_days("biomed") > gate.ttl_days("tech")

    def test_initialization_with_invalid_ttl_raises(self):
        """Invalid TTL should raise."""
        with pytest.raises(ValueError):
            TimeAwarenessGate({"invalid": "P0D"})  # Zero days

    def test_stale_evidence_with_penalty(self):
        """Stale evidence should get penalty."""
        gate = TimeAwarenessGate({"tech": "P12M"}, stale_penalty=0.25)

        claim_time = datetime(2025, 10, 1, tzinfo=timezone.utc)
        source_time = datetime(2024, 9, 1, tzinfo=timezone.utc)  # 13 months old

        decision = gate.evaluate(claim_time, source_time, "tech")
        assert decision.stale is True
        assert decision.risk_uplift == 0.25
        assert decision.delta_days > decision.ttl_days

    def test_fresh_evidence_no_penalty(self):
        """Fresh evidence should have zero penalty."""
        gate = TimeAwarenessGate({"biomed": "P18M"}, stale_penalty=0.25)

        claim_time = datetime(2025, 10, 1, tzinfo=timezone.utc)
        source_time = datetime(2024, 6, 1, tzinfo=timezone.utc)  # 16 months fresh

        decision = gate.evaluate(claim_time, source_time, "biomed")
        assert decision.stale is False
        assert decision.risk_uplift == 0.0

    def test_grace_period_applies(self):
        """Grace period should apply reduced penalty."""
        gate = TimeAwarenessGate(
            {"tech": "P12M"},
            stale_penalty=0.25,
            grace_period_days=30,
            grace_penalty=0.10,
        )

        claim_time = datetime(2025, 10, 1, tzinfo=timezone.utc)
        # 13 months - stale but within grace period
        source_time = datetime(2024, 9, 1, tzinfo=timezone.utc)

        decision = gate.evaluate(claim_time, source_time, "tech")
        assert decision.stale is True
        assert decision.in_grace_period is True
        assert decision.risk_uplift == 0.10  # Grace penalty

    def test_unknown_domain_raises(self):
        """Unknown domain should raise KeyError."""
        gate = TimeAwarenessGate({"tech": "P12M"})

        claim_time = datetime.now(timezone.utc)
        source_time = claim_time - timedelta(days=100)

        with pytest.raises(KeyError, match="Unknown domain"):
            gate.evaluate(claim_time, source_time, "unknown_domain")

    def test_time_travel_raises(self):
        """claim_time < source_time should raise."""
        gate = TimeAwarenessGate({"tech": "P12M"})

        claim_time = datetime(2025, 1, 1, tzinfo=timezone.utc)
        source_time = datetime(2025, 12, 1, tzinfo=timezone.utc)  # Future

        with pytest.raises(ValueError, match="cannot be before"):
            gate.evaluate(claim_time, source_time, "tech")

    def test_configured_domains(self):
        """Test configured_domains method."""
        gate = TimeAwarenessGate({"tech": "P12M", "biomed": "P18M", "policy": "P6M"})
        domains = gate.configured_domains()
        assert set(domains) == {"tech", "biomed", "policy"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
