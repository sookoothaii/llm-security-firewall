"""
Tests for Agentic Campaign Detection (RC10).

Based on Anthropic Report (2025) synthetic campaign scenarios.
"""

import pytest
import time

from llm_firewall.detectors.agentic_campaign import AgenticCampaignDetector
from llm_firewall.detectors.tool_killchain import ToolEvent, KillChainPhase


@pytest.fixture
def detector():
    """Create detector instance."""
    return AgenticCampaignDetector()


@pytest.fixture
def benign_events():
    """Benign tool usage: single recon scan."""
    now = time.time()
    return [
        ToolEvent(
            timestamp=now,
            tool="nmap",
            category="net_scan",
            target="192.168.1.1",
            success=True,
        ),
    ]


@pytest.fixture
def malicious_campaign_events():
    """Malicious campaign: full kill-chain progression."""
    now = time.time()
    events = []

    # Phase 1: Reconnaissance
    events.append(ToolEvent(now, "nmap", "net_scan", "corpA.com", True))
    events.append(ToolEvent(now + 10, "masscan", "port_scan", "corpA.com", True))

    # Phase 2: Exploit Development
    events.append(ToolEvent(now + 60, "vuln_scan", "exploit", "corpA.com", True))
    events.append(
        ToolEvent(now + 120, "exploit_framework", "exploit", "corpA.com", True)
    )

    # Phase 3: Lateral Movement
    events.append(ToolEvent(now + 300, "credential_test", "lateral", "corpA.com", True))
    events.append(ToolEvent(now + 360, "ssh_connect", "lateral", "corpA.com", True))

    # Phase 4: Data Collection
    events.append(ToolEvent(now + 600, "db_query", "exfil", "corpA.com", True))
    events.append(ToolEvent(now + 660, "data_export", "exfil", "corpA.com", True))

    # Phase 5: Documentation
    events.append(ToolEvent(now + 900, "generate_report", "doc", "corpA.com", True))

    return events


@pytest.fixture
def multi_target_campaign_events():
    """Multi-target campaign: parallel operations."""
    now = time.time()
    events = []

    # Target 1: corpA.com
    events.append(ToolEvent(now, "nmap", "net_scan", "corpA.com", True))
    events.append(ToolEvent(now + 30, "vuln_scan", "exploit", "corpA.com", True))

    # Target 2: corpB.com (parallel)
    events.append(ToolEvent(now + 10, "nmap", "net_scan", "corpB.com", True))
    events.append(ToolEvent(now + 40, "vuln_scan", "exploit", "corpB.com", True))

    # Target 3: corpC.com (parallel)
    events.append(ToolEvent(now + 20, "nmap", "net_scan", "corpC.com", True))
    events.append(ToolEvent(now + 50, "vuln_scan", "exploit", "corpC.com", True))

    return events


def test_benign_single_recon(detector, benign_events):
    """Benign single recon scan should not trigger campaign detection."""
    report = detector.detect_campaign(
        benign_events,
        session_id="test_benign",
        operator_id="op_benign",
    )

    assert report["combined_risk_score"] < 0.5, "Benign recon should not be flagged"
    assert not report["is_campaign"], "Should not be detected as campaign"
    assert "killchain_campaign_detected" not in report["signals"]


def test_malicious_full_killchain(detector, malicious_campaign_events):
    """Full kill-chain progression should trigger campaign detection."""
    report = detector.detect_campaign(
        malicious_campaign_events,
        session_id="test_malicious",
        operator_id="op_malicious",
    )

    assert report["combined_risk_score"] >= 0.5, "Full kill-chain should be flagged"
    assert report["is_campaign"], "Should be detected as campaign"
    assert (
        report["killchain"]["phase_depth"] >= KillChainPhase.EXPLOIT_DEVELOPMENT.value
    )
    assert "killchain_campaign_detected" in report["signals"]


def test_multi_target_campaign(detector, multi_target_campaign_events):
    """Multi-target campaign should be detected."""
    report = detector.detect_campaign(
        multi_target_campaign_events,
        session_id="test_multi",
        operator_id="op_multi",
    )

    assert report["campaign"]["target_count"] >= 3, "Should track multiple targets"
    assert (
        "multi_target_campaign" in report["signals"]
        or "campaign_multi_exploit" in report["signals"]
    )


def test_operator_budget_exceeded(detector):
    """Operator budget violations should trigger alerts."""
    now = time.time()
    events = []

    # Generate 150 net_scan events (exceeds default limit of 100)
    for i in range(150):
        events.append(
            ToolEvent(
                timestamp=now + i,
                tool="nmap",
                category="net_scan",
                target=f"target_{i % 10}",
                success=True,
            )
        )

    report = detector.detect_campaign(
        events,
        session_id="test_budget",
        operator_id="op_budget",
    )

    assert (
        "operator_budget_exceeded" in report["signals"]
        or report["operator"]["budget_exceeded"]
    ), "Budget should be exceeded"


def test_pretext_signal_boost(detector, benign_events):
    """Security pretext signals should boost risk score."""
    # Without pretext
    report_no_pretext = detector.detect_campaign(
        benign_events,
        session_id="test_no_pretext",
        operator_id="op_no_pretext",
    )

    # With pretext
    report_with_pretext = detector.detect_campaign(
        benign_events,
        session_id="test_pretext",
        operator_id="op_pretext",
        pretext_signals=["security_engineer_roleplay", "legitimate_pentest_claim"],
    )

    assert (
        report_with_pretext["combined_risk_score"]
        > report_no_pretext["combined_risk_score"]
    ), "Pretext should boost risk"
    assert "pretext_security_engineer_roleplay" in report_with_pretext["signals"]


def test_combined_pretext_and_killchain(detector, malicious_campaign_events):
    """Pretext + kill-chain should have very high risk."""
    report = detector.detect_campaign(
        malicious_campaign_events,
        session_id="test_combined",
        operator_id="op_combined",
        pretext_signals=["security_engineer_roleplay", "simulate_attacker_request"],
    )

    assert report["combined_risk_score"] >= 0.7, "Combined should be high risk"
    assert report["pretext_boost"] > 0, "Should have pretext boost"
    assert report["is_campaign"], "Should be detected as campaign"


def test_scan_tool_events_interface(detector, malicious_campaign_events):
    """Test compatibility with existing detector interface."""
    signals = detector.scan_tool_events_for_signals(
        malicious_campaign_events,
        session_id="test_interface",
        operator_id="op_interface",
    )

    assert isinstance(signals, list), "Should return list of signals"
    assert len(signals) > 0, "Should detect signals"
    assert any("killchain" in s for s in signals), "Should include kill-chain signals"
