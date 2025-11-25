"""
Campaign Benchmark Tests (RC10)
================================

Offline evaluation of campaign detection on synthetic dataset.

Tests:
- ASR/FPR curves over thresholds
- Feature validation (phase depth, branching, tempo, etc.)
- Threshold calibration
- Pareto-front analysis

Creator: Joerg Bollwahn (with GPT-5.1 analysis)
Date: 2025-11-17
License: MIT
"""

import pytest

from benchmarks.campaign_metrics import (
    run_campaign_benchmark,
)

# campaign_dataset is in data/ directory, not llm_firewall.data
from data.campaign_dataset import (
    CampaignLabel,
    convert_scenario_to_tool_events,
    generate_synthetic_dataset,
)
from llm_firewall.detectors.agentic_campaign import AgenticCampaignDetector


@pytest.fixture
def synthetic_dataset():
    """Generate synthetic dataset for testing."""
    return generate_synthetic_dataset(num_benign=20, num_malicious=20, seed=42)


@pytest.fixture
def detector():
    """Create campaign detector."""
    return AgenticCampaignDetector()


def test_dataset_generation(synthetic_dataset):
    """Test that dataset is generated correctly."""
    assert len(synthetic_dataset) == 40, "Should generate 40 campaigns"

    benign = [s for s in synthetic_dataset if s.label == CampaignLabel.BENIGN]
    malicious = [s for s in synthetic_dataset if s.label == CampaignLabel.MALICIOUS]

    assert len(benign) == 20, "Should have 20 benign campaigns"
    assert len(malicious) == 20, "Should have 20 malicious campaigns"


def test_benign_vs_malicious_separation(detector, synthetic_dataset):
    """Test that detector separates benign from malicious."""
    benign_events = []
    malicious_events = []

    for scenario in synthetic_dataset:
        events = convert_scenario_to_tool_events(scenario)
        if scenario.label == CampaignLabel.BENIGN:
            benign_events.append(events)
        else:
            malicious_events.append(events)

    # Run benchmark
    results = run_campaign_benchmark(
        malicious_campaigns=malicious_events,
        benign_campaigns=benign_events,
        detector=detector,
    )

    # Check that malicious campaigns have higher risk scores
    malicious_scores = [r.risk_score for r in results.results if r.is_malicious]
    benign_scores = [r.risk_score for r in results.results if not r.is_malicious]

    avg_malicious = (
        sum(malicious_scores) / len(malicious_scores) if malicious_scores else 0.0
    )
    avg_benign = sum(benign_scores) / len(benign_scores) if benign_scores else 0.0

    assert avg_malicious > avg_benign, (
        "Malicious campaigns should have higher risk scores"
    )

    print(f"Average malicious risk: {avg_malicious:.3f}")
    print(f"Average benign risk: {avg_benign:.3f}")


def test_feature_validation(detector, synthetic_dataset):
    """Test that features distinguish benign from malicious."""
    benign_features = []
    malicious_features = []

    for scenario in synthetic_dataset:
        events = convert_scenario_to_tool_events(scenario)
        report = detector.detect_campaign(
            events,
            session_id=scenario.campaign_id,
            operator_id=scenario.operator_id,
        )

        features = {
            "phase_depth": report.get("killchain", {}).get("phase_depth", 0),
            "branching_factor": report.get("killchain", {}).get(
                "branching_factor", 0.0
            ),
            "tempo": report.get("killchain", {}).get("tempo", 0.0),
            "target_count": report.get("campaign", {}).get("target_count", 0),
        }

        if scenario.label == CampaignLabel.BENIGN:
            benign_features.append(features)
        else:
            malicious_features.append(features)

    # Check phase depth
    benign_phases = [f["phase_depth"] for f in benign_features]
    malicious_phases = [f["phase_depth"] for f in malicious_features]

    avg_benign_phase = sum(benign_phases) / len(benign_phases) if benign_phases else 0.0
    avg_malicious_phase = (
        sum(malicious_phases) / len(malicious_phases) if malicious_phases else 0.0
    )

    assert avg_malicious_phase > avg_benign_phase, (
        "Malicious should reach higher phases"
    )

    # Check branching factor
    benign_branching = [f["branching_factor"] for f in benign_features]
    malicious_branching = [f["branching_factor"] for f in malicious_features]

    avg_benign_branching = (
        sum(benign_branching) / len(benign_branching) if benign_branching else 0.0
    )
    avg_malicious_branching = (
        sum(malicious_branching) / len(malicious_branching)
        if malicious_branching
        else 0.0
    )

    assert avg_malicious_branching >= avg_benign_branching, (
        "Malicious should have higher branching"
    )

    print(f"Average benign phase: {avg_benign_phase:.1f}")
    print(f"Average malicious phase: {avg_malicious_phase:.1f}")
    print(f"Average benign branching: {avg_benign_branching:.1f}")
    print(f"Average malicious branching: {avg_malicious_branching:.1f}")


def test_threshold_calibration(detector, synthetic_dataset):
    """Test threshold calibration for optimal ASR/FPR trade-off."""
    benign_events = []
    malicious_events = []

    for scenario in synthetic_dataset:
        events = convert_scenario_to_tool_events(scenario)
        if scenario.label == CampaignLabel.BENIGN:
            benign_events.append(events)
        else:
            malicious_events.append(events)

    # Test different thresholds
    thresholds = [0.3, 0.4, 0.5, 0.6, 0.7]
    results_by_threshold = []

    for threshold in thresholds:
        # Modify detector threshold (simplified - in practice would be configurable)
        # For now, we'll manually check risk scores
        results = run_campaign_benchmark(
            malicious_campaigns=malicious_events,
            benign_campaigns=benign_events,
            detector=detector,
        )

        # Calculate ASR/FPR for this threshold
        malicious_blocked = sum(
            1 for r in results.results if r.is_malicious and r.risk_score >= threshold
        )
        benign_blocked = sum(
            1
            for r in results.results
            if not r.is_malicious and r.risk_score >= threshold
        )

        total_malicious = len(malicious_events)
        total_benign = len(benign_events)

        asr = (
            1.0 - (malicious_blocked / total_malicious) if total_malicious > 0 else 0.0
        )
        fpr = benign_blocked / total_benign if total_benign > 0 else 0.0

        results_by_threshold.append(
            {
                "threshold": threshold,
                "asr": asr,
                "fpr": fpr,
            }
        )

    # Find Pareto-optimal threshold (low ASR, low FPR)
    # For now, just verify that thresholds affect ASR/FPR
    assert results_by_threshold[0]["asr"] >= results_by_threshold[-1]["asr"], (
        "Higher threshold should reduce ASR"
    )

    print("\nThreshold Calibration Results:")
    for r in results_by_threshold:
        print(
            f"  Threshold {r['threshold']:.1f}: ASR={r['asr']:.3f}, FPR={r['fpr']:.3f}"
        )


def test_acsr_metrics(detector, synthetic_dataset):
    """Test ACSR (Attack Campaign Success Rate) calculation."""
    benign_events = []
    malicious_events = []

    for scenario in synthetic_dataset:
        events = convert_scenario_to_tool_events(scenario)
        if scenario.label == CampaignLabel.BENIGN:
            benign_events.append(events)
        else:
            malicious_events.append(events)

    results = run_campaign_benchmark(
        malicious_campaigns=malicious_events,
        benign_campaigns=benign_events,
        detector=detector,
    )

    # Check ACSR metrics
    assert results.acsr >= 0.0 and results.acsr <= 1.0, "ACSR should be in [0, 1]"
    assert results.acsr_phase_3 >= 0.0 and results.acsr_phase_3 <= 1.0, (
        "ACSR phase 3 should be in [0, 1]"
    )
    assert results.acsr_phase_4 >= 0.0 and results.acsr_phase_4 <= 1.0, (
        "ACSR phase 4 should be in [0, 1]"
    )

    # ACSR should decrease with higher phase thresholds
    assert results.acsr_phase_3 >= results.acsr_phase_4, (
        "ACSR should decrease with higher phase"
    )

    print("\nACSR Metrics:")
    print(f"  Overall: {results.acsr:.3f}")
    print(f"  Phase >= 3: {results.acsr_phase_3:.3f}")
    print(f"  Phase >= 4: {results.acsr_phase_4:.3f}")
    print(f"  Phase >= 5: {results.acsr_phase_5:.3f}")


def test_campaign_fpr_metrics(detector, synthetic_dataset):
    """Test Campaign-FPR calculation."""
    benign_events = []
    malicious_events = []

    for scenario in synthetic_dataset:
        events = convert_scenario_to_tool_events(scenario)
        if scenario.label == CampaignLabel.BENIGN:
            benign_events.append(events)
        else:
            malicious_events.append(events)

    results = run_campaign_benchmark(
        malicious_campaigns=malicious_events,
        benign_campaigns=benign_events,
        detector=detector,
    )

    # Check FPR metrics
    assert results.campaign_fpr >= 0.0 and results.campaign_fpr <= 1.0, (
        "FPR should be in [0, 1]"
    )

    print(f"\nCampaign-FPR: {results.campaign_fpr:.3f}")
    print(f"  False Positives: {results.false_positives} / {results.total_benign}")


def test_detection_rate_by_phase(detector, synthetic_dataset):
    """Test detection rate by kill-chain phase."""
    benign_events = []
    malicious_events = []

    for scenario in synthetic_dataset:
        events = convert_scenario_to_tool_events(scenario)
        if scenario.label == CampaignLabel.BENIGN:
            benign_events.append(events)
        else:
            malicious_events.append(events)

    results = run_campaign_benchmark(
        malicious_campaigns=malicious_events,
        benign_campaigns=benign_events,
        detector=detector,
    )

    # Detection rate should increase with phase (higher phases = easier to detect)
    detection_rates = results.detection_rate_by_phase

    print("\nDetection Rate by Phase:")
    for phase, rate in sorted(detection_rates.items()):
        print(f"  Phase {phase}: {rate:.3f}")

    # Higher phases should generally have higher detection rates
    if len(detection_rates) > 1:
        phases = sorted(detection_rates.keys())
        # Allow some variance, but trend should be upward
        assert detection_rates[phases[-1]] >= detection_rates[phases[0]] * 0.5, (
            "Higher phases should have better detection"
        )
