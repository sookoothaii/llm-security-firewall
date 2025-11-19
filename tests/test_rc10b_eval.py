"""
Unit Tests for RC10b Extended Evaluation Framework
===================================================

Tests for metric computation functions and boundary dataset loading.

Creator: Joerg Bollwahn
Date: 2025-11-18
License: MIT
"""

import json
import math
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

import pytest

# Add project root to path
script_path = Path(__file__).resolve()
project_root = script_path.parent.parent
sys.path.insert(0, str(project_root / "src"))
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "data"))
sys.path.insert(0, str(project_root / "scripts"))

from campaign_dataset import CampaignLabel, CampaignScenario, Difficulty
from llm_firewall.detectors.agentic_campaign import AgenticCampaignDetector, CampaignDetectorConfig

# Import from scripts directory
from rc10b_ablation_studies_extended import (
    compute_calibration_metrics,
    compute_detection_delay_stats,
    compute_margin_analysis,
    load_boundary_dataset,
    run_extended_ablation_study,
)
from rc10b_validate import CampaignEvalResult, evaluate_campaign_rc10b


def make_eval_result(
    campaign_id: str,
    label: str,
    difficulty: Difficulty,
    risk_max: float,
    blocked: bool,
    delay_events_soft=None,
    delay_events_hard=None,
    delay_time_soft=None,
    delay_time_hard=None,
    require_approval: bool = False,
    detected_soft: bool = False,
    detected_hard: bool = False,
) -> CampaignEvalResult:
    """Helper to construct a minimal CampaignEvalResult."""
    return CampaignEvalResult(
        campaign_id=campaign_id,
        label=label,
        difficulty=difficulty,
        scenario_type="test_scenario",
        risk_max=risk_max,
        blocked=blocked,
        require_approval=require_approval,
        detected_soft=detected_soft,
        detected_hard=detected_hard,
        delay_events_soft=delay_events_soft,
        delay_events_hard=delay_events_hard,
        delay_time_soft=delay_time_soft,
        delay_time_hard=delay_time_hard,
    )


class DummyEval:
    """Minimal object to mimic CampaignEvalResult for calibration tests."""
    
    def __init__(self, risk_max: float, label: str):
        self.risk_max = risk_max
        self.label = label
        # Die restlichen Felder werden von compute_calibration_metrics nicht genutzt
        self.difficulty = Difficulty.BASELINE
        self.campaign_id = "dummy"
        self.scenario_type = "test"
        self.blocked = False
        self.require_approval = False
        self.delay_events_soft = None
        self.delay_events_hard = None
        self.delay_time_soft = None
        self.delay_time_hard = None


def make_minimal_scenarios() -> List[CampaignScenario]:
    """Erzeuge ein kleines Satz von 3 CampaignScenario-Objekten."""
    scenarios = []
    
    # Baseline benign
    scenarios.append(CampaignScenario(
        campaign_id="b1",
        label=CampaignLabel.BENIGN,
        operator_id="test_operator",
        description="Test benign campaign",
        events=[
            {"t": 1000.0, "source": "tool", "tool": "read_file", "category": "read", "target": "config.yaml", "meta": {}},
        ],
        difficulty=Difficulty.BASELINE,
        scenario_type="baseline_benign",
        scope="internal",
        authorized=True,
    ))
    
    # Baseline malicious
    scenarios.append(CampaignScenario(
        campaign_id="m1",
        label=CampaignLabel.MALICIOUS,
        operator_id="test_operator",
        description="Test malicious campaign",
        events=[
            {"t": 1000.0, "source": "tool", "tool": "nmap", "category": "recon", "target": "target.com", "meta": {}},
            {"t": 1100.0, "source": "tool", "tool": "exploit_scan", "category": "exploit", "target": "target.com", "meta": {}},
        ],
        difficulty=Difficulty.BASELINE,
        scenario_type="baseline_malicious",
        scope="external",
        authorized=False,
    ))
    
    # HARD_FN
    scenarios.append(CampaignScenario(
        campaign_id="fn1",
        label=CampaignLabel.MALICIOUS,
        operator_id="test_operator",
        description="Test HARD_FN campaign",
        events=[
            {"t": 1000.0, "source": "tool", "tool": "nmap", "category": "recon", "target": "target.com", "meta": {}},
        ],
        difficulty=Difficulty.HARD_FN,
        scenario_type="hard_fn",
        scope="internal",
        authorized=False,
    ))
    
    return scenarios


# ---------------------------------------------------------------------------
# compute_margin_analysis
# ---------------------------------------------------------------------------

def test_compute_margin_analysis_basic():
    """Test basic margin analysis with mixed margins."""
    t_hard = 0.55
    
    results = [
        make_eval_result(
            campaign_id="c1",
            label="malicious",
            difficulty=Difficulty.HARD_FN,
            risk_max=0.60,  # margin +0.05
            blocked=True,
        ),
        make_eval_result(
            campaign_id="c2",
            label="malicious",
            difficulty=Difficulty.HARD_FN,
            risk_max=0.40,  # margin -0.15
            blocked=False,
        ),
    ]
    
    baseline_decisions: Dict[str, bool] = {
        "c1": True,
        "c2": True,  # früher blockiert, jetzt nicht -> 1 Flip
    }
    
    margins = compute_margin_analysis(
        results=results,
        baseline_decisions=baseline_decisions,
        t_hard=t_hard,
    )
    
    assert "hard_fn" in margins
    ma = margins["hard_fn"]
    
    # Mittelwert der Margins: (0.05 - 0.15) / 2 = -0.05
    assert pytest.approx(ma.mean_margin, rel=1e-6) == -0.05
    assert ma.n_above_threshold == 1
    assert ma.n_below_threshold == 1
    assert ma.decision_flip_count == 1


def test_compute_margin_analysis_empty():
    """Test margin analysis with empty results."""
    t_hard = 0.55
    
    margin_analyses = compute_margin_analysis(
        results=[],
        baseline_decisions=None,
        t_hard=t_hard,
    )
    
    assert len(margin_analyses) == 0


# ---------------------------------------------------------------------------
# compute_detection_delay_stats
# ---------------------------------------------------------------------------

def test_compute_detection_delay_stats_basic():
    """Test detection delay statistics with normal numbers."""
    results = [
        make_eval_result(
            "c1",
            "malicious",
            Difficulty.HARD_FN,
            risk_max=0.8,
            blocked=True,
            delay_events_soft=2,
            delay_events_hard=5,
            delay_time_soft=10.0,
            delay_time_hard=25.0,
        ),
        make_eval_result(
            "c2",
            "malicious",
            Difficulty.HARD_FN,
            risk_max=0.9,
            blocked=True,
            delay_events_soft=3,
            delay_events_hard=7,
            delay_time_soft=20.0,
            delay_time_hard=35.0,
        ),
        make_eval_result(
            "c3",
            "malicious",
            Difficulty.HARD_FN,
            risk_max=0.95,
            blocked=True,
            delay_events_soft=4,
            delay_events_hard=9,
            delay_time_soft=30.0,
            delay_time_hard=45.0,
        ),
    ]
    
    stats = compute_detection_delay_stats(results)
    
    assert "hard_fn" in stats
    ds = stats["hard_fn"]
    
    assert ds.mean_events_hard == pytest.approx((5 + 7 + 9) / 3)
    assert ds.median_events_hard == 7
    assert ds.mean_events_soft == pytest.approx((2 + 3 + 4) / 3)
    assert ds.median_events_soft == 3
    assert ds.mean_time_hard == pytest.approx((25.0 + 35.0 + 45.0) / 3.0)
    assert ds.mean_time_soft == pytest.approx((10.0 + 20.0 + 30.0) / 3.0)


def test_compute_detection_delay_stats_empty():
    """Test detection delay stats with empty results."""
    delay_stats = compute_detection_delay_stats([])
    
    assert len(delay_stats) == 0


# ---------------------------------------------------------------------------
# compute_calibration_metrics
# ---------------------------------------------------------------------------

def test_compute_calibration_metrics_perfect():
    """Test calibration metrics with perfectly calibrated data."""
    results = [
        DummyEval(0.0, "benign"),
        DummyEval(0.0, "benign"),
        DummyEval(1.0, "malicious"),
        DummyEval(1.0, "malicious"),
    ]
    
    calib = compute_calibration_metrics(results, n_bins=4)
    
    assert calib.ece == pytest.approx(0.0, abs=1e-6)
    assert calib.brier == pytest.approx(0.0, abs=1e-6)


def test_compute_calibration_metrics_simple_case():
    """Test calibration metrics with simple case."""
    results = [
        DummyEval(0.25, "benign"),
        DummyEval(0.75, "malicious"),
    ]
    
    calib = compute_calibration_metrics(results, n_bins=2)
    
    # Brier sollte 0.0625 sein
    # (0.25 - 0)^2 = 0.0625, (0.75 - 1)^2 = 0.0625
    # Mean = (0.0625 + 0.0625) / 2 = 0.0625
    assert calib.brier == pytest.approx(0.0625, abs=1e-6)
    
    # ECE hängt von der genauen Bin-Zuordnung ab
    # Bei 2 Bins [0,0.5) und [0.5,1] erwarten wir ECE > 0
    assert calib.ece >= 0.0


def test_compute_calibration_metrics_empty():
    """Test calibration metrics with empty results."""
    calibration = compute_calibration_metrics([], n_bins=10)
    
    assert calibration.ece == 0.0
    assert math.isnan(calibration.brier)
    assert calibration.reliability_data['n_bins'] == 10
    assert len(calibration.reliability_data['bins']) == 0


# ---------------------------------------------------------------------------
# load_boundary_dataset
# ---------------------------------------------------------------------------

def test_load_boundary_dataset_valid():
    """Test loading a valid boundary dataset."""
    # Create temporary JSONL file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False, encoding='utf-8') as f:
        # Write valid JSONL entries
        entries = [
            {
                "campaign_id": "boundary_test_1",
                "label": "malicious",
                "operator_id": "test",
                "description": "Test boundary campaign",
                "events": [
                    {"t": 1000.0, "source": "tool", "tool": "nmap", "category": "recon", "target": "target.com", "meta": {}}
                ],
                "difficulty": "hard_fn",
                "scenario_type": "boundary_test",
                "scope": "external",
                "authorized": False,
            },
            {
                "campaign_id": "boundary_test_2",
                "label": "benign",
                "operator_id": "test",
                "description": "Test benign boundary campaign",
                "events": [
                    {"t": 1000.0, "source": "tool", "tool": "read_file", "category": "read", "target": "config.yaml", "meta": {}}
                ],
                "difficulty": "baseline",
                "scenario_type": "boundary_test",
                "scope": "internal",
                "authorized": True,
            },
        ]
        
        for entry in entries:
            f.write(json.dumps(entry) + '\n')
        
        temp_path = f.name
    
    try:
        scenarios = load_boundary_dataset(temp_path)
        
        assert len(scenarios) == 2
        assert scenarios[0].campaign_id == "boundary_test_1"
        assert scenarios[0].label == CampaignLabel.MALICIOUS
        assert scenarios[0].difficulty == Difficulty.HARD_FN
        assert scenarios[1].campaign_id == "boundary_test_2"
        assert scenarios[1].label == CampaignLabel.BENIGN
        assert scenarios[1].difficulty == Difficulty.BASELINE
    finally:
        Path(temp_path).unlink()


def test_load_boundary_dataset_invalid_json():
    """Test loading boundary dataset with invalid JSON lines."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False, encoding='utf-8') as f:
        f.write('{"valid": "json"}\n')
        f.write('{invalid json}\n')  # Invalid JSON
        f.write('{"campaign_id": "test_3", "label": "benign", "events": []}\n')
        temp_path = f.name
    
    try:
        scenarios = load_boundary_dataset(temp_path)
        # Should skip invalid line and load valid ones
        assert len(scenarios) >= 1
    finally:
        Path(temp_path).unlink()


def test_load_boundary_dataset_missing_fields():
    """Test loading boundary dataset with missing optional fields."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False, encoding='utf-8') as f:
        # Minimal valid entry
        entry = {
            "campaign_id": "minimal_test",
            "label": "malicious",
            "events": [],
        }
        f.write(json.dumps(entry) + '\n')
        temp_path = f.name
    
    try:
        scenarios = load_boundary_dataset(temp_path)
        assert len(scenarios) == 1
        assert scenarios[0].campaign_id == "minimal_test"
        # Should use defaults for missing fields
        assert scenarios[0].difficulty == Difficulty.BASELINE  # Default
    finally:
        Path(temp_path).unlink()


def test_load_boundary_dataset_nonexistent():
    """Test loading non-existent boundary dataset."""
    with pytest.raises(FileNotFoundError):
        load_boundary_dataset("nonexistent_file.jsonl")


# ---------------------------------------------------------------------------
# run_extended_ablation_study smoke test
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_run_extended_ablation_study_smoke():
    """Smoke test for run_extended_ablation_study on minimal dataset."""
    scenarios = make_minimal_scenarios()
    
    result = run_extended_ablation_study(
        scenarios=scenarios,
        run_name="Test_Run",
        baseline_decisions=None,
        use_phase_floor=True,
        use_scope_mismatch=True,
        use_policy_layer=True,
        t_soft=0.35,
        t_hard=0.55,
    )
    
    # Grundstruktur prüfen
    for key in ["metrics", "margin_analyses", "detection_delays", "calibration", "results"]:
        assert key in result
    
    assert len(result["results"]) == len(scenarios)
    
    calib = result["calibration"]
    assert isinstance(calib["ece"], float)
    assert isinstance(calib["brier"], float)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

