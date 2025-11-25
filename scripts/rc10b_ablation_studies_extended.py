#!/usr/bin/env python3
"""
RC10b Extended Ablation Studies Script
======================================

Erweiterte Ablations-Studien mit:
1. Margin-Analysen (risk - T_hard)
2. Detection-Delay-Verteilungen
3. Kalibration (Reliability Plots)
4. Boundary-Dataset-Support
5. Evasion-Search (optional)

Creator: Joerg Bollwahn
Date: 2025-11-18
License: MIT
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

# Add paths
script_path = Path(__file__).resolve()
if script_path.parent.name == "scripts":
    project_root = script_path.parent.parent
else:
    cwd = Path.cwd()
    potential_roots = [
        cwd / "standalone_packages" / "llm-security-firewall",
        cwd.parent / "standalone_packages" / "llm-security-firewall",
        script_path.parent.parent,
    ]
    project_root = None
    for root in potential_roots:
        if (root / "src" / "llm_firewall").exists():
            project_root = root
            break
    if project_root is None:
        project_root = script_path.parent.parent

src_path = project_root / "src"
sys.path.insert(0, str(src_path))
sys.path.insert(0, str(project_root))

data_path = project_root / "data"
sys.path.insert(0, str(data_path))

from campaign_dataset import (
    CampaignLabel,
    CampaignScenario,
    Difficulty,
    generate_phase2_hard_cases,
    generate_synthetic_dataset,
    load_dataset,
)

from llm_firewall.detectors.agentic_campaign import (
    AgenticCampaignDetector,
    CampaignDetectorConfig,
)

from rc10b_validate import (
    CampaignEvalResult,
    compute_metrics_by_difficulty,
    evaluate_campaign_rc10b,
)


def load_boundary_dataset(jsonl_path: str) -> List[CampaignScenario]:
    """
    Load boundary dataset from JSONL file.

    Each line should be a JSON object with CampaignScenario-like structure:
    {
        "campaign_id": "...",
        "label": "benign" | "malicious",
        "operator_id": "...",
        "description": "...",
        "events": [...],
        "difficulty": "baseline" | "hard_fp" | "hard_fn" | "shift",
        "scenario_type": "...",
        "scope": "internal" | "external" | "mixed" | "unknown",
        "authorized": true | false | "unknown"
    }
    """
    scenarios = []
    dataset_path = Path(jsonl_path)
    if not dataset_path.is_absolute() and project_root is not None:
        dataset_path = project_root / dataset_path

    if not dataset_path.exists():
        raise FileNotFoundError(f"Boundary dataset not found: {dataset_path}")

    with open(dataset_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)

                # Convert label string to enum
                label_str = data.get("label", "benign").lower()
                if "malicious" in label_str:
                    label = CampaignLabel.MALICIOUS
                else:
                    label = CampaignLabel.BENIGN

                # Convert difficulty string to enum
                diff_str = data.get("difficulty", "baseline").lower()
                try:
                    difficulty = Difficulty(diff_str)
                except ValueError:
                    difficulty = Difficulty.BASELINE

                # Handle authorized field (can be bool or string)
                authorized = data.get("authorized", "unknown")
                if isinstance(authorized, str):
                    authorized = authorized.lower() not in (
                        "false",
                        "no",
                        "0",
                        "unknown",
                    )

                scenario = CampaignScenario(
                    campaign_id=data.get("campaign_id", f"boundary_{line_num}"),
                    label=label,
                    operator_id=data.get("operator_id", "boundary_gen"),
                    description=data.get("description", ""),
                    events=data.get("events", []),
                    difficulty=difficulty,
                    scenario_type=data.get("scenario_type", "boundary"),
                    scope=data.get("scope", "unknown"),
                    authorized=authorized,
                )
                scenarios.append(scenario)
            except json.JSONDecodeError as e:
                print(f"Warning: Skipping invalid JSON at line {line_num}: {e}")
                continue
            except Exception as e:
                print(f"Warning: Error processing line {line_num}: {e}")
                continue

    print(f"Loaded {len(scenarios)} scenarios from boundary dataset")
    return scenarios


@dataclass
class MarginAnalysis:
    """Margin analysis for a set of campaigns."""

    margins: List[float]  # risk - T_hard for each campaign
    mean_margin: float
    median_margin: float
    std_margin: float
    p25_margin: float
    p75_margin: float
    n_above_threshold: int
    n_below_threshold: int
    decision_flip_count: int = 0  # Compared to baseline


@dataclass
class DetectionDelayStats:
    """Detection delay statistics."""

    delays_events_soft: List[int]
    delays_events_hard: List[int]
    delays_time_soft: List[float]
    delays_time_hard: List[float]
    mean_events_soft: Optional[float] = None
    mean_events_hard: Optional[float] = None
    mean_time_soft: Optional[float] = None
    mean_time_hard: Optional[float] = None
    median_events_soft: Optional[int] = None
    median_events_hard: Optional[int] = None


@dataclass
class CalibrationMetrics:
    """Calibration metrics (ECE, Brier Score)."""

    ece: float  # Expected Calibration Error
    brier: float  # Brier Score
    reliability_data: Dict[str, Any]  # Bins, counts, etc.


def compute_margin_analysis(
    results: List[CampaignEvalResult],
    baseline_decisions: Optional[Dict[str, bool]],
    t_hard: float,
) -> Dict[str, MarginAnalysis]:
    """
    Compute margin analysis per difficulty class.

    Margin = risk - T_hard
    - Positive margin: above threshold (should be blocked)
    - Negative margin: below threshold (should not be blocked)

    Args:
        results: List of evaluation results
        baseline_decisions: Optional dict mapping campaign_id -> blocked (for decision flip analysis)
        t_hard: Hard threshold
    """
    margins_by_diff: Dict[Difficulty, List[float]] = defaultdict(list)

    # Collect margins
    for res in results:
        margin = res.risk_max - t_hard
        margins_by_diff[res.difficulty].append(margin)

    # Compute decision flips if baseline provided
    decision_flips: Dict[Difficulty, int] = defaultdict(int)
    if baseline_decisions:
        for res in results:
            baseline_decision = baseline_decisions.get(res.campaign_id)
            if baseline_decision is not None and baseline_decision != res.blocked:
                decision_flips[res.difficulty] += 1

    # Build MarginAnalysis per difficulty
    margin_analyses = {}
    for diff, margins in margins_by_diff.items():
        if not margins:
            continue

        margins_arr = np.array(margins)

        margin_analyses[diff.value] = MarginAnalysis(
            margins=margins,
            mean_margin=float(np.mean(margins_arr)),
            median_margin=float(np.median(margins_arr)),
            std_margin=float(np.std(margins_arr)),
            p25_margin=float(np.percentile(margins_arr, 25)),
            p75_margin=float(np.percentile(margins_arr, 75)),
            n_above_threshold=sum(1 for m in margins if m > 0),
            n_below_threshold=sum(1 for m in margins if m <= 0),
            decision_flip_count=decision_flips.get(diff, 0),
        )

    return margin_analyses


def compute_detection_delay_stats(
    results: List[CampaignEvalResult],
) -> Dict[str, DetectionDelayStats]:
    """Compute detection delay statistics per difficulty class."""
    delays_by_diff: Dict[Difficulty, Dict[str, List]] = defaultdict(
        lambda: {
            "events_soft": [],
            "events_hard": [],
            "time_soft": [],
            "time_hard": [],
        }
    )

    for res in results:
        if res.delay_events_soft is not None:
            delays_by_diff[res.difficulty]["events_soft"].append(res.delay_events_soft)
        if res.delay_events_hard is not None:
            delays_by_diff[res.difficulty]["events_hard"].append(res.delay_events_hard)
        if res.delay_time_soft is not None:
            delays_by_diff[res.difficulty]["time_soft"].append(res.delay_time_soft)
        if res.delay_time_hard is not None:
            delays_by_diff[res.difficulty]["time_hard"].append(res.delay_time_hard)

    delay_stats = {}
    for diff, delays in delays_by_diff.items():
        events_soft = delays["events_soft"]
        events_hard = delays["events_hard"]
        time_soft = delays["time_soft"]
        time_hard = delays["time_hard"]

        delay_stats[diff.value] = DetectionDelayStats(
            delays_events_soft=events_soft,
            delays_events_hard=events_hard,
            delays_time_soft=time_soft,
            delays_time_hard=time_hard,
            mean_events_soft=float(np.mean(events_soft)) if events_soft else None,
            mean_events_hard=float(np.mean(events_hard)) if events_hard else None,
            mean_time_soft=float(np.mean(time_soft)) if time_soft else None,
            mean_time_hard=float(np.mean(time_hard)) if time_hard else None,
            median_events_soft=int(np.median(events_soft)) if events_soft else None,
            median_events_hard=int(np.median(events_hard)) if events_hard else None,
        )

    return delay_stats


def compute_calibration_metrics(
    results: List[CampaignEvalResult],
    n_bins: int = 10,
) -> CalibrationMetrics:
    """
    Compute calibration metrics (ECE, Brier Score).

    Uses risk scores as predicted probabilities and actual labels.

    Note: We treat the maximum campaign risk as a pseudo-probability for the
    purpose of ECE/Brier analysis. If risk_max is not in [0,1], results may
    be less interpretable.
    """
    # Extract risk scores and labels
    risk_scores = []
    labels = []  # 1 = malicious, 0 = benign

    for res in results:
        risk_scores.append(res.risk_max)
        # Robust label handling: accept "malicious"/"MALICIOUS" or CampaignLabel enum
        label_str = str(res.label).lower()
        labels.append(1 if "malicious" in label_str else 0)

    risk_scores = np.array(risk_scores)
    labels = np.array(labels)

    # Handle empty dataset
    if len(risk_scores) == 0:
        return CalibrationMetrics(
            ece=0.0,
            brier=float("nan"),
            reliability_data={"n_bins": n_bins, "bins": []},
        )

    # Bin the risk scores
    bin_edges = np.linspace(0, 1, n_bins + 1)
    bin_indices = np.digitize(risk_scores, bin_edges) - 1
    bin_indices = np.clip(bin_indices, 0, n_bins - 1)

    # Compute per-bin statistics
    bin_data = []
    ece_sum = 0.0
    total_samples = len(risk_scores)

    for i in range(n_bins):
        mask = bin_indices == i
        if not np.any(mask):
            continue

        bin_risks = risk_scores[mask]
        bin_labels = labels[mask]

        mean_risk = float(np.mean(bin_risks))
        mean_label = float(np.mean(bin_labels))
        count = int(np.sum(mask))
        weight = count / total_samples

        calibration_error = abs(mean_risk - mean_label)
        ece_sum += weight * calibration_error

        bin_data.append(
            {
                "bin": i,
                "bin_start": float(bin_edges[i]),
                "bin_end": float(bin_edges[i + 1]),
                "mean_risk": mean_risk,
                "mean_label": mean_label,
                "count": count,
                "calibration_error": calibration_error,
            }
        )

    ece = ece_sum

    # Brier Score
    brier = float(np.mean((risk_scores - labels) ** 2))

    return CalibrationMetrics(
        ece=ece,
        brier=brier,
        reliability_data={
            "n_bins": n_bins,
            "bins": bin_data,
        },
    )


def run_extended_ablation_study(
    scenarios: List[CampaignScenario],
    run_name: str,
    baseline_decisions: Optional[Dict[str, bool]],
    use_phase_floor: bool = True,
    use_scope_mismatch: bool = True,
    use_policy_layer: bool = True,
    t_soft: float = 0.35,
    t_hard: float = 0.55,
) -> Dict[str, Any]:
    """
    Run extended ablation study with margin analysis, delays, and calibration.
    """
    print(f"\n{'=' * 60}")
    print(f"EXTENDED ABLATION STUDY: {run_name}")
    print(f"{'=' * 60}")
    print(f"  Phase-Floor: {use_phase_floor}")
    print(f"  Scope-Mismatch: {use_scope_mismatch}")
    print(f"  Policy-Layer: {use_policy_layer}")
    print()

    # Initialize detector
    detector = AgenticCampaignDetector(
        config=CampaignDetectorConfig(
            use_phase_floor=use_phase_floor,
            use_scope_mismatch=use_scope_mismatch,
            use_policy_layer=use_policy_layer,
        )
    )

    # Evaluate all scenarios
    print("Evaluating campaigns...")
    results: List[CampaignEvalResult] = []

    for i, scenario in enumerate(scenarios):
        if (i + 1) % 20 == 0:
            print(f"  Processed {i + 1}/{len(scenarios)} scenarios...")

        res = evaluate_campaign_rc10b(
            detector=detector,
            scenario=scenario,
            t_soft=t_soft,
            t_hard=t_hard,
        )
        results.append(res)

    print(f"  Completed {len(results)} scenarios\n")

    # Compute standard metrics
    metrics = compute_metrics_by_difficulty(results, t_soft, t_hard)

    # Compute extended metrics
    margin_analyses = compute_margin_analysis(results, baseline_decisions, t_hard)
    delay_stats = compute_detection_delay_stats(results)
    calibration = compute_calibration_metrics(results)

    # Print summary
    print("SUMMARY:")
    for diff in [
        Difficulty.BASELINE,
        Difficulty.HARD_FP,
        Difficulty.HARD_FN,
        Difficulty.SHIFT,
    ]:
        m = metrics.get(diff)
        if m is None:
            continue

        print(f"  [{diff.value}]")
        if diff == Difficulty.HARD_FN:
            print(f"    ASR_block: {m.asr_block:.3f} ({m.asr_block * 100:.1f}%)")
        elif diff == Difficulty.SHIFT:
            print(f"    ASR_block: {m.asr_block:.3f} ({m.asr_block * 100:.1f}%)")
        elif diff == Difficulty.HARD_FP:
            print(f"    FPR_block: {m.fpr_block:.3f} ({m.fpr_block * 100:.1f}%)")
        else:
            print(f"    ASR_block: {m.asr_block:.3f}, FPR_block: {m.fpr_block:.3f}")

        # Print margin analysis
        margin_analysis = margin_analyses.get(diff.value)
        if margin_analysis:
            print(
                f"    Margin: mean={margin_analysis.mean_margin:+.3f}, "
                f"median={margin_analysis.median_margin:+.3f}, "
                f"std={margin_analysis.std_margin:.3f}"
            )
            print(
                f"    Above threshold: {margin_analysis.n_above_threshold}, "
                f"Below threshold: {margin_analysis.n_below_threshold}"
            )
            if margin_analysis.decision_flip_count > 0:
                print(
                    f"    Decision flips vs baseline: {margin_analysis.decision_flip_count}"
                )

        # Print delay stats
        delay_stat = delay_stats.get(diff.value)
        if delay_stat and delay_stat.mean_events_hard is not None:
            print(
                f"    Detection delay: {delay_stat.mean_events_hard:.1f} events "
                f"(median: {delay_stat.median_events_hard})"
            )

    print("\nCalibration:")
    print(f"  ECE: {calibration.ece:.4f}")
    print(f"  Brier Score: {calibration.brier:.4f}")

    return {
        "run_name": run_name,
        "flags": {
            "use_phase_floor": use_phase_floor,
            "use_scope_mismatch": use_scope_mismatch,
            "use_policy_layer": use_policy_layer,
        },
        "metrics": {
            diff.value: {
                "n_benign": m.n_benign,
                "n_malicious": m.n_malicious,
                "asr_block": m.asr_block,
                "asr_detect_soft": m.asr_detect_soft,
                "asr_detect_hard": m.asr_detect_hard,
                "fpr_block": m.fpr_block,
                "fpr_soft": m.fpr_soft,
                "avg_risk_malicious": m.avg_risk_malicious,
                "avg_risk_benign": m.avg_risk_benign,
            }
            for diff, m in metrics.items()
        },
        "margin_analyses": {
            diff: {
                "mean_margin": ma.mean_margin,
                "median_margin": ma.median_margin,
                "std_margin": ma.std_margin,
                "p25_margin": ma.p25_margin,
                "p75_margin": ma.p75_margin,
                "n_above_threshold": ma.n_above_threshold,
                "n_below_threshold": ma.n_below_threshold,
                "decision_flip_count": ma.decision_flip_count,
            }
            for diff, ma in margin_analyses.items()
        },
        "detection_delays": {
            diff: {
                "mean_events_soft": ds.mean_events_soft,
                "mean_events_hard": ds.mean_events_hard,
                "mean_time_soft": ds.mean_time_soft,
                "mean_time_hard": ds.mean_time_hard,
                "median_events_soft": ds.median_events_soft,
                "median_events_hard": ds.median_events_hard,
            }
            for diff, ds in delay_stats.items()
        },
        "calibration": {
            "ece": calibration.ece,
            "brier": calibration.brier,
            "reliability_data": calibration.reliability_data,
        },
        "results": [
            {
                "campaign_id": r.campaign_id,
                "label": r.label,
                "difficulty": r.difficulty.value,
                "scenario_type": r.scenario_type,
                "risk_max": r.risk_max,
                "margin": r.risk_max - t_hard,
                "blocked": r.blocked,
                "require_approval": r.require_approval,
                "delay_events_soft": r.delay_events_soft,
                "delay_events_hard": r.delay_events_hard,
            }
            for r in results
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="RC10b Extended Ablation Studies")
    parser.add_argument(
        "--dataset",
        type=str,
        help="Path to Phase-2 dataset JSON file",
    )
    parser.add_argument(
        "--boundary-dataset",
        type=str,
        help="Path to boundary dataset JSONL file",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="results/ablation_extended",
        help="Directory to save ablation results",
    )
    parser.add_argument(
        "--t-soft",
        type=float,
        default=0.35,
        help="Soft threshold (default: 0.35)",
    )
    parser.add_argument(
        "--t-hard",
        type=float,
        default=0.55,
        help="Hard threshold (default: 0.55)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed (default: 42)",
    )

    args = parser.parse_args()

    # Load or generate dataset
    if args.boundary_dataset:
        print(f"Loading boundary dataset from {args.boundary_dataset}...")
        scenarios = load_boundary_dataset(args.boundary_dataset)
    elif args.dataset:
        dataset_path = Path(args.dataset)
        if not dataset_path.is_absolute() and project_root is not None:
            dataset_path = project_root / dataset_path
        print(f"Loading dataset from {dataset_path}...")
        scenarios = load_dataset(str(dataset_path))
    else:
        print("Generating synthetic Phase-2 dataset...")
        baseline_scenarios = generate_synthetic_dataset(
            num_benign=50,
            num_malicious=50,
            seed=args.seed,
        )
        hard_cases = generate_phase2_hard_cases(
            num_hc1=20,
            num_hc2=20,
            num_hc3=20,
            num_hc4=20,
            seed=args.seed + 1,
        )
        scenarios = baseline_scenarios + hard_cases

    print(f"Loaded {len(scenarios)} scenarios\n")

    # Create output directory
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute() and project_root is not None:
        output_dir = project_root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run 1: Full RC10b (baseline)
    print("Running baseline (Full RC10b)...")
    run1 = run_extended_ablation_study(
        scenarios,
        "Run_1_Full_RC10b",
        baseline_decisions=None,
        use_phase_floor=True,
        use_scope_mismatch=True,
        use_policy_layer=True,
        t_soft=args.t_soft,
        t_hard=args.t_hard,
    )
    # Extract baseline decisions for comparison (only campaign_id -> blocked)
    baseline_decisions = {r["campaign_id"]: r["blocked"] for r in run1["results"]}

    with open(output_dir / "run1_full_rc10b.json", "w") as f:
        json.dump(run1, f, indent=2)

    # Run 2-4: Ablations (with baseline for margin comparison)
    runs = [
        ("Run_2_No_Phase_Floor", False, True, True),
        ("Run_3_No_Scope_Mismatch", True, False, True),
        ("Run_4_No_Policy_Layer", True, True, False),
    ]

    for run_name, use_phase_floor, use_scope_mismatch, use_policy_layer in runs:
        run_data = run_extended_ablation_study(
            scenarios,
            run_name,
            baseline_decisions=baseline_decisions,
            use_phase_floor=use_phase_floor,
            use_scope_mismatch=use_scope_mismatch,
            use_policy_layer=use_policy_layer,
            t_soft=args.t_soft,
            t_hard=args.t_hard,
        )

        # Map run names to expected filenames for test compatibility
        filename_map = {
            "Run_2_No_Phase_Floor": "run2_no_phase_floor.json",
            "Run_3_No_Scope_Mismatch": "run3_no_scope_mismatch.json",
            "Run_4_No_Policy_Layer": "run4_no_policy_layer.json",
        }
        filename = filename_map.get(
            run_name, run_name.lower().replace(" ", "_") + ".json"
        )
        with open(output_dir / filename, "w") as f:
            json.dump(run_data, f, indent=2)

    print(f"\n{'=' * 80}")
    print(f"Results saved to {output_dir}/")
    print(f"{'=' * 80}")


if __name__ == "__main__":
    main()
