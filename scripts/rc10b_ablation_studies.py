#!/usr/bin/env python3
"""
RC10b Ablation Studies Script
==============================

Führt Ablations-Studien durch, um den Effekt jedes Patches zu quantifizieren:
1. Run ohne Phase-Floor (erwartet: HARD_FN ASR → 100%)
2. Run ohne Scope-Mismatch (erwartet: SHIFT ASR → 60%)
3. Run ohne Policy-Schicht (erwartet: HARD_FP FPR_block → 30%)

Creator: Joerg Bollwahn
Date: 2025-11-17
License: MIT
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add paths - find project root intelligently
script_path = Path(__file__).resolve()
# Try to find project root: either parent of scripts/ or standalone_packages/llm-security-firewall/
if script_path.parent.name == "scripts":
    project_root = script_path.parent.parent
else:
    # Fallback: search for standalone_packages/llm-security-firewall from current working directory
    cwd = Path.cwd()
    potential_roots = [
        cwd / "standalone_packages" / "llm-security-firewall",
        cwd.parent / "standalone_packages" / "llm-security-firewall",
        script_path.parent.parent,  # Fallback to original logic
    ]
    project_root = None
    for root in potential_roots:
        if (root / "src" / "llm_firewall").exists():
            project_root = root
            break
    if project_root is None:
        project_root = script_path.parent.parent  # Default fallback

src_path = project_root / "src"
sys.path.insert(0, str(src_path))
sys.path.insert(0, str(project_root))

data_path = project_root / "data"
sys.path.insert(0, str(data_path))

from campaign_dataset import (
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
from typing import Any, Dict, List

# Import validation functions from rc10b_validate
from rc10b_validate import (
    CampaignEvalResult,
    compute_metrics_by_difficulty,
    evaluate_campaign_rc10b,
)


def run_ablation_study(
    scenarios: List[CampaignScenario],
    run_name: str,
    use_phase_floor: bool = True,
    use_scope_mismatch: bool = True,
    use_policy_layer: bool = True,
    t_soft: float = 0.35,
    t_hard: float = 0.55,
) -> Dict[str, Any]:
    """
    Run ablation study with specified flags.

    Returns:
        Dictionary with metrics and results
    """
    print(f"\n{'=' * 60}")
    print(f"ABLATION STUDY: {run_name}")
    print(f"{'=' * 60}")
    print(f"  Phase-Floor: {use_phase_floor}")
    print(f"  Scope-Mismatch: {use_scope_mismatch}")
    print(f"  Policy-Layer: {use_policy_layer}")
    print()

    # Initialize detector with ablation flags
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

    # Compute metrics
    metrics = compute_metrics_by_difficulty(results, t_soft, t_hard)

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
        "results": [
            {
                "campaign_id": r.campaign_id,
                "label": r.label,
                "difficulty": r.difficulty.value,
                "scenario_type": r.scenario_type,
                "risk_max": r.risk_max,
                "blocked": r.blocked,
                "require_approval": r.require_approval,
            }
            for r in results
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="RC10b Ablation Studies")
    parser.add_argument(
        "--dataset",
        type=str,
        help="Path to Phase-2 dataset JSON file",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="results/ablation",
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

    # Resolve dataset path relative to project_root if it's a relative path
    dataset_path = None
    if args.dataset:
        dataset_path = Path(args.dataset)
        if not dataset_path.is_absolute():
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

    # Create output directory - resolve relative to project_root if relative
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = project_root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run 1: Full RC10b (baseline)
    run1 = run_ablation_study(
        scenarios,
        "Run_1_Full_RC10b",
        use_phase_floor=True,
        use_scope_mismatch=True,
        use_policy_layer=True,
        t_soft=args.t_soft,
        t_hard=args.t_hard,
    )
    with open(output_dir / "run1_full_rc10b.json", "w") as f:
        json.dump(run1, f, indent=2)

    # Run 2: Without Phase-Floor
    run2 = run_ablation_study(
        scenarios,
        "Run_2_No_Phase_Floor",
        use_phase_floor=False,
        use_scope_mismatch=True,
        use_policy_layer=True,
        t_soft=args.t_soft,
        t_hard=args.t_hard,
    )
    with open(output_dir / "run2_no_phase_floor.json", "w") as f:
        json.dump(run2, f, indent=2)

    # Run 3: Without Scope-Mismatch
    run3 = run_ablation_study(
        scenarios,
        "Run_3_No_Scope_Mismatch",
        use_phase_floor=True,
        use_scope_mismatch=False,
        use_policy_layer=True,
        t_soft=args.t_soft,
        t_hard=args.t_hard,
    )
    with open(output_dir / "run3_no_scope_mismatch.json", "w") as f:
        json.dump(run3, f, indent=2)

    # Run 4: Without Policy-Layer
    run4 = run_ablation_study(
        scenarios,
        "Run_4_No_Policy_Layer",
        use_phase_floor=True,
        use_scope_mismatch=True,
        use_policy_layer=False,
        t_soft=args.t_soft,
        t_hard=args.t_hard,
    )
    with open(output_dir / "run4_no_policy_layer.json", "w") as f:
        json.dump(run4, f, indent=2)

    # Generate comparison table
    print("\n" + "=" * 80)
    print("ABLATION STUDY RESULTS - COMPARISON TABLE")
    print("=" * 80)

    # Create comparison table
    table_data = []

    # Header
    difficulties = ["baseline", "hard_fn", "shift", "hard_fp"]
    runs = [
        ("Full RC10b", run1),
        ("No Phase-Floor", run2),
        ("No Scope-Mismatch", run3),
        ("No Policy-Layer", run4),
    ]

    print("\n" + "-" * 80)
    print(
        f"{'Configuration':<25} | {'BASELINE':<15} | {'HARD_FN':<15} | {'SHIFT':<15} | {'HARD_FP':<15}"
    )
    print(
        f"{'':<25} | {'ASR/FPR':<15} | {'ASR_block':<15} | {'ASR_block':<15} | {'FPR_block':<15}"
    )
    print("-" * 80)

    for run_name, run_data in runs:
        row = [run_name]
        for diff in difficulties:
            m = run_data["metrics"].get(diff, {})
            if diff == "baseline":
                asr = m.get("asr_block", 0.0)
                fpr = m.get("fpr_block", 0.0)
                cell = f"ASR:{asr:.3f} FPR:{fpr:.3f}"
            elif diff in ["hard_fn", "shift"]:
                asr = m.get("asr_block", 0.0)
                cell = f"{asr:.3f} ({asr * 100:.1f}%)"
            else:  # hard_fp
                fpr = m.get("fpr_block", 0.0)
                cell = f"{fpr:.3f} ({fpr * 100:.1f}%)"
            row.append(cell)
        print(
            f"{row[0]:<25} | {row[1]:<15} | {row[2]:<15} | {row[3]:<15} | {row[4]:<15}"
        )

    print("-" * 80)

    # Detailed analysis
    print("\n" + "=" * 80)
    print("DETAILED ANALYSIS")
    print("=" * 80)

    print("\n1. HARD_FN (Low & Slow) - ASR_block:")
    print(
        f"   Full RC10b:        {run1['metrics']['hard_fn']['asr_block']:.3f} ({run1['metrics']['hard_fn']['asr_block'] * 100:.1f}%)"
    )
    print(
        f"   No Phase-Floor:    {run2['metrics']['hard_fn']['asr_block']:.3f} ({run2['metrics']['hard_fn']['asr_block'] * 100:.1f}%)"
    )
    print(
        f"   Delta:             {run2['metrics']['hard_fn']['asr_block'] - run1['metrics']['hard_fn']['asr_block']:+.3f}"
    )
    print("   Expected:          ~1.000 (100%) - Phase-Floor is critical for HARD_FN")

    print("\n2. SHIFT (Pretext/Scope-Abuse) - ASR_block:")
    print(
        f"   Full RC10b:           {run1['metrics']['shift']['asr_block']:.3f} ({run1['metrics']['shift']['asr_block'] * 100:.1f}%)"
    )
    print(
        f"   No Scope-Mismatch:    {run3['metrics']['shift']['asr_block']:.3f} ({run3['metrics']['shift']['asr_block'] * 100:.1f}%)"
    )
    print(
        f"   Delta:                {run3['metrics']['shift']['asr_block'] - run1['metrics']['shift']['asr_block']:+.3f}"
    )
    print(
        "   Expected:             ~0.600 (60%) - Scope-Mismatch is critical for SHIFT"
    )

    print("\n3. HARD_FP (Testlab/Recon) - FPR_block:")
    print(
        f"   Full RC10b:          {run1['metrics']['hard_fp']['fpr_block']:.3f} ({run1['metrics']['hard_fp']['fpr_block'] * 100:.1f}%)"
    )
    print(
        f"   No Policy-Layer:     {run4['metrics']['hard_fp']['fpr_block']:.3f} ({run4['metrics']['hard_fp']['fpr_block'] * 100:.1f}%)"
    )
    print(
        f"   Delta:               {run4['metrics']['hard_fp']['fpr_block'] - run1['metrics']['hard_fp']['fpr_block']:+.3f}"
    )
    print(
        "   Expected:            ~0.300 (30%, RC10 baseline) - Policy-Layer prevents HC1/HC3 false blocks"
    )

    print("\n4. BASELINE - Stability Check:")
    print(
        f"   Full RC10b:          ASR:{run1['metrics']['baseline']['asr_block']:.3f} FPR:{run1['metrics']['baseline']['fpr_block']:.3f}"
    )
    print(
        f"   No Phase-Floor:      ASR:{run2['metrics']['baseline']['asr_block']:.3f} FPR:{run2['metrics']['baseline']['fpr_block']:.3f}"
    )
    print(
        f"   No Scope-Mismatch:   ASR:{run3['metrics']['baseline']['asr_block']:.3f} FPR:{run3['metrics']['baseline']['fpr_block']:.3f}"
    )
    print(
        f"   No Policy-Layer:     ASR:{run4['metrics']['baseline']['asr_block']:.3f} FPR:{run4['metrics']['baseline']['fpr_block']:.3f}"
    )
    print("   Note: Baseline should remain stable across all configurations")

    print(f"\n{'=' * 80}")
    print(f"Results saved to {output_dir}/")
    print(f"{'=' * 80}")


if __name__ == "__main__":
    main()
