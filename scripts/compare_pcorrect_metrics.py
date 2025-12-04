"""
Compare Alternative p_correct Metrics for Evidence-Based AnswerPolicy
=====================================================================

Evaluates 4 different p_correct formulas to identify the best metric
for AnswerPolicy decisions based on Dempster-Shafer fusion results.

Metrics compared:
1. Current: belief_promote + unknown
2. One minus belief_quarantine: 1.0 - belief_quarantine
3. Plausibility promote: plausibility_promote
4. Trust score: belief_promote / (belief_promote + belief_quarantine)

Usage:
    python scripts/compare_pcorrect_metrics.py \
        --input logs/threshold_sweep/evidence_based_threshold_98.jsonl \
        --dataset datasets/core_suite_smoke.jsonl \
        --output results/pcorrect_metrics_comparison.json

Author: Joerg Bollwahn / AI Assistant
Date: 2025-12-03
License: MIT
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any

import numpy as np


def extract_dempster_shafer_metrics(ap_meta: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract Dempster-Shafer masses and compute all p_correct metrics.

    Args:
        ap_meta: answer_policy metadata dictionary

    Returns:
        Dictionary with all computed metrics
    """
    # Extract masses from combined_mass
    combined_mass = ap_meta.get("combined_mass", {})
    belief_promote = combined_mass.get("promote", 0.0)
    belief_quarantine = combined_mass.get("quarantine", 0.0)
    unknown_mass = combined_mass.get("unknown", 0.0)

    # Also try direct fields (if stored separately)
    if "belief_promote" in ap_meta:
        belief_promote = ap_meta["belief_promote"]
    if "belief_quarantine" in ap_meta:
        belief_quarantine = ap_meta["belief_quarantine"]
    if "unknown_mass" in ap_meta:
        unknown_mass = ap_meta["unknown_mass"]

    # Compute plausibility_promote (1 - belief_quarantine)
    plausibility_promote = 1.0 - belief_quarantine

    # Compute all metrics
    metrics = {
        "current": belief_promote + unknown_mass,
        "one_minus_belief_quar": 1.0 - belief_quarantine,
        "plausibility_prom": plausibility_promote,
        "trust_score": (
            belief_promote / (belief_promote + belief_quarantine)
            if (belief_promote + belief_quarantine) > 1e-10
            else 0.5
        ),
    }

    # Store raw masses for debugging
    metrics["_raw"] = {
        "belief_promote": belief_promote,
        "belief_quarantine": belief_quarantine,
        "unknown_mass": unknown_mass,
    }

    return metrics


def compute_separation_statistics(
    redteam_values: List[float], benign_values: List[float]
) -> Dict[str, float]:
    """
    Compute separation statistics between two distributions.

    Args:
        redteam_values: List of metric values for redteam items
        benign_values: List of metric values for benign items

    Returns:
        Dictionary with separation statistics
    """
    if not redteam_values or not benign_values:
        return {"error": "Empty distribution"}

    redteam_arr = np.array(redteam_values)
    benign_arr = np.array(benign_values)

    # Basic statistics
    stats = {
        "redteam_mean": float(np.mean(redteam_arr)),
        "redteam_std": float(np.std(redteam_arr)),
        "redteam_min": float(np.min(redteam_arr)),
        "redteam_max": float(np.max(redteam_arr)),
        "benign_mean": float(np.mean(benign_arr)),
        "benign_std": float(np.std(benign_arr)),
        "benign_min": float(np.min(benign_arr)),
        "benign_max": float(np.max(benign_arr)),
        "mean_diff": float(np.mean(benign_arr) - np.mean(redteam_arr)),
        "mean_diff_abs": float(abs(np.mean(benign_arr) - np.mean(redteam_arr))),
    }

    # Cohen's d (effect size)
    pooled_std = np.sqrt((np.var(redteam_arr) + np.var(benign_arr)) / 2.0)
    if pooled_std > 1e-10:
        stats["cohens_d"] = float(
            (np.mean(benign_arr) - np.mean(redteam_arr)) / pooled_std
        )
    else:
        stats["cohens_d"] = 0.0

    # Overlap: percentage of redteam values above benign mean
    benign_mean = np.mean(benign_arr)
    overlap_redteam_above_benign_mean = float(
        np.sum(redteam_arr > benign_mean) / len(redteam_arr)
    )

    # Overlap: percentage of benign values below redteam mean
    redteam_mean = np.mean(redteam_arr)
    overlap_benign_below_redteam_mean = float(
        np.sum(benign_arr < redteam_mean) / len(benign_arr)
    )

    stats["overlap_redteam_above_benign_mean"] = overlap_redteam_above_benign_mean
    stats["overlap_benign_below_redteam_mean"] = overlap_benign_below_redteam_mean

    # Value range (spread)
    all_values = np.concatenate([redteam_arr, benign_arr])
    stats["value_range"] = float(np.max(all_values) - np.min(all_values))
    stats["value_std"] = float(np.std(all_values))

    return stats


def analyze_metrics(
    decisions: List[Dict[str, Any]], dataset: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Analyze all p_correct metrics and their separation ability.

    Args:
        decisions: List of decision dictionaries
        dataset: Original dataset with item types

    Returns:
        Analysis results dictionary
    """
    # Create lookup dict
    dataset_dict = {d["id"]: d for d in dataset}

    # Collect metrics by type
    metrics_by_type = defaultdict(lambda: defaultdict(list))

    for decision in decisions:
        item_id = decision.get("item_id", "")
        item_data = dataset_dict.get(item_id, {})
        item_type = item_data.get("type", decision.get("item_type", "unknown"))

        if item_type not in ["redteam", "benign"]:
            continue

        ap_meta = decision.get("metadata", {}).get("answer_policy", {})
        if not ap_meta or ap_meta.get("p_correct_method") != "dempster_shafer":
            continue

        # Extract all metrics
        metrics = extract_dempster_shafer_metrics(ap_meta)

        # Store by metric name and item type
        for metric_name, metric_value in metrics.items():
            if not metric_name.startswith("_"):  # Skip raw/internal fields
                metrics_by_type[metric_name][item_type].append(metric_value)

    # Compute separation statistics for each metric
    results = {}
    for metric_name in [
        "current",
        "one_minus_belief_quar",
        "plausibility_prom",
        "trust_score",
    ]:
        redteam_values = metrics_by_type[metric_name].get("redteam", [])
        benign_values = metrics_by_type[metric_name].get("benign", [])

        if not redteam_values or not benign_values:
            results[metric_name] = {"error": "Insufficient data"}
            continue

        stats = compute_separation_statistics(redteam_values, benign_values)
        stats["redteam_count"] = len(redteam_values)
        stats["benign_count"] = len(benign_values)
        results[metric_name] = stats

    return results


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Compare alternative p_correct metrics for AnswerPolicy"
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Input decision log JSONL file",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        help="Original dataset JSONL file (for item types)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output JSON file for results",
    )

    args = parser.parse_args()

    # Load decisions
    decisions = []
    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    decisions.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: Invalid JSON: {e}", file=sys.stderr)
                    continue

    if not decisions:
        print("Error: No valid decisions found", file=sys.stderr)
        return 1

    # Load dataset if provided
    dataset = []
    if args.dataset and args.dataset.exists():
        with open(args.dataset, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        dataset.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

    # Analyze metrics
    print("Analyzing p_correct metrics...")
    results = analyze_metrics(decisions, dataset)

    # Print summary table
    print("\n" + "=" * 80)
    print("p_correct Metrics Comparison")
    print("=" * 80)
    print(
        f"{'Metric':<30} {'Redteam Mean':<15} {'Benign Mean':<15} {'Mean Diff':<15} {'Cohens d':<12} {'Range':<10}"
    )
    print("-" * 80)

    for metric_name, stats in results.items():
        if "error" in stats:
            print(f"{metric_name:<30} {'ERROR':<15}")
            continue

        print(
            f"{metric_name:<30} "
            f"{stats['redteam_mean']:<15.4f} "
            f"{stats['benign_mean']:<15.4f} "
            f"{stats['mean_diff']:<15.4f} "
            f"{stats['cohens_d']:<12.4f} "
            f"{stats['value_range']:<10.4f}"
        )

    print("\n" + "=" * 80)
    print("Detailed Statistics")
    print("=" * 80)

    for metric_name, stats in results.items():
        if "error" in stats:
            continue

        print(f"\n{metric_name.upper()}:")
        print(
            f"  Redteam: mean={stats['redteam_mean']:.4f}, std={stats['redteam_std']:.4f}, "
            f"range=[{stats['redteam_min']:.4f}, {stats['redteam_max']:.4f}], n={stats['redteam_count']}"
        )
        print(
            f"  Benign:  mean={stats['benign_mean']:.4f}, std={stats['benign_std']:.4f}, "
            f"range=[{stats['benign_min']:.4f}, {stats['benign_max']:.4f}], n={stats['benign_count']}"
        )
        print(
            f"  Separation: mean_diff={stats['mean_diff']:.4f}, Cohen's d={stats['cohens_d']:.4f}"
        )
        print(
            f"  Overlap: {stats['overlap_redteam_above_benign_mean'] * 100:.1f}% redteam > benign_mean, "
            f"{stats['overlap_benign_below_redteam_mean'] * 100:.1f}% benign < redteam_mean"
        )
        print(
            f"  Value spread: range={stats['value_range']:.4f}, std={stats['value_std']:.4f}"
        )

    # Save results if output specified
    if args.output:
        output_data = {
            "input_file": str(args.input),
            "dataset_file": str(args.dataset) if args.dataset else None,
            "total_decisions": len(decisions),
            "metrics": results,
        }

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)

        print(f"\nResults saved to: {args.output}")

    return 0


if __name__ == "__main__":
    # Check if numpy is available
    try:
        import numpy as np
    except ImportError:
        print(
            "Error: numpy is required. Install with: pip install numpy", file=sys.stderr
        )
        sys.exit(1)

    sys.exit(main())
