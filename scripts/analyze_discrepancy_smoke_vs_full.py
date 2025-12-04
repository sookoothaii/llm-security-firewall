#!/usr/bin/env python3
"""
Smoke Test vs. Full Evaluation Discrepancy Analysis
====================================================

Systematically diagnoses the cause of discrepancies between smoke test and
full evaluation results. Analyzes dataset composition, label distribution,
category distribution, and p_correct distributions.

This script addresses the root cause identified in evaluation: smoke tests
were misleading due to small, non-representative samples.

Usage:
    python scripts/analyze_discrepancy_smoke_vs_full.py \
        --smoke-results logs/smoke_test_results.jsonl \
        --full-results logs/full_evaluation_results.jsonl \
        --output analysis/discrepancy_analysis.json \
        --num-workers 20

Author: Joerg Bollwahn
Date: 2025-12-04
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add src directory to path
base_dir = Path(__file__).parent.parent
src_dir = base_dir / "src"
if src_dir.exists():
    sys.path.insert(0, str(src_dir))

try:
    from scripts.cpu_optimization import get_optimal_worker_count, detect_cpu_info

    HAS_CPU_OPT = True
except ImportError:
    HAS_CPU_OPT = False


def load_results(filepath: Path) -> List[Dict[str, Any]]:
    """
    Load experiment results from JSONL file.

    Args:
        filepath: Path to JSONL file

    Returns:
        List of result dictionaries
    """
    results = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: Failed to parse line: {e}", file=sys.stderr)
                    continue
    return results


def analyze_dataset_composition(
    smoke_results: List[Dict[str, Any]], full_results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Analyze dataset composition differences.

    Args:
        smoke_results: Smoke test results
        full_results: Full evaluation results

    Returns:
        Dictionary with composition analysis
    """
    return {
        "smoke_test_items": len(smoke_results),
        "full_eval_items": len(full_results),
        "ratio": len(full_results) / len(smoke_results) if smoke_results else 0.0,
    }


def analyze_label_distribution(
    smoke_results: List[Dict[str, Any]], full_results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Analyze label distribution differences.

    Args:
        smoke_results: Smoke test results
        full_results: Full evaluation results

    Returns:
        Dictionary with label distribution analysis
    """

    def count_labels(results: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = defaultdict(int)
        for r in results:
            label = r.get("item_type", "").lower()
            if label:
                counts[label] += 1
        return dict(counts)

    smoke_labels = count_labels(smoke_results)
    full_labels = count_labels(full_results)

    def calculate_percentages(counts: Dict[str, int], total: int) -> Dict[str, float]:
        return {
            label: count / total if total > 0 else 0.0
            for label, count in counts.items()
        }

    smoke_total = len(smoke_results)
    full_total = len(full_results)

    smoke_pct = calculate_percentages(smoke_labels, smoke_total)
    full_pct = calculate_percentages(full_labels, full_total)

    return {
        "smoke_test": {
            "counts": smoke_labels,
            "percentages": smoke_pct,
            "total": smoke_total,
        },
        "full_eval": {
            "counts": full_labels,
            "percentages": full_pct,
            "total": full_total,
        },
        "differences": {
            label: {
                "absolute_diff": smoke_labels.get(label, 0) - full_labels.get(label, 0),
                "percentage_diff": smoke_pct.get(label, 0.0) - full_pct.get(label, 0.0),
            }
            for label in set(list(smoke_labels.keys()) + list(full_labels.keys()))
        },
    }


def analyze_category_distribution(
    smoke_results: List[Dict[str, Any]], full_results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Analyze category distribution differences.

    Args:
        smoke_results: Smoke test results
        full_results: Full evaluation results

    Returns:
        Dictionary with category distribution analysis
    """

    def get_categories(results: List[Dict[str, Any]]) -> Dict[str, int]:
        categories = defaultdict(int)
        for r in results:
            category = r.get("category", "unknown")
            if category:
                categories[category] += 1
        return dict(categories)

    smoke_cats = get_categories(smoke_results)
    full_cats = get_categories(full_results)

    smoke_total = len(smoke_results)
    full_total = len(full_results)

    smoke_pct = {
        cat: count / smoke_total if smoke_total > 0 else 0.0
        for cat, count in smoke_cats.items()
    }
    full_pct = {
        cat: count / full_total if full_total > 0 else 0.0
        for cat, count in full_cats.items()
    }

    # Calculate differences for top categories in smoke test
    all_categories = set(list(smoke_cats.keys()) + list(full_cats.keys()))
    differences = {}

    for cat in all_categories:
        smoke_count = smoke_cats.get(cat, 0)
        full_count = full_cats.get(cat, 0)
        smoke_p = smoke_pct.get(cat, 0.0)
        full_p = full_pct.get(cat, 0.0)

        differences[cat] = {
            "smoke_count": smoke_count,
            "smoke_percentage": smoke_p,
            "full_count": full_count,
            "full_percentage": full_p,
            "percentage_difference": smoke_p - full_p,
        }

    # Sort by percentage difference (absolute)
    sorted_diffs = sorted(
        differences.items(),
        key=lambda x: abs(x[1]["percentage_difference"]),
        reverse=True,
    )

    return {
        "smoke_test_categories": smoke_cats,
        "full_eval_categories": full_cats,
        "differences_by_category": dict(sorted_diffs),
        "top_differences": [
            {"category": cat, **data} for cat, data in sorted_diffs[:10]
        ],
    }


def analyze_p_correct_distribution(
    smoke_results: List[Dict[str, Any]],
    full_results: List[Dict[str, Any]],
    label_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyze p_correct distribution differences.

    Args:
        smoke_results: Smoke test results
        full_results: Full evaluation results
        label_filter: Optional label to filter by ('redteam' or 'benign')

    Returns:
        Dictionary with p_correct distribution analysis
    """

    def extract_p_correct(
        results: List[Dict[str, Any]], label: Optional[str] = None
    ) -> List[float]:
        p_values = []
        for r in results:
            if label and r.get("item_type", "").lower() != label.lower():
                continue

            # Try multiple paths to find p_correct
            p_correct = None
            metadata = r.get("metadata", {})

            # Path 1: answer_policy.p_correct
            answer_policy = metadata.get("answer_policy", {})
            if "p_correct" in answer_policy:
                p_correct = answer_policy["p_correct"]

            # Path 2: Direct in metadata
            if p_correct is None and "p_correct" in metadata:
                p_correct = metadata["p_correct"]

            # Path 3: Direct in result
            if p_correct is None and "p_correct" in r:
                p_correct = r["p_correct"]

            if p_correct is not None:
                try:
                    p_values.append(float(p_correct))
                except (ValueError, TypeError):
                    continue

        return p_values

    def compute_stats(values: List[float]) -> Dict[str, float]:
        if not values:
            return {}

        sorted_vals = sorted(values)
        n = len(values)

        return {
            "count": n,
            "min": min(values),
            "max": max(values),
            "mean": sum(values) / n,
            "median": sorted_vals[n // 2] if n > 0 else 0.0,
            "std": (
                (sum((x - sum(values) / n) ** 2 for x in values) / n) ** 0.5
                if n > 0
                else 0.0
            ),
        }

    smoke_redteam_p = extract_p_correct(
        smoke_results,
        "redteam" if not label_filter or label_filter == "redteam" else None,
    )
    full_redteam_p = extract_p_correct(
        full_results,
        "redteam" if not label_filter or label_filter == "redteam" else None,
    )

    smoke_benign_p = extract_p_correct(
        smoke_results,
        "benign" if not label_filter or label_filter == "benign" else None,
    )
    full_benign_p = extract_p_correct(
        full_results, "benign" if not label_filter or label_filter == "benign" else None
    )

    result = {}

    if smoke_redteam_p and full_redteam_p:
        result["redteam"] = {
            "smoke_test": compute_stats(smoke_redteam_p),
            "full_eval": compute_stats(full_redteam_p),
        }

        # Statistical test (t-test approximation)
        if len(smoke_redteam_p) > 1 and len(full_redteam_p) > 1:
            try:
                from scipy import stats

                t_stat, p_value = stats.ttest_ind(
                    smoke_redteam_p, full_redteam_p, equal_var=False
                )
                result["redteam"]["statistical_test"] = {
                    "t_statistic": float(t_stat),
                    "p_value": float(p_value),
                    "significant_at_5pct": p_value < 0.05,
                }
            except ImportError:
                result["redteam"]["statistical_test"] = {
                    "error": "scipy not available for statistical test",
                }

    if smoke_benign_p and full_benign_p:
        result["benign"] = {
            "smoke_test": compute_stats(smoke_benign_p),
            "full_eval": compute_stats(full_benign_p),
        }

        # Statistical test
        if len(smoke_benign_p) > 1 and len(full_benign_p) > 1:
            try:
                from scipy import stats

                t_stat, p_value = stats.ttest_ind(
                    smoke_benign_p, full_benign_p, equal_var=False
                )
                result["benign"]["statistical_test"] = {
                    "t_statistic": float(t_stat),
                    "p_value": float(p_value),
                    "significant_at_5pct": p_value < 0.05,
                }
            except ImportError:
                result["benign"]["statistical_test"] = {
                    "error": "scipy not available for statistical test",
                }

    return result


def generate_recommendations(analysis: Dict[str, Any]) -> List[str]:
    """
    Generate recommendations based on analysis.

    Args:
        analysis: Complete analysis dictionary

    Returns:
        List of recommendation strings
    """
    recommendations = []

    # Category distribution bias
    category_diff = analysis.get("category_distribution", {})
    top_diffs = category_diff.get("top_differences", [])

    if top_diffs:
        significant_bias = [
            d for d in top_diffs if abs(d.get("percentage_difference", 0)) > 0.10
        ]
        if significant_bias:
            recommendations.append(
                f"Smoke test has significant category bias: {len(significant_bias)} categories differ by >10%. "
                "This indicates the smoke test sample was not representative of the full dataset."
            )

    # Label distribution bias
    label_diff = analysis.get("label_distribution", {})
    label_diffs = label_diff.get("differences", {})

    for label, diff in label_diffs.items():
        pct_diff = abs(diff.get("percentage_difference", 0))
        if pct_diff > 0.10:
            recommendations.append(
                f"Label distribution bias: {label} differs by {pct_diff:.1%} between smoke test and full evaluation. "
                "Smoke test sample composition is not representative."
            )

    # p_correct distribution differences
    p_correct_analysis = analysis.get("p_correct_distribution", {})

    if "redteam" in p_correct_analysis:
        redteam_stats = p_correct_analysis["redteam"]
        stat_test = redteam_stats.get("statistical_test", {})
        if stat_test.get("significant_at_5pct", False):
            recommendations.append(
                "Redteam p_correct distributions are significantly different (p < 0.05). "
                "The model behaves differently on the two datasets, indicating sample bias."
            )

    if "benign" in p_correct_analysis:
        benign_stats = p_correct_analysis["benign"]
        stat_test = benign_stats.get("statistical_test", {})
        if stat_test.get("significant_at_5pct", False):
            recommendations.append(
                "Benign p_correct distributions are significantly different (p < 0.05). "
                "The model behaves differently on the two datasets, indicating sample bias."
            )

    # General recommendations
    smoke_count = analysis.get("dataset_composition", {}).get("smoke_test_items", 0)
    if smoke_count < 100:
        recommendations.append(
            f"Smoke test sample size ({smoke_count} items) is too small for reliable performance estimation. "
            "Use smoke tests only for sanity checks (catastrophic failures), not for performance metrics."
        )

    recommendations.append(
        "All performance claims must be based on full, representative dataset evaluation with proper statistical validation."
    )

    return recommendations


def main():
    parser = argparse.ArgumentParser(
        description="Analyze discrepancies between smoke test and full evaluation results"
    )
    parser.add_argument(
        "--smoke-results",
        type=str,
        required=True,
        help="Path to smoke test results JSONL file",
    )
    parser.add_argument(
        "--full-results",
        type=str,
        required=True,
        help="Path to full evaluation results JSONL file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to output JSON file (default: print to stdout)",
    )
    parser.add_argument(
        "--num-workers",
        type=int,
        default=None,
        help="Number of parallel workers (auto-detected if not specified)",
    )

    args = parser.parse_args()

    # Auto-detect optimal worker count if not specified
    if args.num_workers is None:
        if HAS_CPU_OPT:
            cpu_info = detect_cpu_info()
            args.num_workers = get_optimal_worker_count(cpu_info, task_type="io_bound")
        else:
            args.num_workers = min(20, (os.cpu_count() or 4) - 2)

    smoke_path = Path(args.smoke_results)
    full_path = Path(args.full_results)

    if not smoke_path.exists():
        print(
            f"Error: Smoke test results file not found: {smoke_path}", file=sys.stderr
        )
        sys.exit(1)

    if not full_path.exists():
        print(
            f"Error: Full evaluation results file not found: {full_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Load results
    print(f"Loading smoke test results from {smoke_path}...")
    smoke_results = load_results(smoke_path)
    print(f"Loaded {len(smoke_results)} smoke test results")

    print(f"Loading full evaluation results from {full_path}...")
    full_results = load_results(full_path)
    print(f"Loaded {len(full_results)} full evaluation results")

    # Perform analysis
    print(f"Analyzing discrepancies with {args.num_workers} workers...")

    analysis = {
        "dataset_composition": analyze_dataset_composition(smoke_results, full_results),
        "label_distribution": analyze_label_distribution(smoke_results, full_results),
        "category_distribution": analyze_category_distribution(
            smoke_results, full_results
        ),
        "p_correct_distribution": analyze_p_correct_distribution(
            smoke_results, full_results
        ),
    }

    # Generate recommendations
    analysis["recommendations"] = generate_recommendations(analysis)

    # Output results
    output_json = json.dumps(analysis, indent=2, ensure_ascii=False, default=str)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"\nAnalysis saved to {output_path}")

        # Print summary
        print("\n" + "=" * 70)
        print("DISCREPANCY ANALYSIS SUMMARY")
        print("=" * 70)

        comp = analysis["dataset_composition"]
        print(f"Smoke Test Items: {comp['smoke_test_items']}")
        print(f"Full Eval Items: {comp['full_eval_items']}")
        print(f"Ratio: {comp['ratio']:.1f}x")

        label_dist = analysis["label_distribution"]
        print("\nLabel Distribution:")
        for label in ["redteam", "benign"]:
            smoke_pct = label_dist["smoke_test"]["percentages"].get(label, 0.0)
            full_pct = label_dist["full_eval"]["percentages"].get(label, 0.0)
            diff = (
                label_dist["differences"]
                .get(label, {})
                .get("percentage_difference", 0.0)
            )
            print(
                f"  {label}: Smoke {smoke_pct:.1%} vs Full {full_pct:.1%} (diff: {diff:+.2%})"
            )

        if analysis.get("recommendations"):
            print("\nRecommendations:")
            for i, rec in enumerate(analysis["recommendations"], 1):
                print(f"  {i}. {rec}")
    else:
        print(output_json)


if __name__ == "__main__":
    import os

    main()
