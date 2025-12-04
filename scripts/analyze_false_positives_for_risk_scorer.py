#!/usr/bin/env python3
"""
False Positive Analysis for Risk Scorer Improvement
====================================================

Analyzes false positive cases from experiment results to identify patterns and
improve risk scorer thresholds, category floors, and model logic.

This script addresses the root cause identified in the evidence-based AnswerPolicy
evaluation: the upstream risk scorer is the primary source of error, contributing
significantly to false positives.

Usage:
    python scripts/analyze_false_positives_for_risk_scorer.py \
        --results logs/experiment_results.jsonl \
        --output analysis/false_positive_analysis.json

Author: Joerg Bollwahn
Date: 2025-12-04
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any

# Add src directory to path
base_dir = Path(__file__).parent.parent
src_dir = base_dir / "src"
if src_dir.exists():
    sys.path.insert(0, str(src_dir))

# Try to import CPU optimization for optimal worker count
scripts_dir = Path(__file__).parent
try:
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    from cpu_optimization import (
        get_optimal_worker_count,
        detect_cpu_info,
        get_optimal_settings_for_i9_12900hx,
    )

    HAS_CPU_OPT = True
except ImportError:
    HAS_CPU_OPT = False

# Auto-detect optimal worker count for analysis (I/O-bound)
if HAS_CPU_OPT:
    try:
        cpu_info = detect_cpu_info()
        if cpu_info.get("detected_model") == "Intel Core i9-12900HX":
            optimal = get_optimal_settings_for_i9_12900hx()
            DEFAULT_WORKERS = optimal["analysis_workers"]
        else:
            DEFAULT_WORKERS = get_optimal_worker_count(cpu_info, task_type="io_bound")
    except Exception:
        DEFAULT_WORKERS = 20  # Safe default for analysis (I/O-bound)
else:
    try:
        import multiprocessing

        cpu_count = multiprocessing.cpu_count() or 4
        DEFAULT_WORKERS = max(1, min(20, cpu_count - 2))
    except Exception:
        DEFAULT_WORKERS = 8

try:
    import llm_firewall.risk.risk_scorer  # noqa: F401

    HAS_RISK_SCORER = True
except ImportError:
    HAS_RISK_SCORER = False
    print(
        "Warning: Risk scorer not available. Analysis will be limited.", file=sys.stderr
    )


def load_experiment_results(filepath: Path) -> List[Dict[str, Any]]:
    """Load experiment results from JSONL file."""
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


def identify_false_positives(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify false positive cases: benign items that were blocked.

    Args:
        results: List of experiment result dictionaries

    Returns:
        List of false positive cases with detailed metadata
    """
    false_positives = []

    for result in results:
        item_type = result.get("item_type", "").lower()
        allowed = result.get("allowed", True)

        # False positive: benign item that was blocked
        if item_type == "benign" and not allowed:
            fp_case = {
                "item_id": result.get("item_id", "unknown"),
                "item_type": item_type,
                "prompt": result.get("sanitized_text", result.get("prompt", "")),
                "risk_score": result.get("risk_score", 0.0),
                "base_risk_score": result.get("metadata", {})
                .get("answer_policy", {})
                .get("base_risk_score", 0.0),
                "reason": result.get("reason", "unknown"),
                "detected_threats": result.get("detected_threats", []),
                "metadata": result.get("metadata", {}),
            }
            false_positives.append(fp_case)

    return false_positives


def analyze_risk_score_distribution(
    false_positives: List[Dict[str, Any]], all_benign: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Analyze risk score distribution for false positives vs. all benign items.

    Args:
        false_positives: List of false positive cases
        all_benign: List of all benign items from experiment

    Returns:
        Dictionary with distribution statistics
    """
    fp_risk_scores = [
        fp.get("risk_score", 0.0)
        for fp in false_positives
        if fp.get("risk_score") is not None
    ]
    all_benign_risk_scores = [
        item.get("risk_score", 0.0)
        for item in all_benign
        if item.get("risk_score") is not None
    ]

    if not fp_risk_scores or not all_benign_risk_scores:
        return {"error": "Insufficient data for distribution analysis"}

    def compute_stats(scores: List[float]) -> Dict[str, float]:
        if not scores:
            return {}
        return {
            "min": min(scores),
            "max": max(scores),
            "mean": sum(scores) / len(scores),
            "median": sorted(scores)[len(scores) // 2],
        }

    return {
        "false_positives": {
            "count": len(fp_risk_scores),
            **compute_stats(fp_risk_scores),
        },
        "all_benign": {
            "count": len(all_benign_risk_scores),
            **compute_stats(all_benign_risk_scores),
        },
        "threshold_analysis": {
            "suggested_threshold_for_95pct_fp_prevention": sorted(fp_risk_scores)[
                int(len(fp_risk_scores) * 0.95)
            ]
            if fp_risk_scores
            else None,
            "suggested_threshold_for_99pct_fp_prevention": sorted(fp_risk_scores)[
                int(len(fp_risk_scores) * 0.99)
            ]
            if fp_risk_scores
            else None,
        },
    }


def analyze_category_patterns(false_positives: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze which threat categories are most frequently triggered in false positives.

    Args:
        false_positives: List of false positive cases

    Returns:
        Dictionary with category frequency analysis
    """
    category_counts = defaultdict(int)
    category_items = defaultdict(list)

    for fp in false_positives:
        detected_threats = fp.get("detected_threats", [])
        if not detected_threats:
            # Try to extract from metadata
            metadata = fp.get("metadata", {})
            risk_scorer_meta = metadata.get("risk_scorer", {})
            categories = risk_scorer_meta.get("by_category", {})

            for category, value in categories.items():
                if value > 0:
                    category_counts[category] += 1
                    category_items[category].append(fp["item_id"])
        else:
            # Count categories from detected threats
            for threat in detected_threats:
                if isinstance(threat, dict):
                    category = threat.get("category", "unknown")
                elif isinstance(threat, str):
                    category = threat
                else:
                    category = "unknown"

                category_counts[category] += 1
                if fp["item_id"] not in category_items[category]:
                    category_items[category].append(fp["item_id"])

    # Sort by frequency
    sorted_categories = sorted(
        category_counts.items(), key=lambda x: x[1], reverse=True
    )

    return {
        "category_frequencies": dict(sorted_categories),
        "items_by_category": {cat: items for cat, items in category_items.items()},
        "top_categories": [cat for cat, count in sorted_categories[:10]],
    }


def analyze_floor_contributions(
    false_positives: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Analyze which category floors contribute most to false positives.

    This helps identify if specific category floors (jailbreak, evasion, etc.)
    are too aggressive for benign content.

    Args:
        false_positives: List of false positive cases

    Returns:
        Dictionary with floor contribution analysis
    """
    floor_contributions = defaultdict(
        lambda: {"count": 0, "avg_score": 0.0, "items": []}
    )

    for fp in false_positives:
        metadata = fp.get("metadata", {})
        risk_scorer_meta = metadata.get("risk_scorer", {})
        categories = risk_scorer_meta.get("by_category", {})

        # Check which category floors might have fired
        floor_categories = [
            "jailbreak_instruction_bypass",
            "obfuscation_encoding",
            "unicode_evasion",
            "information_extraction_sensitive",
            "capability_escalation",
        ]

        for category in floor_categories:
            if categories.get(category, 0) > 0:
                floor_contributions[category]["count"] += 1
                floor_contributions[category]["items"].append(fp["item_id"])

                # Track average category score
                if "scores" not in floor_contributions[category]:
                    floor_contributions[category]["scores"] = []
                floor_contributions[category]["scores"].append(
                    categories.get(category, 0)
                )

    # Compute averages
    for category, data in floor_contributions.items():
        if data.get("scores"):
            data["avg_score"] = sum(data["scores"]) / len(data["scores"])
            del data["scores"]

    # Sort by count
    sorted_floors = sorted(
        floor_contributions.items(), key=lambda x: x[1]["count"], reverse=True
    )

    return {
        "floor_contributions": {cat: data for cat, data in sorted_floors},
        "top_contributing_floors": [cat for cat, _ in sorted_floors[:5]],
    }


def generate_recommendations(analysis: Dict[str, Any]) -> List[str]:
    """
    Generate actionable recommendations based on analysis results.

    Args:
        analysis: Complete analysis dictionary

    Returns:
        List of recommendation strings
    """
    recommendations = []

    # Risk score threshold recommendations
    threshold_analysis = analysis.get("risk_score_distribution", {}).get(
        "threshold_analysis", {}
    )
    suggested_95 = threshold_analysis.get("suggested_threshold_for_95pct_fp_prevention")
    suggested_99 = threshold_analysis.get("suggested_threshold_for_99pct_fp_prevention")

    if suggested_95:
        recommendations.append(
            f"Consider raising risk score threshold to {suggested_95:.3f} to prevent 95% of false positives. "
            "This would require re-evaluation of true positive rate impact."
        )

    # Category floor recommendations
    top_categories = analysis.get("category_patterns", {}).get("top_categories", [])
    if top_categories:
        recommendations.append(
            f"Top false positive categories: {', '.join(top_categories)}. "
            "Consider reviewing category detection logic or floor values for these categories."
        )

    # Floor contribution recommendations
    top_floors = analysis.get("floor_contributions", {}).get(
        "top_contributing_floors", []
    )
    if top_floors:
        recommendations.append(
            f"Category floors contributing most to false positives: {', '.join(top_floors)}. "
            "Consider lowering floor values or tightening category detection logic."
        )

    # General recommendations
    fp_count = analysis.get("summary", {}).get("false_positive_count", 0)
    total_benign = analysis.get("summary", {}).get("total_benign_count", 0)

    if fp_count > 0 and total_benign > 0:
        fpr = fp_count / total_benign
        recommendations.append(
            f"Current false positive rate: {fpr:.1%} ({fp_count}/{total_benign}). "
            "Target FPR for production should typically be <5%."
        )

    return recommendations


def main():
    parser = argparse.ArgumentParser(
        description="Analyze false positives to improve risk scorer thresholds and logic"
    )
    parser.add_argument(
        "--results",
        type=str,
        required=True,
        help="Path to experiment results JSONL file",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Path to output JSON file (default: print to stdout)",
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Include detailed item-level analysis in output",
    )
    parser.add_argument(
        "--num-workers",
        type=int,
        default=None,
        help=f"Number of parallel workers for analysis (default: auto-detect, optimal: {DEFAULT_WORKERS})",
    )

    args = parser.parse_args()

    results_path = Path(args.results)
    if not results_path.exists():
        print(f"Error: Results file not found: {results_path}", file=sys.stderr)
        sys.exit(1)

    # Load results
    print(f"Loading results from {results_path}...")
    results = load_experiment_results(results_path)

    # Use auto-detected default workers if not specified (for future parallelization)
    num_workers = args.num_workers if args.num_workers is not None else DEFAULT_WORKERS
    if (
        args.num_workers is None and len(results) > 1000
    ):  # Only show if we have large dataset
        print(
            f"Using auto-detected optimal worker count: {num_workers} (for future parallelization)"
        )
    print(f"Loaded {len(results)} results")

    # Separate benign items
    all_benign = [r for r in results if r.get("item_type", "").lower() == "benign"]
    print(f"Found {len(all_benign)} benign items")

    # Identify false positives
    false_positives = identify_false_positives(results)
    print(f"Identified {len(false_positives)} false positives")

    if not false_positives:
        print("No false positives found. Nothing to analyze.")
        sys.exit(0)

    # Perform analysis
    print("Analyzing false positives...")
    analysis = {
        "summary": {
            "total_items": len(results),
            "total_benign_count": len(all_benign),
            "false_positive_count": len(false_positives),
            "false_positive_rate": len(false_positives) / len(all_benign)
            if all_benign
            else 0.0,
        },
        "risk_score_distribution": analyze_risk_score_distribution(
            false_positives, all_benign
        ),
        "category_patterns": analyze_category_patterns(false_positives),
        "floor_contributions": analyze_floor_contributions(false_positives),
    }

    if args.detailed:
        analysis["false_positives"] = false_positives

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

        # Also print summary to console
        print("\n" + "=" * 70)
        print("FALSE POSITIVE ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"False Positive Rate: {analysis['summary']['false_positive_rate']:.1%}")
        print(
            f"False Positives: {analysis['summary']['false_positive_count']}/{analysis['summary']['total_benign_count']}"
        )

        if analysis.get("category_patterns", {}).get("top_categories"):
            print("\nTop Categories in False Positives:")
            for cat, count in list(
                analysis["category_patterns"]["category_frequencies"].items()
            )[:5]:
                print(f"  {cat}: {count}")

        if analysis.get("recommendations"):
            print("\nRecommendations:")
            for i, rec in enumerate(analysis["recommendations"], 1):
                print(f"  {i}. {rec}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
