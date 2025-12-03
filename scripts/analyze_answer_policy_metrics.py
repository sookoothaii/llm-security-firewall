"""
AnswerPolicy Metrics Analysis Script
===================================

Offline analysis tool for AnswerPolicy behavior from decision logs.

Reads JSONL files containing FirewallDecision records and computes:
- Global counts (enabled/disabled, policy usage)
- Per-policy statistics (refusal rate, block rate, p_correct distribution)
- Histogram summaries (p_correct bins vs. decision mode)

Usage:
    python scripts/analyze_answer_policy_metrics.py --input logs/decisions.jsonl
    python scripts/analyze_answer_policy_metrics.py --input logs/decisions.jsonl --output-csv metrics/summary.csv

Author: Joerg Bollwahn
Date: 2025-12-02
License: MIT
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev, median
from typing import Dict, List, Optional, Any


def parse_jsonl(file_path: Path) -> List[Dict[str, Any]]:
    """
    Parse JSONL file into list of decision records.

    Args:
        file_path: Path to JSONL file

    Returns:
        List of decision dictionaries

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file contains invalid JSON
    """
    decisions = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                decision = json.loads(line)
                decisions.append(decision)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON on line {line_num} of {file_path}: {e}")
    return decisions


def extract_answer_policy_metadata(
    decision: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Extract AnswerPolicy metadata from decision record.

    Args:
        decision: Decision dictionary

    Returns:
        AnswerPolicy metadata dict or None if missing
    """
    metadata = decision.get("metadata", {})
    return metadata.get("answer_policy")


def analyze_decisions(decisions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze decisions and compute metrics.

    Args:
        decisions: List of decision dictionaries

    Returns:
        Dictionary containing computed metrics
    """
    # Global counts
    total = len(decisions)
    enabled_count = 0
    disabled_count = 0
    missing_metadata_count = 0

    # Latency tracking
    latency_values = []

    # Per-policy statistics
    policy_stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "answer_count": 0,
            "silence_count": 0,
            "blocked_count": 0,
            "blocked_by_answer_policy": 0,
            "blocked_by_other": 0,
            "p_correct_values": [],
            "threshold_values": [],
        }
    )

    # Histogram buckets: [0-0.2], (0.2-0.4], (0.4-0.6], (0.6-0.8], (0.8-1.0]
    histogram: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"answer": 0, "silence": 0}
    )

    for decision in decisions:
        allowed = decision.get("allowed", True)
        reason = decision.get("reason", "")

        # Extract AnswerPolicy metadata
        ap_meta = extract_answer_policy_metadata(decision)

        if ap_meta is None:
            missing_metadata_count += 1
            continue

        enabled = ap_meta.get("enabled", False)
        if enabled:
            enabled_count += 1
        else:
            disabled_count += 1

        policy_name = ap_meta.get("policy_name")
        if policy_name is None:
            policy_name = "None"

        mode = ap_meta.get("mode")
        p_correct = ap_meta.get("p_correct")
        threshold = ap_meta.get("threshold")

        # Update policy statistics
        stats = policy_stats[policy_name]
        stats["count"] += 1

        if mode == "answer":
            stats["answer_count"] += 1
        elif mode == "silence":
            stats["silence_count"] += 1

        if not allowed:
            stats["blocked_count"] += 1
            # Block source attribution: AnswerPolicy vs. other safety layers
            # Heuristic: Check if reason contains "Epistemic gate" or mode is "silence"
            is_answer_policy_block = mode == "silence" or "Epistemic gate" in reason
            if is_answer_policy_block:
                stats["blocked_by_answer_policy"] += 1
            else:
                stats["blocked_by_other"] += 1

        if p_correct is not None:
            stats["p_correct_values"].append(p_correct)

            # Update histogram
            if p_correct <= 0.2:
                bucket = "[0.0-0.2]"
            elif p_correct <= 0.4:
                bucket = "(0.2-0.4]"
            elif p_correct <= 0.6:
                bucket = "(0.4-0.6]"
            elif p_correct <= 0.8:
                bucket = "(0.6-0.8]"
            else:
                bucket = "(0.8-1.0]"

            if mode == "answer":
                histogram[bucket]["answer"] += 1
            elif mode == "silence":
                histogram[bucket]["silence"] += 1

        if threshold is not None:
            stats["threshold_values"].append(threshold)

        # Extract latency if available
        metadata = decision.get("metadata", {})
        timing = metadata.get("timing", {})
        elapsed_ms = timing.get("elapsed_ms")
        if elapsed_ms is not None:
            latency_values.append(elapsed_ms)

    # Compute latency statistics
    latency_stats = {}
    if latency_values:
        latency_stats = {
            "count": len(latency_values),
            "mean_ms": mean(latency_values),
            "median_ms": median(latency_values),
            "min_ms": min(latency_values),
            "max_ms": max(latency_values),
        }
        # Approximate 95th percentile
        sorted_latencies = sorted(latency_values)
        p95_index = int(len(sorted_latencies) * 0.95)
        if p95_index < len(sorted_latencies):
            latency_stats["p95_ms"] = sorted_latencies[p95_index]
        else:
            latency_stats["p95_ms"] = sorted_latencies[-1] if sorted_latencies else None

    # Compute per-policy aggregates
    policy_aggregates = {}
    for policy_name, stats in policy_stats.items():
        count = stats["count"]
        if count == 0:
            continue

        answer_pct = (stats["answer_count"] / count * 100) if count > 0 else 0.0
        silence_pct = (stats["silence_count"] / count * 100) if count > 0 else 0.0
        block_rate = (stats["blocked_count"] / count * 100) if count > 0 else 0.0
        ap_block_rate = (
            (stats["blocked_by_answer_policy"] / count * 100) if count > 0 else 0.0
        )

        p_correct_mean = (
            mean(stats["p_correct_values"]) if stats["p_correct_values"] else None
        )
        p_correct_std = (
            stdev(stats["p_correct_values"])
            if len(stats["p_correct_values"]) > 1
            else None
        )

        threshold_mean = (
            mean(stats["threshold_values"]) if stats["threshold_values"] else None
        )
        threshold_std = (
            stdev(stats["threshold_values"])
            if len(stats["threshold_values"]) > 1
            else None
        )

        policy_aggregates[policy_name] = {
            "count": count,
            "answer_count": stats["answer_count"],
            "answer_percentage": answer_pct,
            "silence_count": stats["silence_count"],
            "silence_percentage": silence_pct,
            "blocked_count": stats["blocked_count"],
            "block_rate": block_rate,
            "blocked_by_answer_policy": stats["blocked_by_answer_policy"],
            "answer_policy_block_rate": ap_block_rate,
            "blocked_by_other": stats["blocked_by_other"],
            "p_correct_mean": p_correct_mean,
            "p_correct_std": p_correct_std,
            "threshold_mean": threshold_mean,
            "threshold_std": threshold_std,
        }

    return {
        "global": {
            "total": total,
            "enabled": enabled_count,
            "disabled": disabled_count,
            "missing_metadata": missing_metadata_count,
        },
        "policies": policy_aggregates,
        "histogram": dict(histogram),
        "latency": latency_stats,
    }


def print_summary(metrics: Dict[str, Any]) -> None:
    """Print formatted summary to stdout."""
    print("=" * 70)
    print("AnswerPolicy Metrics Summary")
    print("=" * 70)

    # Global counts
    global_stats = metrics["global"]
    print("\nGlobal Statistics:")
    print(f"  Total decisions: {global_stats['total']}")
    print(f"  AnswerPolicy enabled: {global_stats['enabled']}")
    print(f"  AnswerPolicy disabled: {global_stats['disabled']}")
    print(f"  Missing metadata: {global_stats['missing_metadata']}")

    # Per-policy statistics
    print("\nPer-Policy Statistics:")
    print("-" * 70)
    for policy_name, stats in sorted(metrics["policies"].items()):
        print(f"\nPolicy: {policy_name}")
        print(f"  Count: {stats['count']}")
        print(
            f"  Mode 'answer': {stats['answer_count']} ({stats['answer_percentage']:.1f}%)"
        )
        print(
            f"  Mode 'silence': {stats['silence_count']} ({stats['silence_percentage']:.1f}%)"
        )
        print(f"  Total blocked: {stats['blocked_count']} ({stats['block_rate']:.1f}%)")
        print(
            f"  Blocked by AnswerPolicy: {stats['blocked_by_answer_policy']} "
            f"({stats['answer_policy_block_rate']:.1f}%)"
        )
        print(f"  Blocked by other reasons: {stats['blocked_by_other']}")

        if stats["p_correct_mean"] is not None:
            print(f"  p_correct: mean={stats['p_correct_mean']:.3f}", end="")
            if stats["p_correct_std"] is not None:
                print(f", std={stats['p_correct_std']:.3f}")
            else:
                print()

        if stats["threshold_mean"] is not None:
            print(f"  threshold: mean={stats['threshold_mean']:.3f}", end="")
            if stats["threshold_std"] is not None:
                print(f", std={stats['threshold_std']:.3f}")
            else:
                print()

    # Histogram
    print("\nHistogram: p_correct Distribution vs. Decision Mode")
    print("-" * 70)
    print(f"{'Bucket':<15} {'Answer':<15} {'Silence':<15}")
    print("-" * 70)
    for bucket in ["[0.0-0.2]", "(0.2-0.4]", "(0.4-0.6]", "(0.6-0.8]", "(0.8-1.0]"]:
        counts = metrics["histogram"].get(bucket, {"answer": 0, "silence": 0})
        print(f"{bucket:<15} {counts['answer']:<15} {counts['silence']:<15}")

    # Latency statistics
    latency = metrics.get("latency", {})
    if latency:
        print("\nLatency Statistics:")
        print(f"  Count: {latency.get('count', 0)}")
        print(f"  Mean: {latency.get('mean_ms', 0):.2f} ms")
        print(f"  Median: {latency.get('median_ms', 0):.2f} ms")
        print(f"  Min: {latency.get('min_ms', 0):.2f} ms")
        print(f"  Max: {latency.get('max_ms', 0):.2f} ms")
        if latency.get("p95_ms") is not None:
            print(f"  95th percentile: {latency.get('p95_ms', 0):.2f} ms")

    print("=" * 70)


def export_csv(metrics: Dict[str, Any], output_path: Path) -> None:
    """
    Export per-policy aggregates to CSV.

    Args:
        metrics: Metrics dictionary
        output_path: Path to output CSV file
    """
    import csv

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Header
        writer.writerow(
            [
                "policy_name",
                "count",
                "answer_count",
                "answer_percentage",
                "silence_count",
                "silence_percentage",
                "blocked_count",
                "block_rate",
                "blocked_by_answer_policy",
                "answer_policy_block_rate",
                "blocked_by_other",
                "p_correct_mean",
                "p_correct_std",
                "threshold_mean",
                "threshold_std",
            ]
        )

        # Data rows
        for policy_name, stats in sorted(metrics["policies"].items()):
            writer.writerow(
                [
                    policy_name,
                    stats["count"],
                    stats["answer_count"],
                    f"{stats['answer_percentage']:.2f}",
                    stats["silence_count"],
                    f"{stats['silence_percentage']:.2f}",
                    stats["blocked_count"],
                    f"{stats['block_rate']:.2f}",
                    stats["blocked_by_answer_policy"],
                    f"{stats['answer_policy_block_rate']:.2f}",
                    stats["blocked_by_other"],
                    f"{stats['p_correct_mean']:.3f}"
                    if stats["p_correct_mean"] is not None
                    else "",
                    f"{stats['p_correct_std']:.3f}"
                    if stats["p_correct_std"] is not None
                    else "",
                    f"{stats['threshold_mean']:.3f}"
                    if stats["threshold_mean"] is not None
                    else "",
                    f"{stats['threshold_std']:.3f}"
                    if stats["threshold_std"] is not None
                    else "",
                ]
            )

    print(f"\nCSV exported to: {output_path}")


def analyze_file(input_path: Path) -> Dict[str, Any]:
    """
    Analyze decisions from JSONL file.

    Args:
        input_path: Path to input JSONL file

    Returns:
        Metrics dictionary
    """
    decisions = parse_jsonl(input_path)
    return analyze_decisions(decisions)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze AnswerPolicy metrics from decision logs (JSONL format)"
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Input JSONL file containing decision records",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        default=None,
        help="Optional: Export per-policy aggregates to CSV file",
    )

    args = parser.parse_args()

    # Validate input file
    if not args.input.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        return 1

    try:
        # Analyze
        metrics = analyze_file(args.input)

        # Print summary
        print_summary(metrics)

        # Export CSV if requested
        if args.output_csv:
            export_csv(metrics, args.output_csv)

        return 0

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
