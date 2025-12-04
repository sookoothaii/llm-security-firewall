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


def analyze_evidence_based_metrics(decisions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze extended metadata from evidence-based AnswerPolicy decisions.

    Compares Dempster-Shafer vs. heuristic, analyzes CUSUM impact, and evidence correlations.

    Args:
        decisions: List of decision dictionaries

    Returns:
        Dictionary containing evidence-based analysis
    """
    # Filter decisions where Dempster-Shafer was used
    ds_decisions = []
    heuristic_decisions = []

    for d in decisions:
        ap_meta = d.get("metadata", {}).get("answer_policy", {})
        method = ap_meta.get("p_correct_method", "heuristic")
        if method == "dempster_shafer":
            ds_decisions.append(d)
        elif method == "heuristic":
            heuristic_decisions.append(d)

    if not ds_decisions:
        return {
            "evidence_based_count": 0,
            "heuristic_count": len(heuristic_decisions),
            "message": "No evidence-based decisions found in the log.",
        }

    # 1. p_correct Distribution Comparison
    p_correct_ds = [d["metadata"]["answer_policy"]["p_correct"] for d in ds_decisions]
    p_correct_heuristic_sim = []
    for d in ds_decisions:
        ap_meta = d["metadata"]["answer_policy"]
        evidence_masses = ap_meta.get("evidence_masses", {})
        # Try to extract risk_scorer from evidence_masses
        if isinstance(evidence_masses, dict):
            risk_scorer = evidence_masses.get("risk_scorer", {})
            if isinstance(risk_scorer, dict):
                # If it's a dict with promote/quarantine, use quarantine
                risk_value = risk_scorer.get("quarantine", 0.0)
            else:
                risk_value = float(risk_scorer) if risk_scorer else 0.0
        else:
            risk_value = 0.0
        # Simulate heuristic: p_correct = 1 - risk_score
        p_correct_heuristic_sim.append(max(0.0, min(1.0, 1.0 - risk_value)))

    # 2. CUSUM Influence Analysis
    cusum_influenced = []
    cusum_high_count = 0
    for d in ds_decisions:
        ap_meta = d["metadata"]["answer_policy"]
        evidence_masses = ap_meta.get("evidence_masses", {})
        if isinstance(evidence_masses, dict):
            cusum_info = evidence_masses.get("cusum_drift", {})
            if isinstance(cusum_info, dict):
                cusum_quarantine = cusum_info.get("quarantine", 0.0)
            else:
                cusum_quarantine = float(cusum_info) if cusum_info else 0.0
        else:
            cusum_quarantine = 0.0

        # Normalize: cusum_quarantine is already [0,1], but we check if > 0.5
        if cusum_quarantine > 0.5:
            cusum_high_count += 1
            if ap_meta.get("mode") == "silence":
                cusum_influenced.append(
                    {
                        "item_id": d.get("item_id"),
                        "cusum_quarantine": cusum_quarantine,
                        "belief_quarantine": ap_meta.get("belief_quarantine", 0.0),
                        "p_correct": ap_meta.get("p_correct", 0.0),
                    }
                )

    # 3. Evidence Correlation Analysis
    silence_evidences = []
    answer_evidences = []

    for d in ds_decisions:
        ap_meta = d["metadata"]["answer_policy"]
        evidence_masses = ap_meta.get("evidence_masses", {})
        mode = ap_meta.get("mode")

        # Extract risk_scorer and cusum_drift values
        risk_value = 0.0
        cusum_value = 0.0

        if isinstance(evidence_masses, dict):
            risk_info = evidence_masses.get("risk_scorer", {})
            if isinstance(risk_info, dict):
                risk_value = risk_info.get("quarantine", 0.0)
            else:
                risk_value = float(risk_info) if risk_info else 0.0

            cusum_info = evidence_masses.get("cusum_drift", {})
            if isinstance(cusum_info, dict):
                cusum_value = cusum_info.get("quarantine", 0.0)
            else:
                cusum_value = float(cusum_info) if cusum_info else 0.0

        evidence_entry = {"risk_scorer": risk_value, "cusum_drift": cusum_value}

        if mode == "silence":
            silence_evidences.append(evidence_entry)
        elif mode == "answer":
            answer_evidences.append(evidence_entry)

    def avg_evidence(ev_list, key):
        """Helper to compute average evidence value."""
        vals = [e.get(key, 0.0) for e in ev_list]
        return mean(vals) if vals else 0.0

    return {
        "evidence_based_count": len(ds_decisions),
        "heuristic_count": len(heuristic_decisions),
        "p_correct_comparison": {
            "dempster_shafer": {
                "count": len(p_correct_ds),
                "mean": mean(p_correct_ds) if p_correct_ds else None,
                "min": min(p_correct_ds) if p_correct_ds else None,
                "max": max(p_correct_ds) if p_correct_ds else None,
            },
            "heuristic_simulated": {
                "count": len(p_correct_heuristic_sim),
                "mean": mean(p_correct_heuristic_sim)
                if p_correct_heuristic_sim
                else None,
                "min": min(p_correct_heuristic_sim)
                if p_correct_heuristic_sim
                else None,
                "max": max(p_correct_heuristic_sim)
                if p_correct_heuristic_sim
                else None,
            },
        },
        "cusum_analysis": {
            "high_cusum_count": cusum_high_count,
            "high_cusum_with_silence": len(cusum_influenced),
            "avg_cusum_in_silence": mean(
                [c["cusum_quarantine"] for c in cusum_influenced]
            )
            if cusum_influenced
            else None,
            "avg_belief_in_silence": mean(
                [c["belief_quarantine"] for c in cusum_influenced]
            )
            if cusum_influenced
            else None,
        },
        "evidence_correlations": {
            "silence_decisions": {
                "count": len(silence_evidences),
                "avg_risk_scorer": avg_evidence(silence_evidences, "risk_scorer"),
                "avg_cusum_drift": avg_evidence(silence_evidences, "cusum_drift"),
            },
            "answer_decisions": {
                "count": len(answer_evidences),
                "avg_risk_scorer": avg_evidence(answer_evidences, "risk_scorer"),
                "avg_cusum_drift": avg_evidence(answer_evidences, "cusum_drift"),
            },
        },
    }


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

    # Evidence-based analysis
    evidence_metrics = analyze_evidence_based_metrics(decisions)

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
        "evidence_based": evidence_metrics,
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

    # Evidence-based analysis
    evidence = metrics.get("evidence_based", {})
    if evidence and evidence.get("evidence_based_count", 0) > 0:
        print("\n" + "=" * 70)
        print("Evidence-Based AnswerPolicy Analysis")
        print("=" * 70)
        print(f"\nEvidence-based decisions: {evidence.get('evidence_based_count', 0)}")
        print(f"Heuristic decisions: {evidence.get('heuristic_count', 0)}")

        # p_correct comparison
        p_comp = evidence.get("p_correct_comparison", {})
        if p_comp:
            print("\n1. p_correct Distribution Comparison:")
            ds_stats = p_comp.get("dempster_shafer", {})
            heur_stats = p_comp.get("heuristic_simulated", {})
            if ds_stats.get("count", 0) > 0:
                print(f"   Dempster-Shafer (n={ds_stats['count']}):")
                print(
                    f"     avg={ds_stats.get('mean', 0):.3f}, "
                    f"min={ds_stats.get('min', 0):.3f}, "
                    f"max={ds_stats.get('max', 0):.3f}"
                )
            if heur_stats.get("count", 0) > 0:
                print(f"   Heuristic (simulated, n={heur_stats['count']}):")
                print(
                    f"     avg={heur_stats.get('mean', 0):.3f}, "
                    f"min={heur_stats.get('min', 0):.3f}, "
                    f"max={heur_stats.get('max', 0):.3f}"
                )

        # CUSUM analysis
        cusum = evidence.get("cusum_analysis", {})
        if cusum:
            print("\n2. CUSUM Influence Analysis:")
            print(f"   Decisions with CUSUM > 0.5: {cusum.get('high_cusum_count', 0)}")
            print(
                f"   Of which resulted in 'silence': {cusum.get('high_cusum_with_silence', 0)}"
            )
            if cusum.get("avg_cusum_in_silence") is not None:
                print(
                    f"   Avg CUSUM score in these cases: {cusum['avg_cusum_in_silence']:.3f}"
                )
            if cusum.get("avg_belief_in_silence") is not None:
                print(
                    f"   Avg belief_quarantine in these cases: {cusum['avg_belief_in_silence']:.3f}"
                )

        # Evidence correlations
        corr = evidence.get("evidence_correlations", {})
        if corr:
            print("\n3. Average Evidence Masses by Decision:")
            silence = corr.get("silence_decisions", {})
            answer = corr.get("answer_decisions", {})
            if silence.get("count", 0) > 0:
                print(f"   'silence' decisions (n={silence['count']}):")
                print(f"     - risk_scorer: {silence.get('avg_risk_scorer', 0):.3f}")
                print(f"     - cusum_drift: {silence.get('avg_cusum_drift', 0):.3f}")
            if answer.get("count", 0) > 0:
                print(f"   'answer' decisions (n={answer['count']}):")
                print(f"     - risk_scorer: {answer.get('avg_risk_scorer', 0):.3f}")
                print(f"     - cusum_drift: {answer.get('avg_cusum_drift', 0):.3f}")

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
