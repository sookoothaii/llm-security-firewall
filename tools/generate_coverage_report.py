"""
Defense Coverage Report Generator
==================================

Parses test logs and generates coverage matrix with ASR/FPR/Latency metrics.

Usage:
    python tools/generate_coverage_report.py --test-log pytest_output.txt --output coverage_report.json
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List


def parse_test_results(test_log_path: str) -> Dict:
    """
    Parse pytest output to extract test results.

    Args:
        test_log_path: Path to pytest output file

    Returns:
        Dict with test statistics
    """
    stats = {
        "total_tests": 0,
        "passed": 0,
        "failed": 0,
        "success_rate": 0.0,
        "timestamp": datetime.now().isoformat(),
    }

    try:
        with open(test_log_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Parse pytest summary line
        # Example: "197 passed in 40.58s"
        import re

        match = re.search(r"(\d+)\s+passed", content)
        if match:
            stats["passed"] = int(match.group(1))
            stats["total_tests"] = stats["passed"]

        failed_match = re.search(r"(\d+)\s+failed", content)
        if failed_match:
            stats["failed"] = int(failed_match.group(1))
            stats["total_tests"] += stats["failed"]

        if stats["total_tests"] > 0:
            stats["success_rate"] = stats["passed"] / stats["total_tests"]

    except Exception as e:
        print(f"Warning: Could not parse test log: {e}")

    return stats


def load_coverage_matrix(csv_path: str) -> List[Dict]:
    """Load coverage matrix from CSV."""
    matrix = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            matrix.append(row)

    return matrix


def compute_aggregates(matrix: List[Dict]) -> Dict:
    """Compute aggregate metrics from coverage matrix."""
    total_attacks = len(set(row["Attack_Class"] for row in matrix))
    total_defenses = len(set(row["Defense_Layer"] for row in matrix))

    # Parse percentages
    asr_reductions = []
    fpr_impacts = []
    latencies = []

    for row in matrix:
        try:
            asr = float(row["ASR_Reduction"].rstrip("%"))
            asr_reductions.append(asr)
        except (ValueError, KeyError, AttributeError):
            pass

        try:
            fpr = float(row["FPR_Impact"].rstrip("%"))
            fpr_impacts.append(fpr)
        except (ValueError, KeyError, AttributeError):
            pass

        try:
            lat = float(row["Latency_Delta_ms"])
            latencies.append(lat)
        except (ValueError, KeyError):
            pass

    return {
        "total_attack_classes": total_attacks,
        "total_defense_layers": total_defenses,
        "total_mappings": len(matrix),
        "avg_asr_reduction": sum(asr_reductions) / len(asr_reductions)
        if asr_reductions
        else 0.0,
        "avg_fpr_impact": sum(fpr_impacts) / len(fpr_impacts) if fpr_impacts else 0.0,
        "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0.0,
        "max_latency_ms": max(latencies) if latencies else 0.0,
    }


def generate_report(matrix_path: str, test_log_path: str, output_path: str):
    """
    Generate comprehensive coverage report.

    Args:
        matrix_path: Path to coverage_matrix.csv
        test_log_path: Path to pytest output
        output_path: Path for output JSON
    """
    print("=== Defense Coverage Report Generator ===\n")

    # Load data
    print("Loading coverage matrix...")
    matrix = load_coverage_matrix(matrix_path)
    print(f"  Loaded {len(matrix)} attack-defense mappings")

    print("\nParsing test results...")
    test_stats = parse_test_results(test_log_path)
    print(
        f"  Tests: {test_stats['passed']}/{test_stats['total_tests']} passed ({test_stats['success_rate'] * 100:.1f}%)"
    )

    print("\nComputing aggregates...")
    aggregates = compute_aggregates(matrix)
    print(f"  Attack classes: {aggregates['total_attack_classes']}")
    print(f"  Defense layers: {aggregates['total_defense_layers']}")
    print(f"  Avg ASR reduction: {aggregates['avg_asr_reduction']:.1f}%")
    print(f"  Avg FPR impact: {aggregates['avg_fpr_impact']:.1f}%")
    print(f"  Avg latency: {aggregates['avg_latency_ms']:.1f}ms")

    # Build report
    report = {
        "version": "2025-10-28",
        "timestamp": datetime.now().isoformat(),
        "test_results": test_stats,
        "coverage_aggregates": aggregates,
        "attack_defense_matrix": matrix,
        "slos": {
            "asr_at_0_1_percent": 10.0,  # Target: ≤ 10%
            "promotion_fpr": 1.0,  # Target: ≤ 1%
            "ece": 0.05,  # Target: ≤ 0.05
            "time_to_detect_min": 15,  # Target: ≤ 15min
            "time_to_contain_min": 30,  # Target: ≤ 30min
        },
        "status": "PRODUCTION_READY"
        if test_stats["success_rate"] >= 0.97
        else "NEEDS_REVIEW",
    }

    # Write report
    print(f"\nWriting report to {output_path}...")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("✓ Report generated successfully")
    print(f"\nStatus: {report['status']}")

    return report


def main():
    """Main entry point."""
    ap = argparse.ArgumentParser(
        description="Generate Defense Coverage Report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    ap.add_argument(
        "--matrix",
        default="monitoring/defense_coverage_matrix.csv",
        help="Path to coverage matrix CSV",
    )
    ap.add_argument(
        "--test-log", default="pytest_output.txt", help="Path to pytest output log"
    )
    ap.add_argument(
        "--output",
        default="defense_coverage_report.json",
        help="Path for output JSON report",
    )

    args = ap.parse_args()

    # Check files exist
    if not Path(args.matrix).exists():
        print(f"ERROR: Matrix file not found: {args.matrix}")
        return 1

    if not Path(args.test_log).exists():
        print(f"Warning: Test log not found: {args.test_log}")
        print("Using empty test stats...")

    # Generate report
    generate_report(
        matrix_path=args.matrix, test_log_path=args.test_log, output_path=args.output
    )

    return 0


if __name__ == "__main__":
    exit(main())
