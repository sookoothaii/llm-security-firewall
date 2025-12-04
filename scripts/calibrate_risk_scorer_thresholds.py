#!/usr/bin/env python3
"""
Risk Scorer Threshold Calibration
==================================

Calibrates risk scorer thresholds to optimize ASR/FPR trade-off based on
experiment results. Supports threshold sweep and optimal threshold selection.

This script helps address the root cause identified in evaluation: improving
risk scorer thresholds to reduce false positives while maintaining security.

Usage:
    python scripts/calibrate_risk_scorer_thresholds.py \
        --results logs/experiment_results.jsonl \
        --output analysis/threshold_calibration.json \
        --min-threshold 0.0 \
        --max-threshold 1.0 \
        --step 0.01

Author: Joerg Bollwahn
Date: 2025-12-04
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Any, Optional

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

# Auto-detect optimal worker count
if HAS_CPU_OPT:
    try:
        cpu_info = detect_cpu_info()
        if cpu_info.get("detected_model") == "Intel Core i9-12900HX":
            optimal = get_optimal_settings_for_i9_12900hx()
            DEFAULT_WORKERS = optimal["threshold_sweep_workers"]
        else:
            DEFAULT_WORKERS = get_optimal_worker_count(cpu_info, task_type="cpu_bound")
    except Exception:
        DEFAULT_WORKERS = 16  # Safe default for threshold sweep (CPU-bound)
else:
    try:
        import multiprocessing

        cpu_count = multiprocessing.cpu_count() or 4
        DEFAULT_WORKERS = max(1, min(16, cpu_count - 2))
    except Exception:
        DEFAULT_WORKERS = 8


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


def evaluate_threshold(
    results: List[Dict[str, Any]], threshold: float, risk_score_key: str = "risk_score"
) -> Dict[str, Any]:
    """
    Evaluate performance metrics at a given threshold.

    Args:
        results: List of experiment result dictionaries
        threshold: Risk score threshold (block if risk_score >= threshold)
        risk_score_key: Key to use for risk score (default: 'risk_score')

    Returns:
        Dictionary with performance metrics
    """
    tp = 0  # True Positive: redteam blocked
    fn = 0  # False Negative: redteam allowed
    fp = 0  # False Positive: benign blocked
    tn = 0  # True Negative: benign allowed

    for result in results:
        item_type = result.get("item_type", "").lower()
        risk_score = result.get(risk_score_key, 0.0)

        if risk_score is None:
            risk_score = 0.0

        blocked = risk_score >= threshold

        if item_type == "redteam":
            if blocked:
                tp += 1
            else:
                fn += 1
        elif item_type == "benign":
            if blocked:
                fp += 1
            else:
                tn += 1

    # Calculate metrics
    total_redteam = tp + fn
    total_benign = fp + tn

    asr = fn / total_redteam if total_redteam > 0 else 0.0  # Attack Success Rate
    fpr = fp / total_benign if total_benign > 0 else 0.0  # False Positive Rate
    tpr = (
        tp / total_redteam if total_redteam > 0 else 0.0
    )  # True Positive Rate (Detection Rate)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tpr
    f1 = (
        2 * (precision * recall) / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "threshold": threshold,
        "asr": asr,
        "fpr": fpr,
        "tpr": tpr,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fn": fn,
        "fp": fp,
        "tn": tn,
        "total_redteam": total_redteam,
        "total_benign": total_benign,
    }


def sweep_thresholds(
    results: List[Dict[str, Any]],
    min_threshold: float = 0.0,
    max_threshold: float = 1.0,
    step: float = 0.01,
    risk_score_key: str = "risk_score",
    num_workers: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Perform threshold sweep and evaluate performance at each threshold.
    Parallelized for performance on multi-core systems.

    Args:
        results: List of experiment result dictionaries
        min_threshold: Minimum threshold to test
        max_threshold: Maximum threshold to test
        step: Step size for threshold sweep
        risk_score_key: Key to use for risk score
        num_workers: Number of parallel workers (auto-detected if None)

    Returns:
        List of evaluation results for each threshold
    """
    # Generate list of thresholds to test
    thresholds_to_test = []
    current = min_threshold
    while current <= max_threshold:
        thresholds_to_test.append(round(current, 3))
        current += step
        current = round(current, 3)  # Avoid floating point errors

    num_thresholds = len(thresholds_to_test)

    # Use parallel processing if we have multiple thresholds and workers > 1
    if num_workers is None:
        num_workers = DEFAULT_WORKERS

    if num_thresholds < 10 or num_workers <= 1:
        # Sequential processing for small sweeps
        thresholds = []
        for thresh in thresholds_to_test:
            metrics = evaluate_threshold(results, thresh, risk_score_key)
            thresholds.append(metrics)
        return thresholds

    # Parallel processing
    thresholds = [None] * num_thresholds  # Pre-allocate list

    def evaluate_single_threshold(index_and_thresh):
        """Evaluate single threshold - worker function."""
        index, thresh = index_and_thresh
        metrics = evaluate_threshold(results, thresh, risk_score_key)
        return index, metrics

    print(
        f"  Parallelizing threshold sweep with {num_workers} workers ({num_thresholds} thresholds)..."
    )

    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Submit all tasks
        futures = {
            executor.submit(evaluate_single_threshold, (i, thresh)): i
            for i, thresh in enumerate(thresholds_to_test)
        }

        # Collect results
        completed = 0
        for future in as_completed(futures):
            try:
                index, metrics = future.result()
                thresholds[index] = metrics
                completed += 1

                # Progress indicator
                if (
                    completed % max(1, num_thresholds // 20) == 0
                    or completed == num_thresholds
                ):
                    print(
                        f"    Evaluated {completed}/{num_thresholds} thresholds... ({completed * 100 // num_thresholds}%)",
                        end="\r",
                    )
            except Exception as e:
                print(f"\nWarning: Error evaluating threshold: {e}", file=sys.stderr)

    print()  # New line after progress indicator

    # Filter out None values (shouldn't happen, but safety check)
    thresholds = [t for t in thresholds if t is not None]

    return thresholds


def find_optimal_threshold(
    threshold_results: List[Dict[str, Any]],
    objective: str = "f1",
    max_fpr: Optional[float] = None,
    max_asr: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """
    Find optimal threshold based on specified objective.

    Args:
        threshold_results: List of threshold evaluation results
        objective: Optimization objective ('f1', 'balanced', 'min_fpr', 'min_asr')
        max_fpr: Optional maximum acceptable FPR
        max_asr: Optional maximum acceptable ASR

    Returns:
        Optimal threshold result or None
    """
    # Filter by constraints
    candidates = threshold_results

    if max_fpr is not None:
        candidates = [r for r in candidates if r["fpr"] <= max_fpr]

    if max_asr is not None:
        candidates = [r for r in candidates if r["asr"] <= max_asr]

    if not candidates:
        return None

    # Find optimal based on objective
    if objective == "f1":
        optimal = max(candidates, key=lambda x: x["f1"])
    elif objective == "balanced":
        # Minimize distance to (ASR=0, FPR=0) in normalized space
        optimal = min(candidates, key=lambda x: (x["asr"] ** 2 + x["fpr"] ** 2) ** 0.5)
    elif objective == "min_fpr":
        optimal = min(candidates, key=lambda x: x["fpr"])
    elif objective == "min_asr":
        optimal = min(candidates, key=lambda x: x["asr"])
    else:
        optimal = max(candidates, key=lambda x: x["f1"])  # Default to F1

    return optimal


def generate_calibration_report(
    threshold_results: List[Dict[str, Any]],
    optimal_threshold: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generate comprehensive calibration report.

    Args:
        threshold_results: List of threshold evaluation results
        optimal_threshold: Optional optimal threshold result

    Returns:
        Dictionary with calibration report
    """
    # Find key thresholds
    fpr_5pct_thresholds = [r for r in threshold_results if r["fpr"] <= 0.05]
    fpr_1pct_thresholds = [r for r in threshold_results if r["fpr"] <= 0.01]
    asr_10pct_thresholds = [r for r in threshold_results if r["asr"] <= 0.10]

    # Find best F1 score
    best_f1 = max(threshold_results, key=lambda x: x["f1"])

    # Find balanced point (min distance to origin)
    balanced = min(
        threshold_results, key=lambda x: (x["asr"] ** 2 + x["fpr"] ** 2) ** 0.5
    )

    report = {
        "threshold_sweep_summary": {
            "total_thresholds_tested": len(threshold_results),
            "threshold_range": {
                "min": min(r["threshold"] for r in threshold_results),
                "max": max(r["threshold"] for r in threshold_results),
            },
        },
        "key_thresholds": {
            "best_f1_score": {
                "threshold": best_f1["threshold"],
                "asr": best_f1["asr"],
                "fpr": best_f1["fpr"],
                "f1": best_f1["f1"],
            },
            "balanced_optimal": {
                "threshold": balanced["threshold"],
                "asr": balanced["asr"],
                "fpr": balanced["fpr"],
            },
        },
    }

    if fpr_5pct_thresholds:
        best_fpr_5 = max(fpr_5pct_thresholds, key=lambda x: x["tpr"])
        report["key_thresholds"]["fpr_5pct_constraint"] = {
            "threshold": best_fpr_5["threshold"],
            "asr": best_fpr_5["asr"],
            "fpr": best_fpr_5["fpr"],
            "tpr": best_fpr_5["tpr"],
        }

    if fpr_1pct_thresholds:
        best_fpr_1 = max(fpr_1pct_thresholds, key=lambda x: x["tpr"])
        report["key_thresholds"]["fpr_1pct_constraint"] = {
            "threshold": best_fpr_1["threshold"],
            "asr": best_fpr_1["asr"],
            "fpr": best_fpr_1["fpr"],
            "tpr": best_fpr_1["tpr"],
        }

    if optimal_threshold:
        report["recommended_threshold"] = {
            "threshold": optimal_threshold["threshold"],
            "asr": optimal_threshold["asr"],
            "fpr": optimal_threshold["fpr"],
            "tpr": optimal_threshold["tpr"],
            "f1": optimal_threshold["f1"],
            "rationale": "Based on specified optimization objective and constraints",
        }

    return report


def main():
    parser = argparse.ArgumentParser(
        description="Calibrate risk scorer thresholds to optimize ASR/FPR trade-off"
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
        "--min-threshold",
        type=float,
        default=0.0,
        help="Minimum threshold to test (default: 0.0)",
    )
    parser.add_argument(
        "--max-threshold",
        type=float,
        default=1.0,
        help="Maximum threshold to test (default: 1.0)",
    )
    parser.add_argument(
        "--step",
        type=float,
        default=0.01,
        help="Step size for threshold sweep (default: 0.01)",
    )
    parser.add_argument(
        "--objective",
        type=str,
        default="balanced",
        choices=["f1", "balanced", "min_fpr", "min_asr"],
        help="Optimization objective (default: balanced)",
    )
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=None,
        help="Maximum acceptable false positive rate (constraint)",
    )
    parser.add_argument(
        "--max-asr",
        type=float,
        default=None,
        help="Maximum acceptable attack success rate (constraint)",
    )
    parser.add_argument(
        "--risk-score-key",
        type=str,
        default="risk_score",
        help="Key to use for risk score in results (default: risk_score)",
    )
    parser.add_argument(
        "--num-workers",
        type=int,
        default=None,
        help=f"Number of parallel workers for threshold sweep (default: auto-detect, optimal: {DEFAULT_WORKERS})",
    )

    args = parser.parse_args()

    # Use auto-detected default workers if not specified
    num_workers = args.num_workers if args.num_workers is not None else DEFAULT_WORKERS
    if args.num_workers is None:
        print(f"Using auto-detected optimal worker count: {num_workers}")

    results_path = Path(args.results)
    if not results_path.exists():
        print(f"Error: Results file not found: {results_path}", file=sys.stderr)
        sys.exit(1)

    # Load results
    print(f"Loading results from {results_path}...")
    results = load_experiment_results(results_path)
    print(f"Loaded {len(results)} results")

    # Count items
    redteam_count = sum(
        1 for r in results if r.get("item_type", "").lower() == "redteam"
    )
    benign_count = sum(1 for r in results if r.get("item_type", "").lower() == "benign")
    print(f"Redteam items: {redteam_count}, Benign items: {benign_count}")

    # Perform threshold sweep
    print(
        f"Performing threshold sweep from {args.min_threshold} to {args.max_threshold} (step: {args.step})..."
    )
    threshold_results = sweep_thresholds(
        results,
        min_threshold=args.min_threshold,
        max_threshold=args.max_threshold,
        step=args.step,
        risk_score_key=args.risk_score_key,
        num_workers=num_workers,
    )
    print(f"Evaluated {len(threshold_results)} thresholds")

    # Find optimal threshold
    optimal_threshold = find_optimal_threshold(
        threshold_results,
        objective=args.objective,
        max_fpr=args.max_fpr,
        max_asr=args.max_asr,
    )

    if optimal_threshold:
        print(
            f"\nOptimal threshold (objective: {args.objective}): {optimal_threshold['threshold']:.3f}"
        )
        print(f"  ASR: {optimal_threshold['asr']:.1%}")
        print(f"  FPR: {optimal_threshold['fpr']:.1%}")
        print(f"  F1:  {optimal_threshold['f1']:.3f}")
    else:
        print("\nWarning: No optimal threshold found with specified constraints")

    # Generate report
    report = generate_calibration_report(threshold_results, optimal_threshold)

    # Prepare output
    output = {
        "calibration_report": report,
        "threshold_sweep_results": threshold_results,
        "optimal_threshold": optimal_threshold,
    }

    output_json = json.dumps(output, indent=2, ensure_ascii=False, default=str)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"\nCalibration results saved to {output_path}")

        # Print summary
        print("\n" + "=" * 70)
        print("THRESHOLD CALIBRATION SUMMARY")
        print("=" * 70)
        print(
            f"Best F1 Score Threshold: {report['key_thresholds']['best_f1_score']['threshold']:.3f}"
        )
        print(
            f"  ASR: {report['key_thresholds']['best_f1_score']['asr']:.1%}, FPR: {report['key_thresholds']['best_f1_score']['fpr']:.1%}"
        )
        print(
            f"\nBalanced Optimal Threshold: {report['key_thresholds']['balanced_optimal']['threshold']:.3f}"
        )
        print(
            f"  ASR: {report['key_thresholds']['balanced_optimal']['asr']:.1%}, FPR: {report['key_thresholds']['balanced_optimal']['fpr']:.1%}"
        )

        if "fpr_5pct_constraint" in report["key_thresholds"]:
            print(
                f"\nFPR < 5% Constraint Threshold: {report['key_thresholds']['fpr_5pct_constraint']['threshold']:.3f}"
            )
            print(
                f"  ASR: {report['key_thresholds']['fpr_5pct_constraint']['asr']:.1%}, FPR: {report['key_thresholds']['fpr_5pct_constraint']['fpr']:.1%}"
            )
    else:
        print(output_json)


if __name__ == "__main__":
    main()
