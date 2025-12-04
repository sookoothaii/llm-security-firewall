"""
Threshold Sensitivity Analysis for Evidence-Based AnswerPolicy
==============================================================

Automated threshold sweep to find optimal threshold for evidence-based
AnswerPolicy that balances ASR and FPR.

Usage:
    python scripts/threshold_sweep.py \
        --dataset datasets/core_suite_smoke.jsonl \
        --policy kids \
        --thresholds 0.85,0.90,0.93,0.95,0.97,0.98 \
        --output-dir logs/threshold_sweep

Author: Joerg Bollwahn / AI Assistant
Date: 2025-12-03
License: MIT
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Any

# Add src directory to path
base_dir = Path(__file__).parent.parent
src_dir = base_dir / "src"
if src_dir.exists():
    sys.path.insert(0, str(src_dir))

try:
    from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2
    from llm_firewall.core.policy_provider import PolicyProvider
    from llm_firewall.core.decision_policy import AnswerPolicy
    from llm_firewall.fusion.dempster_shafer import DempsterShaferFusion

    HAS_FIREWALL = True
except ImportError as e:
    HAS_FIREWALL = False
    print(f"Error: FirewallEngineV2 not available: {e}", file=sys.stderr)
    sys.exit(1)


def create_policy_with_threshold(
    base_policy_name: str, target_threshold: float
) -> AnswerPolicy:
    """
    Create AnswerPolicy with specific threshold.

    Threshold formula: threshold = (C - A) / (C + B)
    Where:
        C = cost_wrong
        A = cost_silence
        B = benefit_correct

    For a given threshold, we fix B=1.0 and A=0.0, then solve for C:
        threshold = C / (C + 1.0)
        threshold * (C + 1.0) = C
        threshold * C + threshold = C
        threshold = C - threshold * C
        threshold = C * (1 - threshold)
        C = threshold / (1 - threshold)

    Args:
        base_policy_name: Base policy name (e.g., "kids")
        target_threshold: Desired threshold value (0.0-1.0)

    Returns:
        AnswerPolicy instance with the specified threshold
    """
    # Get base policy to copy other attributes
    from llm_firewall.core.decision_policy import get_policy

    base_policy = get_policy(base_policy_name)

    # Calculate cost_wrong to achieve target threshold
    # Assuming benefit_correct=1.0 and cost_silence=0.0
    if target_threshold >= 1.0:
        cost_wrong = 1000.0  # Very high cost to force threshold near 1.0
    elif target_threshold <= 0.0:
        cost_wrong = 0.0  # Very low cost to force threshold near 0.0
    else:
        cost_wrong = target_threshold / (1.0 - target_threshold)

    # Create new policy with adjusted cost_wrong
    policy = AnswerPolicy(
        benefit_correct=base_policy.benefit_correct,
        cost_wrong=cost_wrong,
        cost_silence=base_policy.cost_silence,
        policy_name=f"{base_policy_name}_threshold_{int(target_threshold * 100)}",
    )

    # Verify threshold
    actual_threshold = policy.threshold()
    if abs(actual_threshold - target_threshold) > 0.01:
        print(
            f"Warning: Target threshold {target_threshold:.3f} != actual {actual_threshold:.3f}",
            file=sys.stderr,
        )

    return policy


def decision_to_dict(decision, item_id: str, item_type: str) -> Dict[str, Any]:
    """Convert FirewallDecision to dictionary."""
    return {
        "item_id": item_id,
        "item_type": item_type,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "metadata": decision.metadata or {},
    }


def process_single_item(
    item: Dict[str, str],
    policy: AnswerPolicy,
    use_evidence_based: bool,
    tenant_id: str,
) -> Dict[str, Any]:
    """Process a single item through firewall."""
    # Initialize engine with evidence-based fusion if requested
    try:
        dempster_fuser = DempsterShaferFusion() if use_evidence_based else None
        # Test different stretch factors (can be made configurable)
        stretch_factor = 3.0  # Increased from 2.0 for better distribution

        engine = FirewallEngineV2(
            dempster_shafer_fuser=dempster_fuser,
            use_evidence_based_p_correct=use_evidence_based,
            p_correct_stretch_factor=stretch_factor,
        )
    except Exception:
        engine = FirewallEngineV2()

    # Create policy provider with custom policy
    provider = PolicyProvider()
    provider.add_policy(policy)

    try:
        decision = engine.process_input(
            text=item["prompt"],
            user_id=f"user_{item.get('id', 'unknown')}",
            tenant_id=tenant_id,
            route="/api/test",
            use_answer_policy=True,
            policy_provider=provider,
        )

        return decision_to_dict(
            decision,
            item_id=item.get("id", "unknown"),
            item_type=item.get("type", "unknown"),
        )
    except Exception as e:
        return {
            "item_id": item.get("id", "unknown"),
            "item_type": item.get("type", "unknown"),
            "error": str(e),
            "allowed": False,
            "reason": f"Processing error: {e}",
            "risk_score": 1.0,
            "metadata": {},
        }


def collect_metrics(
    decisions: List[Dict[str, Any]], dataset: List[Dict[str, Any]]
) -> Dict[str, float]:
    """
    Calculate ASR and FPR from decisions and dataset.

    Args:
        decisions: List of decision dictionaries
        dataset: Original dataset with item types

    Returns:
        Dictionary with ASR, FPR, and counts
    """
    # Create lookup dict
    dataset_dict = {d["id"]: d for d in dataset}

    # Count redteam and benign
    redteam_allowed = 0
    redteam_total = 0
    benign_blocked = 0
    benign_total = 0

    for decision in decisions:
        item_id = decision.get("item_id")
        if not item_id:
            continue

        item_data = dataset_dict.get(item_id, {})
        item_type = item_data.get("type", decision.get("item_type", "unknown"))

        if item_type == "redteam":
            redteam_total += 1
            if decision.get("allowed", False):
                redteam_allowed += 1
        elif item_type == "benign":
            benign_total += 1
            if not decision.get("allowed", False):
                benign_blocked += 1

    asr = redteam_allowed / redteam_total if redteam_total > 0 else 0.0
    fpr = benign_blocked / benign_total if benign_total > 0 else 0.0

    return {
        "asr": asr,
        "fpr": fpr,
        "redteam_allowed": redteam_allowed,
        "redteam_total": redteam_total,
        "benign_blocked": benign_blocked,
        "benign_total": benign_total,
    }


def run_experiment_with_threshold(
    threshold: float,
    dataset: List[Dict[str, Any]],
    base_policy_name: str,
    use_evidence_based: bool,
    num_workers: int = 4,
) -> List[Dict[str, Any]]:
    """
    Run experiment with specific threshold.

    Args:
        threshold: Threshold value to test
        dataset: Dataset items
        base_policy_name: Base policy name
        use_evidence_based: Whether to use evidence-based p_correct
        num_workers: Number of parallel workers

    Returns:
        List of decision dictionaries
    """
    # Create policy with target threshold
    policy = create_policy_with_threshold(base_policy_name, threshold)
    tenant_id = f"tenant_threshold_{int(threshold * 100)}"

    decisions = []

    if num_workers > 1 and len(dataset) > 1:
        # Parallel processing
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [
                executor.submit(
                    process_single_item,
                    item,
                    policy,
                    use_evidence_based,
                    tenant_id,
                )
                for item in dataset
            ]

            for future in as_completed(futures):
                try:
                    decision = future.result()
                    decisions.append(decision)
                except Exception as e:
                    print(
                        f"Warning: Error in parallel processing: {e}", file=sys.stderr
                    )
    else:
        # Sequential processing
        for item in dataset:
            try:
                decision = process_single_item(
                    item, policy, use_evidence_based, tenant_id
                )
                decisions.append(decision)
            except Exception as e:
                print(f"Warning: Error processing item: {e}", file=sys.stderr)

    return decisions


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Threshold sensitivity analysis for AnswerPolicy"
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        required=True,
        help="Input JSONL dataset file",
    )
    parser.add_argument(
        "--policy",
        type=str,
        default="kids",
        help="Base policy name (default: kids)",
    )
    parser.add_argument(
        "--thresholds",
        type=str,
        default="0.85,0.90,0.93,0.95,0.97,0.98",
        help="Comma-separated list of thresholds to test (default: 0.85,0.90,0.93,0.95,0.97,0.98)",
    )
    parser.add_argument(
        "--use-evidence-based",
        action="store_true",
        help="Use evidence-based p_correct (Dempster-Shafer fusion)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("logs/threshold_sweep"),
        help="Output directory for logs and results (default: logs/threshold_sweep)",
    )
    parser.add_argument(
        "--num-workers",
        type=int,
        default=4,
        help="Number of parallel workers (default: 4)",
    )

    args = parser.parse_args()

    # Parse thresholds
    try:
        thresholds = [float(t.strip()) for t in args.thresholds.split(",")]
    except ValueError as e:
        print(f"Error: Invalid thresholds format: {e}", file=sys.stderr)
        return 1

    # Validate dataset
    if not args.dataset.exists():
        print(f"Error: Dataset file not found: {args.dataset}", file=sys.stderr)
        return 1

    # Load dataset
    dataset = []
    with open(args.dataset, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                dataset.append(item)
            except json.JSONDecodeError as e:
                print(f"Warning: Invalid JSON in dataset: {e}", file=sys.stderr)
                continue

    if not dataset:
        print("Error: No valid items in dataset", file=sys.stderr)
        return 1

    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("Threshold Sensitivity Analysis")
    print("=" * 70)
    print(f"Dataset: {args.dataset}")
    print(f"Policy: {args.policy}")
    print(f"Evidence-based: {args.use_evidence_based}")
    print(f"Thresholds: {thresholds}")
    print(f"Items: {len(dataset)}")
    print(f"Workers: {args.num_workers}")
    print("=" * 70)
    print()

    # Run experiments for each threshold
    results = []
    method_name = "evidence_based" if args.use_evidence_based else "heuristic"

    for threshold in thresholds:
        print(f"Testing threshold: {threshold:.3f}...", end=" ", flush=True)
        start_time = time.time()

        # Run experiment
        decisions = run_experiment_with_threshold(
            threshold=threshold,
            dataset=dataset,
            base_policy_name=args.policy,
            use_evidence_based=args.use_evidence_based,
            num_workers=args.num_workers,
        )

        # Calculate metrics
        metrics = collect_metrics(decisions, dataset)
        metrics["threshold"] = threshold
        metrics["method"] = method_name
        metrics["policy"] = args.policy

        # Save decisions log
        log_file = (
            args.output_dir / f"{method_name}_threshold_{int(threshold * 100)}.jsonl"
        )
        with open(log_file, "w", encoding="utf-8") as f:
            for decision in decisions:
                f.write(json.dumps(decision) + "\n")

        elapsed = time.time() - start_time
        print(f"ASR={metrics['asr']:.3f}, FPR={metrics['fpr']:.3f} ({elapsed:.1f}s)")

        results.append(metrics)

    # Save results summary
    results_file = args.output_dir / f"{method_name}_sweep_results.json"
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Print summary table
    print()
    print("=" * 70)
    print("Results Summary")
    print("=" * 70)
    print(f"{'Threshold':<12} {'ASR':<8} {'FPR':<8} {'Redteam':<12} {'Benign':<12}")
    print("-" * 70)
    for r in results:
        print(
            f"{r['threshold']:<12.3f} {r['asr']:<8.3f} {r['fpr']:<8.3f} "
            f"{r['redteam_allowed']}/{r['redteam_total']:<8} "
            f"{r['benign_blocked']}/{r['benign_total']:<8}"
        )

    print()
    print(f"Results saved to: {results_file}")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
