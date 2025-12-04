"""
Simple AnswerPolicy Experiment Runner (v0.2)
===========================================

Minimal script to run AnswerPolicy experiments on a dataset.
Generates decision logs for baseline and kids policy runs.
Supports parallel processing for large datasets.

Usage:
    python scripts/run_simple_experiment.py
    python scripts/run_simple_experiment.py --parallel --workers 8
    python scripts/run_simple_experiment.py --input datasets/mixed_expanded_500.jsonl

Output:
    - logs/baseline_mixed_small.jsonl
    - logs/kids_mixed_small.jsonl

Author: Joerg Bollwahn
Date: 2025-12-02
License: MIT
"""

import json
import sys
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict

# Add src directory to path for local development
base_dir = Path(__file__).parent.parent
src_dir = base_dir / "src"
if src_dir.exists():
    sys.path.insert(0, str(src_dir))

try:
    from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2
    from llm_firewall.core.policy_provider import PolicyProvider, get_default_provider

    HAS_FIREWALL = True
except ImportError as e:
    HAS_FIREWALL = False
    print(f"Error: FirewallEngineV2 not available: {e}", file=sys.stderr)
    sys.exit(1)


def decision_to_dict(decision) -> dict:
    """Convert FirewallDecision to dictionary for JSON serialization."""
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "sanitized_text": decision.sanitized_text,
        "detected_threats": decision.detected_threats or [],
        "metadata": decision.metadata or {},
    }


def process_single_item(
    item: Dict[str, str],
    policy_name: str,
    use_answer_policy: bool,
    tenant_id: str,
    provider,
) -> Dict:
    """
    Process a single item through firewall (for parallel processing).

    Args:
        item: Item dictionary with id, type, prompt
        policy_name: Policy name
        use_answer_policy: Whether AnswerPolicy is enabled
        tenant_id: Tenant ID
        provider: Policy provider (or None)

    Returns:
        Decision dictionary with item metadata
    """
    engine = FirewallEngineV2()

    try:
        decision = engine.process_input(
            text=item["prompt"],
            user_id=f"user_{item.get('id', 'unknown')}",
            tenant_id=tenant_id,
            route="/api/test",
            use_answer_policy=use_answer_policy,
            policy_provider=provider,
        )

        decision_dict = decision_to_dict(decision)
        decision_dict["item_id"] = item.get("id", "unknown")
        decision_dict["item_type"] = item.get("type", "unknown")

        return decision_dict
    except Exception as e:
        return {
            "item_id": item.get("id", "unknown"),
            "item_type": item.get("type", "unknown"),
            "error": str(e),
            "allowed": False,
            "reason": f"Processing error: {e}",
        }


def run_experiment(
    policy_name: str,
    use_answer_policy: bool,
    input_path: Path,
    output_path: Path,
    parallel: bool = False,
    workers: int = 4,
) -> None:
    """
    Run experiment with specified policy.

    Args:
        policy_name: Policy name ("default" or "kids")
        use_answer_policy: Whether to enable AnswerPolicy
        input_path: Path to input JSONL file
        output_path: Path to output JSONL file
        parallel: Whether to use parallel processing
        workers: Number of parallel workers (if parallel=True)
    """
    # Setup policy provider
    if use_answer_policy:
        if policy_name == "kids":
            provider = PolicyProvider(tenant_policy_map={"tenant_test": "kids"})
            tenant_id = "tenant_test"
        else:
            provider = get_default_provider()
            tenant_id = "tenant_default"
    else:
        provider = None
        tenant_id = "tenant_default"

    # Load all items
    items = []
    with open(input_path, "r", encoding="utf-8") as f_in:
        for line_num, line in enumerate(f_in, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
                items.append(item)
            except json.JSONDecodeError as e:
                print(f"Warning: Invalid JSON on line {line_num}: {e}", file=sys.stderr)
                continue

    print(
        f"Running experiment: policy={policy_name}, use_answer_policy={use_answer_policy}"
    )
    print(
        f"  Items: {len(items)}, Parallel: {parallel}, Workers: {workers if parallel else 1}"
    )

    decisions = []

    if parallel and len(items) > 10:
        # Parallel processing for large datasets
        print(f"  Using parallel processing with {workers} workers...")

        # Use ThreadPoolExecutor (I/O bound, shared engine state)
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(
                    process_single_item,
                    item,
                    policy_name,
                    use_answer_policy,
                    tenant_id,
                    provider,
                )
                for item in items
            ]

            completed = 0
            for future in as_completed(futures):
                try:
                    decision = future.result()
                    decisions.append(decision)
                    completed += 1

                    # Progress indicator
                    if completed % max(1, len(items) // 20) == 0:
                        print(
                            f"  Processed {completed}/{len(items)} items... ({completed * 100 // len(items)}%)",
                            end="\r",
                        )
                except Exception as e:
                    print(
                        f"Warning: Error in parallel processing: {e}", file=sys.stderr
                    )
                    continue

        print(f"\n  Completed: {len(decisions)} decisions processed")
    else:
        # Sequential processing (original code)
        engine = FirewallEngineV2()

        for item_num, item in enumerate(items, start=1):
            try:
                decision = engine.process_input(
                    text=item["prompt"],
                    user_id=f"user_{item.get('id', f'item_{item_num}')}",
                    tenant_id=tenant_id,
                    route="/api/test",
                    use_answer_policy=use_answer_policy,
                    policy_provider=provider,
                )

                decision_dict = decision_to_dict(decision)
                decision_dict["item_id"] = item.get("id", f"item_{item_num}")
                decision_dict["item_type"] = item.get("type", "unknown")

                decisions.append(decision_dict)

                # Progress indicator
                if item_num % max(1, len(items) // 20) == 0:
                    print(
                        f"  Processed {item_num}/{len(items)} items... ({item_num * 100 // len(items)}%)",
                        end="\r",
                    )

            except Exception as e:
                print(
                    f"Warning: Error processing item {item_num}: {e}", file=sys.stderr
                )
                continue

        print(f"\n  Completed: {len(decisions)} decisions processed")

    # Write output
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f_out:
        for decision in decisions:
            f_out.write(json.dumps(decision, ensure_ascii=False) + "\n")

    print(f"Completed: {len(decisions)} decisions written to {output_path}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run AnswerPolicy experiments")
    parser.add_argument(
        "--input",
        type=str,
        default=None,
        help="Input JSONL file (default: datasets/mixed_small.jsonl)",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Use parallel processing for large datasets",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of parallel workers (default: 4)",
    )
    parser.add_argument(
        "--baseline-only",
        action="store_true",
        help="Run only baseline experiment",
    )
    parser.add_argument(
        "--kids-only",
        action="store_true",
        help="Run only kids policy experiment",
    )

    args = parser.parse_args()

    # Paths
    base_dir = Path(__file__).parent.parent
    if args.input:
        input_path = Path(args.input)
    else:
        input_path = base_dir / "datasets" / "mixed_small.jsonl"
    logs_dir = base_dir / "logs"

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        print(f"Please create {input_path} with test prompts.", file=sys.stderr)
        return 1

    # Determine output filenames based on input
    input_stem = input_path.stem
    baseline_output = logs_dir / f"baseline_{input_stem}.jsonl"
    kids_output = logs_dir / f"kids_{input_stem}.jsonl"

    # Run baseline (no AnswerPolicy or default)
    if not args.kids_only:
        print("=" * 70)
        print("Experiment A: Baseline")
        print("=" * 70)
        run_experiment(
            policy_name="default",
            use_answer_policy=False,
            input_path=input_path,
            output_path=baseline_output,
            parallel=args.parallel,
            workers=args.workers,
        )

    # Run kids policy
    if not args.baseline_only:
        print("\n" + "=" * 70)
        print("Experiment B: Kids Policy")
        print("=" * 70)
        run_experiment(
            policy_name="kids",
            use_answer_policy=True,
            input_path=input_path,
            output_path=kids_output,
            parallel=args.parallel,
            workers=args.workers,
        )

    print("\n" + "=" * 70)
    print("Experiments completed!")
    print("=" * 70)
    print("\nNext steps:")
    if not args.kids_only:
        print("  1. Analyze baseline:")
        print(
            f"     python scripts/analyze_answer_policy_metrics.py --input {baseline_output}"
        )
    if not args.baseline_only:
        print("  2. Analyze kids policy:")
        print(
            f"     python scripts/analyze_answer_policy_metrics.py --input {kids_output}"
        )
    print("  3. Compare results and document findings")

    return 0


if __name__ == "__main__":
    sys.exit(main())
