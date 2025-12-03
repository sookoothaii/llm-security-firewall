"""
Unified AnswerPolicy Experiment Runner
======================================

Single, flexible experiment runner for AnswerPolicy evaluation.
Supports baseline, default, kids, and internal_debug policies.

Usage:
    python scripts/run_answerpolicy_experiment.py \
        --policy baseline \
        --input datasets/mixed_small.jsonl \
        --output logs/baseline_mixed_small.jsonl

    python scripts/run_answerpolicy_experiment.py \
        --policy kids \
        --input datasets/mixed_small.jsonl \
        --output logs/kids_mixed_small.jsonl \
        --use-answer-policy \
        --num-workers 4

Author: Joerg Bollwahn
Date: 2025-12-03
License: MIT
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Optional, Any

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


def decision_to_dict(
    decision, item_id: str, item_type: str, elapsed_ms: Optional[float] = None
) -> Dict[str, Any]:
    """
    Convert FirewallDecision to dictionary for JSON serialization.

    Args:
        decision: FirewallDecision object
        item_id: Original item ID from dataset
        item_type: Original item type (redteam/benign) from dataset
        elapsed_ms: Optional elapsed time in milliseconds

    Returns:
        Dictionary representation of decision
    """
    result = {
        "item_id": item_id,
        "item_type": item_type,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "risk_score": decision.risk_score,
        "sanitized_text": decision.sanitized_text,
        "detected_threats": decision.detected_threats or [],
        "metadata": decision.metadata or {},
    }

    # Add timing if provided
    if elapsed_ms is not None:
        if "timing" not in result["metadata"]:
            result["metadata"]["timing"] = {}
        result["metadata"]["timing"]["elapsed_ms"] = elapsed_ms

    return result


def process_single_item(
    item: Dict[str, str],
    policy_name: str,
    use_answer_policy: bool,
    tenant_id: str,
    provider: Optional[PolicyProvider],
    measure_latency: bool = False,
) -> Dict[str, Any]:
    """
    Process a single item through firewall (for parallel processing).

    Args:
        item: Item dictionary with id, type, prompt
        policy_name: Policy name
        use_answer_policy: Whether AnswerPolicy is enabled
        tenant_id: Tenant ID
        provider: Policy provider (or None)
        measure_latency: Whether to measure processing latency

    Returns:
        Decision dictionary with item metadata
    """
    engine = FirewallEngineV2()

    start_time = time.perf_counter() if measure_latency else None

    try:
        decision = engine.process_input(
            text=item["prompt"],
            user_id=f"user_{item.get('id', 'unknown')}",
            tenant_id=tenant_id,
            route="/api/test",
            use_answer_policy=use_answer_policy,
            policy_provider=provider,
        )

        elapsed_ms = None
        if measure_latency and start_time is not None:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        decision_dict = decision_to_dict(
            decision,
            item_id=item.get("id", "unknown"),
            item_type=item.get("type", "unknown"),
            elapsed_ms=elapsed_ms,
        )

        return decision_dict
    except Exception as e:
        # Return error decision
        elapsed_ms = None
        if measure_latency and start_time is not None:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return {
            "item_id": item.get("id", "unknown"),
            "item_type": item.get("type", "unknown"),
            "error": str(e),
            "allowed": False,
            "reason": f"Processing error: {e}",
            "risk_score": 1.0,
            "metadata": {
                "answer_policy": {
                    "enabled": False,
                    "blocked_by_answer_policy": False,
                },
                "timing": {"elapsed_ms": elapsed_ms} if elapsed_ms is not None else {},
            },
        }


def run_experiment(
    policy_name: str,
    input_path: Path,
    output_path: Path,
    use_answer_policy: bool = False,
    num_workers: int = 1,
    measure_latency: bool = False,
) -> None:
    """
    Run experiment with specified policy.

    Args:
        policy_name: Policy name (baseline, default, kids, internal_debug)
        input_path: Path to input JSONL file
        output_path: Path to output JSONL file
        use_answer_policy: Whether to enable AnswerPolicy
        num_workers: Number of parallel workers (1 = sequential)
        measure_latency: Whether to measure processing latency
    """
    engine = FirewallEngineV2()

    # Setup policy provider and tenant mapping
    provider = None
    tenant_id = "tenant_baseline"

    if policy_name == "baseline":
        use_answer_policy = False
        tenant_id = "tenant_baseline"
    elif policy_name == "default":
        use_answer_policy = True
        provider = get_default_provider()
        tenant_id = "tenant_default"
    elif policy_name == "kids":
        use_answer_policy = True
        provider = PolicyProvider(tenant_policy_map={"tenant_kids": "kids"})
        tenant_id = "tenant_kids"
    elif policy_name == "internal_debug":
        use_answer_policy = True
        provider = PolicyProvider(tenant_policy_map={"tenant_debug": "internal_debug"})
        tenant_id = "tenant_debug"
    else:
        raise ValueError(
            f"Unknown policy: {policy_name}. Must be one of: baseline, default, kids, internal_debug"
        )

    # Load all items
    items = []
    with open(input_path, "r", encoding="utf-8") as f_in:
        for line_num, line in enumerate(f_in, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
                # Validate required fields
                if "id" not in item or "type" not in item or "prompt" not in item:
                    print(
                        f"Warning: Invalid item on line {line_num}: missing required fields",
                        file=sys.stderr,
                    )
                    continue
                items.append(item)
            except json.JSONDecodeError as e:
                print(f"Warning: Invalid JSON on line {line_num}: {e}", file=sys.stderr)
                continue

    print(
        f"Running experiment: policy={policy_name}, use_answer_policy={use_answer_policy}"
    )
    print(f"  Items: {len(items)}, Workers: {num_workers}, Latency: {measure_latency}")

    decisions = []

    if num_workers > 1 and len(items) > 1:
        # Parallel processing
        print(f"  Using parallel processing with {num_workers} workers...")

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [
                executor.submit(
                    process_single_item,
                    item,
                    policy_name,
                    use_answer_policy,
                    tenant_id,
                    provider,
                    measure_latency,
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
                    if completed % max(1, len(items) // 20) == 0 or completed == len(
                        items
                    ):
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
        # Sequential processing
        for item_num, item in enumerate(items, start=1):
            try:
                decision = process_single_item(
                    item,
                    policy_name,
                    use_answer_policy,
                    tenant_id,
                    provider,
                    measure_latency,
                )
                decisions.append(decision)

                # Progress indicator
                if item_num % max(1, len(items) // 20) == 0 or item_num == len(items):
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
        "--policy",
        type=str,
        required=True,
        choices=["baseline", "default", "kids", "internal_debug"],
        help="Policy to use (baseline, default, kids, internal_debug)",
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to input dataset JSONL file",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Path to output decisions JSONL file",
    )
    parser.add_argument(
        "--use-answer-policy",
        action="store_true",
        help="Enable AnswerPolicy (overrides policy default for baseline)",
    )
    parser.add_argument(
        "--num-workers",
        type=int,
        default=1,
        help="Number of parallel workers (default: 1, sequential)",
    )
    parser.add_argument(
        "--measure-latency",
        action="store_true",
        help="Measure per-request latency (adds timing metadata)",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        return 1

    output_path = Path(args.output)

    # Override use_answer_policy if explicitly set
    use_answer_policy = args.use_answer_policy
    if args.policy == "baseline" and not use_answer_policy:
        use_answer_policy = False
    elif args.policy != "baseline":
        use_answer_policy = True

    try:
        run_experiment(
            policy_name=args.policy,
            input_path=input_path,
            output_path=output_path,
            use_answer_policy=use_answer_policy,
            num_workers=args.num_workers,
            measure_latency=args.measure_latency,
        )
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
