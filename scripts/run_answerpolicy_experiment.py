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

# Try to import CPU optimization for optimal worker count
scripts_dir = Path(__file__).parent
try:
    # Add scripts directory to path for import
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
            DEFAULT_WORKERS = optimal["experiment_workers"]
        else:
            DEFAULT_WORKERS = get_optimal_worker_count(cpu_info, task_type="mixed")
    except Exception:
        DEFAULT_WORKERS = 18  # Safe default for i9-12900HX
else:
    # Fallback: detect CPU info manually
    try:
        import multiprocessing

        cpu_count = multiprocessing.cpu_count() or 4
        DEFAULT_WORKERS = max(1, min(18, cpu_count - 2))
    except Exception:
        DEFAULT_WORKERS = 18  # Safe default for i9-12900HX


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
    use_evidence_based_p_correct: bool = False,
    p_correct_stretch_factor: float = 1.0,
    uncertainty_boost_factor: float = 0.0,
    use_optimized_mass_calibration: bool = False,
    p_correct_formula: str = "stretched",
    p_correct_scale_method: str = "none",
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
        use_evidence_based_p_correct: Whether to use Dempster-Shafer evidence fusion

    Returns:
        Decision dictionary with item metadata
    """
    # Initialize engine with evidence-based p_correct if requested
    try:
        from llm_firewall.fusion.dempster_shafer import DempsterShaferFusion

        dempster_fuser = (
            DempsterShaferFusion() if use_evidence_based_p_correct else None
        )

        # VectorGuard initialization (optional - for CUSUM evidence)
        vector_guard = None
        if use_evidence_based_p_correct:
            # Try to initialize VectorGuard for real CUSUM evidence
            try:
                from hak_gal.core.session_manager import SessionManager
                from hak_gal.layers.inbound.vector_guard import SemanticVectorCheck

                session_manager = SessionManager()
                vector_guard = SemanticVectorCheck(
                    session_manager=session_manager,
                    model_name="all-MiniLM-L6-v2",  # Lightweight model
                    drift_threshold=0.7,
                    window_size=50,
                )
                print("  VectorGuard: ENABLED (CUSUM evidence active)")
            except ImportError as e:
                print(f"  VectorGuard: DISABLED (ImportError: {e})")
                print("  Install: pip install sentence-transformers")
                vector_guard = None
            except Exception as e:
                print(f"  VectorGuard: DISABLED (Error: {e})")
                vector_guard = None

        engine = FirewallEngineV2(
            dempster_shafer_fuser=dempster_fuser,
            use_evidence_based_p_correct=use_evidence_based_p_correct,
            vector_guard=vector_guard,
            p_correct_stretch_factor=p_correct_stretch_factor,
            uncertainty_boost_factor=uncertainty_boost_factor,
            use_optimized_mass_calibration=use_optimized_mass_calibration,
            p_correct_formula=p_correct_formula,
            p_correct_scale_method=p_correct_scale_method,
        )
    except ImportError:
        # Fallback if Dempster-Shafer not available
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
    use_evidence_based_p_correct: bool = False,
    p_correct_stretch_factor: float = 1.0,
    uncertainty_boost_factor: float = 0.0,
    use_optimized_mass_calibration: bool = False,
    p_correct_formula: str = "stretched",
    p_correct_scale_method: str = "none",
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
        use_evidence_based_p_correct: Whether to use Dempster-Shafer evidence fusion
    """
    # Engine initialization moved to process_single_item for parallel processing

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
    elif policy_name == "kids_evidence":
        use_answer_policy = True
        provider = PolicyProvider(
            tenant_policy_map={"tenant_kids_evidence": "kids_evidence"}
        )
        tenant_id = "tenant_kids_evidence"
    elif policy_name == "internal_debug":
        use_answer_policy = True
        provider = PolicyProvider(tenant_policy_map={"tenant_debug": "internal_debug"})
        tenant_id = "tenant_debug"
    else:
        raise ValueError(
            f"Unknown policy: {policy_name}. Must be one of: baseline, default, kids, kids_evidence, internal_debug"
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
    if use_evidence_based_p_correct:
        print("  Evidence-based p_correct: ENABLED (Dempster-Shafer)")
        print(f"    Stretch factor: {p_correct_stretch_factor}")
        print(f"    Uncertainty boost: {uncertainty_boost_factor}")
        print(f"    Optimized mass calibration: {use_optimized_mass_calibration}")
        print(f"    p_correct formula: {p_correct_formula}")
        print(f"    p_correct scale method: {p_correct_scale_method}")
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
                    use_evidence_based_p_correct,
                    p_correct_stretch_factor,
                    uncertainty_boost_factor,
                    use_optimized_mass_calibration,
                    p_correct_formula,
                    p_correct_scale_method,
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
                    use_evidence_based_p_correct,
                    p_correct_stretch_factor,
                    uncertainty_boost_factor,
                    use_optimized_mass_calibration,
                    p_correct_formula,
                    p_correct_scale_method,
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
        choices=["baseline", "default", "kids", "kids_evidence", "internal_debug"],
        help="Policy to use (baseline, default, kids, kids_evidence, internal_debug)",
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
        default=None,
        help=f"Number of parallel workers (default: auto-detect, optimal for your CPU: {DEFAULT_WORKERS if 'DEFAULT_WORKERS' in globals() else 18})",
    )
    parser.add_argument(
        "--measure-latency",
        action="store_true",
        help="Measure per-request latency (adds timing metadata)",
    )
    parser.add_argument(
        "--use-evidence-based-p-correct",
        action="store_true",
        help="Use Dempster-Shafer evidence fusion for p_correct calculation (instead of heuristic)",
    )
    parser.add_argument(
        "--p-correct-stretch-factor",
        type=float,
        default=1.0,
        help="Stretch factor for p_correct distribution (default: 1.0, recommended: 3.0 for evidence-based)",
    )
    parser.add_argument(
        "--uncertainty-boost-factor",
        type=float,
        default=0.0,
        help="Uncertainty boost factor for intermediate confidence values (default: 0.0, recommended: 0.4 for calibration)",
    )
    parser.add_argument(
        "--use-optimized-mass-calibration",
        action="store_true",
        help="Use optimized mass calibration (experimental, produces higher p_correct values)",
    )
    parser.add_argument(
        "--p-correct-formula",
        type=str,
        default="stretched",
        choices=["stretched", "weighted", "plausibility", "transformed"],
        help="p_correct formula to use (default: stretched)",
    )
    parser.add_argument(
        "--p-correct-scale-method",
        type=str,
        default="none",
        choices=["none", "linear_shift", "power_transform", "simple_shift"],
        help="p_correct scaling method (default: none, use 'linear_shift' for weighted formula)",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        return 1

    output_path = Path(args.output)

    # Use auto-detected default workers if not specified
    num_workers = args.num_workers if args.num_workers is not None else DEFAULT_WORKERS
    if args.num_workers is None:
        print(f"Using auto-detected optimal worker count: {num_workers}")

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
            use_evidence_based_p_correct=args.use_evidence_based_p_correct,
            p_correct_stretch_factor=args.p_correct_stretch_factor,
            uncertainty_boost_factor=args.uncertainty_boost_factor,
            use_optimized_mass_calibration=args.use_optimized_mass_calibration,
            p_correct_formula=args.p_correct_formula,
            p_correct_scale_method=args.p_correct_scale_method,
            num_workers=num_workers,
            measure_latency=args.measure_latency,
        )
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
