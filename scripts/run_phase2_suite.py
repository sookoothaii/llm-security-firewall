"""
Phase-2.5 Orchestrated Experiment Runner
=========================================

Single entry point for running multi-policy experiments across one or more datasets.
Automates the workflow: dataset -> experiment -> effectiveness -> comparison report.

Usage:
    python scripts/run_phase2_suite.py --config smoke_test
    python scripts/run_phase2_suite.py --dataset datasets/mixed_small.jsonl --policies baseline default kids
    python scripts/run_phase2_suite.py --config-file my_config.json

Author: Joerg Bollwahn
Date: 2025-12-03
License: MIT
"""

import argparse
import sys
from pathlib import Path
from typing import Dict, Optional, Any

# Add parent directory to path for imports
base_dir = Path(__file__).parent.parent
if base_dir.exists():
    sys.path.insert(0, str(base_dir))

# Import shared utilities and configs
from scripts.eval_utils import parse_jsonl, load_dataset, ensure_directory
from scripts.experiment_configs import (
    get_smoke_test_config,
    get_medium_config,
    get_experiment_config,
    load_config_from_dict,
    load_config_from_json,
)
from scripts.compute_answerpolicy_effectiveness import compute_effectiveness
from scripts.analyze_answer_policy_metrics import analyze_decisions


def run_single_experiment(
    policy_name: str,
    dataset_path: Path,
    output_dir: Path,
    experiment_id: str,
    num_workers: int = 1,
    measure_latency: bool = False,
) -> Path:
    """
    Run a single policy experiment using the existing script.

    Args:
        policy_name: Policy name (baseline, default, kids, internal_debug)
        dataset_path: Path to input dataset JSONL
        output_dir: Directory for output files
        experiment_id: Experiment identifier for file naming
        num_workers: Number of parallel workers
        measure_latency: Whether to measure latency

    Returns:
        Path to decision log JSONL file
    """
    # Import here to avoid circular dependencies
    from scripts.run_answerpolicy_experiment import run_experiment

    # Determine output path
    dataset_stem = dataset_path.stem
    log_path = (
        output_dir / "logs" / f"{policy_name}_{experiment_id}_{dataset_stem}.jsonl"
    )

    ensure_directory(log_path)

    # Run experiment (in-process call, not subprocess)
    run_experiment(
        policy_name=policy_name,
        input_path=dataset_path,
        output_path=log_path,
        use_answer_policy=(policy_name != "baseline"),
        num_workers=num_workers,
        measure_latency=measure_latency,
    )

    return log_path


def compute_effectiveness_for_log(
    log_path: Path, dataset_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Compute effectiveness metrics for a decision log.

    Args:
        log_path: Path to decision log JSONL
        dataset_path: Optional path to original dataset (for type mapping)

    Returns:
        Effectiveness metrics dictionary
    """
    decisions = parse_jsonl(log_path)

    dataset_map = None
    if dataset_path and dataset_path.exists():
        dataset_map = load_dataset(dataset_path)

    return compute_effectiveness(decisions, dataset_map)


def generate_comparison_report(
    results: Dict[str, Dict[str, Any]], output_path: Path
) -> None:
    """
    Generate ASCII Markdown comparison report for multiple policies.

    Args:
        results: Dictionary mapping policy_name -> effectiveness metrics
        output_path: Path to output Markdown file
    """
    ensure_directory(output_path)

    lines = []
    lines.append("# Phase-2 Evaluation Suite: Policy Comparison")
    lines.append("")
    lines.append("## Summary")
    lines.append("")

    # Table header
    lines.append(
        "| Policy | ASR | FPR | Redteam Blocked | Benign Blocked | AP Blocks (RT) | AP Blocks (B) |"
    )
    lines.append(
        "|--------|-----|-----|-----------------|---------------|----------------|--------------|"
    )

    # Table rows
    for policy_name in sorted(results.keys()):
        metrics = results[policy_name]
        rt = metrics["redteam"]
        bg = metrics["benign"]

        asr_str = f"{rt['asr']:.3f}"
        fpr_str = f"{bg['fpr']:.3f}"

        lines.append(
            f"| {policy_name} | {asr_str} | {fpr_str} | "
            f"{rt['blocked']}/{rt['total']} | {bg['blocked']}/{bg['total']} | "
            f"{rt['blocked_by_answer_policy']} | {bg['blocked_by_answer_policy']} |"
        )

    lines.append("")
    lines.append("## Detailed Results")
    lines.append("")

    for policy_name in sorted(results.keys()):
        metrics = results[policy_name]
        lines.append(f"### Policy: {policy_name}")
        lines.append("")
        lines.append(f"**Total items:** {metrics['total_items']}")
        lines.append("")
        lines.append("**Redteam:**")
        lines.append(f"- Total: {metrics['redteam']['total']}")
        lines.append(f"- Blocked: {metrics['redteam']['blocked']}")
        lines.append(f"- Allowed: {metrics['redteam']['allowed']}")
        lines.append(f"- ASR: {metrics['redteam']['asr']:.3f}")
        lines.append(
            f"- Blocked by AnswerPolicy: {metrics['redteam']['blocked_by_answer_policy']}"
        )
        lines.append("")
        lines.append("**Benign:**")
        lines.append(f"- Total: {metrics['benign']['total']}")
        lines.append(f"- Blocked: {metrics['benign']['blocked']}")
        lines.append(f"- Allowed: {metrics['benign']['allowed']}")
        lines.append(f"- FPR: {metrics['benign']['fpr']:.3f}")
        lines.append(
            f"- Blocked by AnswerPolicy: {metrics['benign']['blocked_by_answer_policy']}"
        )
        lines.append("")

    # Write file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def run_suite(config: Dict[str, Any], base_dir: Optional[Path] = None) -> int:
    """
    Run complete evaluation suite for a configuration.

    Args:
        config: Experiment configuration dictionary
        base_dir: Base directory for relative paths

    Returns:
        Exit code (0 = success, 1 = error)
    """
    if base_dir is None:
        base_dir = Path.cwd()

    experiment_id = config["experiment_id"]
    dataset_path = Path(config["dataset_path"])
    policies = config["policies"]
    num_workers = config["num_workers"]
    measure_latency = config["measure_latency"]

    # Validate dataset exists
    if not dataset_path.exists():
        print(f"Error: Dataset not found: {dataset_path}", file=sys.stderr)
        return 1

    # Setup output directories
    output_dir = base_dir
    logs_dir = output_dir / "logs"
    results_dir = output_dir / "results"
    ensure_directory(logs_dir)
    ensure_directory(results_dir)

    print(f"Running Phase-2 Suite: {experiment_id}")
    print(f"  Dataset: {dataset_path}")
    print(f"  Policies: {', '.join(policies)}")
    print(f"  Workers: {num_workers}, Latency: {measure_latency}")
    print("")

    # Run experiments for each policy
    log_paths = {}
    for policy_name in policies:
        print(f"Running experiment: {policy_name}...")
        try:
            log_path = run_single_experiment(
                policy_name=policy_name,
                dataset_path=dataset_path,
                output_dir=output_dir,
                experiment_id=experiment_id,
                num_workers=num_workers,
                measure_latency=measure_latency,
            )
            log_paths[policy_name] = log_path
            print(f"  Completed: {log_path}")
        except Exception as e:
            print(f"  Error: {e}", file=sys.stderr)
            return 1

    print("")

    # Compute effectiveness for each policy
    print("Computing effectiveness metrics...")
    results = {}
    for policy_name, log_path in log_paths.items():
        print(f"  Processing: {policy_name}...")
        try:
            metrics = compute_effectiveness_for_log(log_path, dataset_path)
            results[policy_name] = metrics

            # Optionally run detailed metrics analysis
            if measure_latency:
                decisions = parse_jsonl(log_path)
                detailed_metrics = analyze_decisions(decisions)
                # Store detailed metrics in results if needed
                results[policy_name]["detailed"] = detailed_metrics

        except Exception as e:
            print(
                f"  Error computing effectiveness for {policy_name}: {e}",
                file=sys.stderr,
            )
            return 1

    print("")

    # Generate comparison report
    dataset_stem = dataset_path.stem
    report_path = results_dir / f"{experiment_id}_{dataset_stem}_comparison.md"
    print(f"Generating comparison report: {report_path}...")
    try:
        generate_comparison_report(results, report_path)
        print(f"  Completed: {report_path}")
    except Exception as e:
        print(f"  Error generating report: {e}", file=sys.stderr)
        return 1

    print("")
    print("=" * 70)
    print("Phase-2 Suite Complete")
    print("=" * 70)
    print(f"Experiment ID: {experiment_id}")
    print(f"Dataset: {dataset_path}")
    print(f"Policies evaluated: {', '.join(policies)}")
    print(f"Comparison report: {report_path}")
    print("=" * 70)

    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run Phase-2 evaluation suite across multiple policies"
    )
    parser.add_argument(
        "--config",
        type=str,
        help="Use predefined configuration (e.g. smoke_test_core, core_suite_full, tool_abuse_focused, combined_suite, category_ablation). Legacy: smoke_test, medium",
    )
    parser.add_argument(
        "--config-file",
        type=str,
        help="Path to JSON configuration file",
    )
    parser.add_argument(
        "--dataset",
        type=str,
        help="Path to dataset JSONL file (overrides config)",
    )
    parser.add_argument(
        "--policies",
        type=str,
        nargs="+",
        choices=["baseline", "default", "kids", "internal_debug"],
        help="Policies to run (overrides config)",
    )
    parser.add_argument(
        "--num-workers",
        type=int,
        help="Number of parallel workers (overrides config)",
    )
    parser.add_argument(
        "--measure-latency",
        action="store_true",
        help="Measure latency (overrides config)",
    )
    parser.add_argument(
        "--experiment-id",
        type=str,
        help="Experiment identifier (overrides config)",
    )

    args = parser.parse_args()

    base_dir = Path(__file__).parent.parent

    # Load configuration
    if args.config_file:
        config = load_config_from_json(Path(args.config_file))
    elif args.config:
        # Try predefined configs first
        if args.config in ("smoke_test", "medium"):
            # Legacy configs
            if args.config == "smoke_test":
                config = get_smoke_test_config(base_dir)
            else:
                config = get_medium_config(base_dir)
        else:
            # New predefined configs
            try:
                config = get_experiment_config(args.config, base_dir)
            except ValueError as e:
                print(f"Error: {e}", file=sys.stderr)
                return 1
    else:
        # Minimal config from command-line args
        if not args.dataset:
            print(
                "Error: Must specify --config, --config-file, or --dataset",
                file=sys.stderr,
            )
            return 1
        config = {
            "experiment_id": args.experiment_id or "manual",
            "dataset_path": args.dataset,
            "policies": args.policies or ["baseline", "default", "kids"],
            "num_workers": args.num_workers or 1,
            "measure_latency": args.measure_latency,
        }

    # Override config with command-line args
    if args.dataset:
        config["dataset_path"] = args.dataset
    if args.policies:
        config["policies"] = args.policies
    if args.num_workers is not None:
        config["num_workers"] = args.num_workers
    if args.measure_latency:
        config["measure_latency"] = True
    if args.experiment_id:
        config["experiment_id"] = args.experiment_id

    # Validate and normalize
    try:
        config = load_config_from_dict(config)
    except ValueError as e:
        print(f"Error: Invalid configuration: {e}", file=sys.stderr)
        return 1

    # Run suite
    return run_suite(config, base_dir)


if __name__ == "__main__":
    sys.exit(main())
