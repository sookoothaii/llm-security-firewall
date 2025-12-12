"""
AdvBench Evaluation Script
==========================

Evaluates LLM Security Firewall against AdvBench dataset (foundational jailbreak test).

AdvBench contains harmful strings and instructions to test if a model's safety
can be bypassed. This is a foundational benchmark for testing basic safety alignment.

Source: GitHub: https://github.com/arobey1/advbench

Usage:
    python scripts/run_advbench_eval.py
    python scripts/run_advbench_eval.py --limit 100
    python scripts/run_advbench_eval.py --output results/advbench_results.json
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# CRITICAL: Enforce GPU usage BEFORE any imports that might initialize ML models
# This must happen at the very top of the script
try:
    import torch
    if not torch.cuda.is_available():
        print("\n" + "="*80)
        print("FATAL ERROR: GPU is REQUIRED but not available!")
        print("="*80)
        print("CPU usage is COMPLETELY DISABLED.")
        print("Please ensure CUDA is available before running benchmarks.")
        print("="*80 + "\n")
        sys.exit(1)
    
    # Verify GPU is actually available and log info
    print(f"[GPU CHECK] CUDA available: {torch.cuda.is_available()}")
    print(f"[GPU CHECK] Device: {torch.cuda.get_device_name(0)}")
    print(f"[GPU CHECK] CUDA Version: {torch.version.cuda}")
    print(f"[GPU CHECK] TORCH_DEVICE env: {os.environ.get('TORCH_DEVICE', 'not set')}")
    print(f"[GPU CHECK] CUDA_VISIBLE_DEVICES: {os.environ.get('CUDA_VISIBLE_DEVICES', 'not set')}")
    
    # Force GPU usage
    os.environ['TORCH_DEVICE'] = 'cuda'
    if 'CUDA_VISIBLE_DEVICES' not in os.environ:
        os.environ['CUDA_VISIBLE_DEVICES'] = '0'
    
    print(f"[GPU CHECK] GPU enforcement: TORCH_DEVICE=cuda set")
    print(f"[GPU CHECK] All ML components will use GPU\n")
except ImportError:
    print("[WARNING] PyTorch not available - cannot verify GPU")
except Exception as e:
    print(f"[ERROR] GPU check failed: {e}")
    sys.exit(1)

# Add parent directory to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir / "src"))
sys.path.insert(0, str(base_dir))  # benchmarks/ is at project root

try:
    from llm_firewall.core.firewall_engine_v3 import FirewallEngineV3, EmergencyFixFirewallConfig
    from benchmarks.benchmark_evaluator_base import (
        BenchmarkEvaluatorBase,
        BenchmarkResult,
        BenchmarkSummary,
    )
except ImportError as e:
    print(f"[ERROR] Failed to import required modules: {e}")
    print("[INFO] Make sure you're running from the project root directory")
    sys.exit(1)


class AdvBenchEvaluator(BenchmarkEvaluatorBase):
    """
    Evaluator for AdvBench dataset.

    AdvBench is a foundational jailbreak test containing harmful strings and
    instructions to test basic safety alignment.
    """

    def __init__(self, data_dir=None):
        super().__init__("AdvBench", data_dir)

    def load_dataset(self, limit=None):
        """
        Load AdvBench dataset.

        AdvBench format is a CSV file with 'Behavior' column containing the prompt.
        The dataset is available in HarmBench's extra_behavior_datasets directory.

        Args:
            limit: Maximum number of prompts to load (None = all)

        Returns:
            List of test case dictionaries
        """
        # Check multiple possible locations for AdvBench data
        possible_paths = [
            # HarmBench extra behavior datasets (preferred - already available)
            base_dir
            / "tests"
            / "benchmarks"
            / "harmbench"
            / "data"
            / "behavior_datasets"
            / "extra_behavior_datasets"
            / "advbench_behaviors.csv",
            # Alternative locations
            self.data_dir / "advbench" / "advbench.csv",
            self.data_dir / "advbench.csv",
            base_dir / "datasets" / "advbench" / "advbench.csv",
            base_dir / "datasets" / "advbench.csv",
            self.data_dir / "advbench.txt",
            base_dir / "datasets" / "advbench.txt",
        ]

        data_file = None
        for path in possible_paths:
            if path.exists():
                data_file = path
                break

        if not data_file:
            print("\n[ERROR] AdvBench dataset not found in any of these locations:")
            for path in possible_paths:
                print(f"  - {path}")
            print(
                "\n[INFO] AdvBench dataset should be a CSV file with a 'Behavior' column."
            )
            print(
                "[INFO] The dataset is typically included in HarmBench's extra_behavior_datasets directory."
            )
            sys.exit(1)

        print(f"[INFO] Loading AdvBench from: {data_file}")
        test_cases = []

        # Load CSV format
        import csv

        with open(data_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # AdvBench CSV has 'Behavior' column with the prompt
                prompt = row.get("Behavior", row.get("goal", row.get("prompt", "")))
                if not prompt:
                    # If no Behavior column, try other common column names
                    prompt = next(
                        (
                            v
                            for k, v in row.items()
                            if v
                            and k.lower()
                            not in [
                                "id",
                                "category",
                                "tags",
                                "contextstring",
                                "behaviorid",
                            ]
                        ),
                        "",
                    )

                if prompt and prompt.strip():
                    # Get behavior ID if available
                    behavior_id = row.get(
                        "BehaviorID", row.get("id", f"advbench_{len(test_cases) + 1}")
                    )
                    category = row.get("Category", "jailbreak")

                    test_cases.append(
                        {
                            "id": behavior_id,
                            "prompt": prompt.strip(),
                            "category": category if category else "jailbreak",
                        }
                    )

        if limit:
            test_cases = test_cases[:limit]

        print(f"[OK] Loaded {len(test_cases)} AdvBench prompts")
        return test_cases

    def prepare_prompt(self, test_case):
        """Extract prompt from AdvBench test case."""
        return test_case["prompt"]


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate LLM Security Firewall against AdvBench dataset"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of prompts to evaluate (None = all)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON file path (default: results/advbench_YYYYMMDD_HHMMSS.json)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Directory containing AdvBench dataset (default: datasets/advbench)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress",
    )

    args = parser.parse_args()

    # Set output file
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = base_dir / "results" / f"advbench_{timestamp}.json"
    else:
        output_file = Path(args.output)

    # Initialize evaluator
    data_dir = Path(args.data_dir) if args.data_dir else None
    evaluator = AdvBenchEvaluator(data_dir=data_dir)

    # Initialize firewall
    print("\n[0] Initializing FirewallEngineV3...")
    config = EmergencyFixFirewallConfig(enable_kids_policy=False)
    firewall = FirewallEngineV3(config)
    print("[OK] FirewallEngineV3 initialized")

    # Run evaluation
    results, summary = evaluator.run_evaluation(
        firewall=firewall,
        limit=args.limit,
        verbose=args.verbose,
    )

    # Print summary
    evaluator.print_summary(summary)

    # Save results
    evaluator.save_results(results, summary, output_file)

    print("\n[OK] Evaluation complete!")
    print(f"    Benchmark: {summary.benchmark_name}")
    print(f"    Total Tests: {summary.total_tests}")
    print(f"    ASR: {summary.attack_success_rate:.2%}")
    print(f"    Results saved to: {output_file}")


if __name__ == "__main__":
    main()
