"""
HH-RLHF Evaluation Script
=========================

Evaluates LLM Security Firewall against Anthropic HH-RLHF dataset.

HH-RLHF (Helpful and Harmless Reinforcement Learning from Human Feedback) contains
human preference data with "chosen" and "rejected" response pairs. This dataset
tests the firewall's ability to detect harmful content in both preferred and
rejected responses.

Source: Hugging Face: Anthropic/hh-rlhf
Paper: https://arxiv.org/abs/2204.05862
GitHub: https://github.com/anthropics/hh-rlhf

Available subsets:
- helpful-base: Base model helpfulness comparisons
- helpful-online: Online RLHF helpfulness comparisons
- helpful-rejection-sampling: Rejection sampling helpfulness comparisons
- harmless-base: Base model harmlessness comparisons
- red-team-attempts: Red teaming dialogues (different format)

Usage:
    python scripts/run_hh_rlhf_eval.py
    python scripts/run_hh_rlhf_eval.py --subset helpful-base --limit 1000
    python scripts/run_hh_rlhf_eval.py --subset harmless-base --test-both
    python scripts/run_hh_rlhf_eval.py --output results/hh_rlhf_results.json
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


class HHRlhfEvaluator(BenchmarkEvaluatorBase):
    """
    Evaluator for Anthropic HH-RLHF dataset.

    HH-RLHF tests firewall detection of harmful content in human preference data.
    Each entry contains a "chosen" (preferred) and "rejected" (less preferred) response.
    """

    def __init__(self, data_dir=None, subset="helpful-base", test_both=False):
        """
        Initialize HH-RLHF evaluator.

        Args:
            data_dir: Directory for cached dataset
            subset: Dataset subset to use (helpful-base, harmless-base, etc.)
            test_both: If True, test both chosen and rejected responses
        """
        super().__init__("HH-RLHF", data_dir)
        self.subset = subset
        self.test_both = test_both

    def load_dataset(self, limit=None):
        """
        Load HH-RLHF dataset from Hugging Face.

        Args:
            limit: Maximum number of prompts to load (None = all)

        Returns:
            List of test case dictionaries
        """
        try:
            from datasets import load_dataset
        except ImportError:
            print("\n[ERROR] Hugging Face datasets library not found.")
            print("[INFO] Install with: pip install datasets")
            sys.exit(1)

        cache_dir = base_dir / "datasets" / "hh-rlhf"
        cache_dir.mkdir(parents=True, exist_ok=True)

        print("[INFO] Loading HH-RLHF from Hugging Face...")
        print(f"[INFO] Subset: {self.subset}")
        print("[INFO] This may take a few minutes on first run")

        try:
            # Load dataset from Hugging Face
            # HH-RLHF has different subsets with different data_dir parameters
            dataset = load_dataset(
                "Anthropic/hh-rlhf", data_dir=self.subset, cache_dir=str(cache_dir)
            )

            # Process dataset
            test_cases = []

            # Get the first available split (usually "train" or "test")
            if hasattr(dataset, "keys"):
                dataset_keys = list(dataset.keys())  # type: ignore
                split_name = (
                    "train"
                    if "train" in dataset_keys
                    else dataset_keys[0]
                    if dataset_keys
                    else "train"
                )
            else:
                split_name = "train"

            data = dataset[split_name]  # type: ignore

            # Get data length safely
            data_len = len(data) if hasattr(data, "__len__") else 0  # type: ignore
            print(f"[INFO] Processing split: {split_name} ({data_len} entries)")

            for i, item in enumerate(data):
                # Convert item to dict if it's a Dataset row object
                if hasattr(item, "keys") and not isinstance(item, dict):
                    item = dict(item)

                # HH-RLHF format: each item has "chosen" and "rejected" strings
                chosen = item.get("chosen", "")
                rejected = item.get("rejected", "")

                if not chosen and not rejected:
                    continue

                # Test chosen response
                if chosen:
                    test_cases.append(
                        {
                            "id": f"hh_rlhf_{self.subset}_{i + 1:06d}_chosen",
                            "prompt": str(chosen).strip(),
                            "category": f"{self.subset}_chosen",
                            "response_type": "chosen",
                            "original_index": i,
                        }
                    )

                # Test rejected response if requested
                if self.test_both and rejected:
                    test_cases.append(
                        {
                            "id": f"hh_rlhf_{self.subset}_{i + 1:06d}_rejected",
                            "prompt": str(rejected).strip(),
                            "category": f"{self.subset}_rejected",
                            "response_type": "rejected",
                            "original_index": i,
                        }
                    )

                if limit and len(test_cases) >= limit:
                    break

            print(f"[OK] Loaded {len(test_cases)} HH-RLHF test cases")
            if self.test_both:
                chosen_count = sum(
                    1 for tc in test_cases if tc.get("response_type") == "chosen"
                )
                rejected_count = sum(
                    1 for tc in test_cases if tc.get("response_type") == "rejected"
                )
                print(f"[INFO]   Chosen responses: {chosen_count}")
                print(f"[INFO]   Rejected responses: {rejected_count}")

            return test_cases

        except Exception as e:
            print(f"\n[ERROR] Failed to load HH-RLHF dataset: {e}")
            print(
                "[INFO] Make sure you have internet connection and 'datasets' library installed"
            )
            print("[INFO] Try: pip install datasets")
            print(
                "[INFO] Available subsets: helpful-base, helpful-online, helpful-rejection-sampling, harmless-base, red-team-attempts"
            )
            sys.exit(1)

    def prepare_prompt(self, test_case):
        """Extract prompt from HH-RLHF test case."""
        return test_case["prompt"]


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate LLM Security Firewall against HH-RLHF dataset"
    )
    parser.add_argument(
        "--subset",
        type=str,
        default="helpful-base",
        choices=[
            "helpful-base",
            "helpful-online",
            "helpful-rejection-sampling",
            "harmless-base",
            "red-team-attempts",
        ],
        help="Dataset subset to evaluate (default: helpful-base)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of prompts to evaluate (None = all, default: 1000 for testing)",
    )
    parser.add_argument(
        "--test-both",
        action="store_true",
        help="Test both chosen and rejected responses (default: only chosen)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON file path (default: results/hh_rlhf_YYYYMMDD_HHMMSS.json)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Directory for cached dataset (default: datasets/hh-rlhf)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress",
    )

    args = parser.parse_args()

    # Set default limit to 1000 for testing
    if args.limit is None:
        print("[INFO] No limit specified. Using default limit of 1000 for testing.")
        print(
            "[INFO] Use --limit to specify a different limit, or --limit 0 for full dataset."
        )
        args.limit = 1000

    # Set output file
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        subset_suffix = args.subset.replace("-", "_")
        output_file = base_dir / "results" / f"hh_rlhf_{subset_suffix}_{timestamp}.json"
    else:
        output_file = Path(args.output)

    # Initialize evaluator
    data_dir = Path(args.data_dir) if args.data_dir else None
    evaluator = HHRlhfEvaluator(
        data_dir=data_dir, subset=args.subset, test_both=args.test_both
    )

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

    # Additional analysis for chosen vs rejected if both were tested
    if args.test_both:
        chosen_results = [r for r in results if r.category and "chosen" in r.category]
        rejected_results = [
            r for r in results if r.category and "rejected" in r.category
        ]

        if chosen_results and rejected_results:
            chosen_blocked = sum(1 for r in chosen_results if r.blocked)
            rejected_blocked = sum(1 for r in rejected_results if r.blocked)
            chosen_asr = (
                (len(chosen_results) - chosen_blocked) / len(chosen_results)
                if chosen_results
                else 0.0
            )
            rejected_asr = (
                (len(rejected_results) - rejected_blocked) / len(rejected_results)
                if rejected_results
                else 0.0
            )

            print("\n" + "=" * 80)
            print("CHOSEN vs REJECTED ANALYSIS")
            print("=" * 80)
            print("\nChosen Responses:")
            print(f"  Total: {len(chosen_results)}")
            print(f"  Blocked: {chosen_blocked} ({100 * (1 - chosen_asr):.1f}%)")
            print(f"  ASR: {chosen_asr:.2%}")
            print("\nRejected Responses:")
            print(f"  Total: {len(rejected_results)}")
            print(f"  Blocked: {rejected_blocked} ({100 * (1 - rejected_asr):.1f}%)")
            print(f"  ASR: {rejected_asr:.2%}")
            print(f"\nDifference: {abs(chosen_asr - rejected_asr):.2%} ASR")
            if rejected_asr < chosen_asr:
                print("[OK] Rejected responses blocked more often (expected behavior)")
            else:
                print(
                    "[WARNING] Chosen responses blocked more often than rejected (unexpected)"
                )

    # Save results
    evaluator.save_results(results, summary, output_file)

    print("\n[OK] Evaluation complete!")
    print(f"    Benchmark: {summary.benchmark_name}")
    print(f"    Subset: {args.subset}")
    print(f"    Total Tests: {summary.total_tests}")
    print(f"    ASR: {summary.attack_success_rate:.2%}")
    print(f"    Results saved to: {output_file}")


if __name__ == "__main__":
    main()
