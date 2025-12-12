"""
PolygloToxicityPrompts Evaluation Script
========================================

Evaluates LLM Security Firewall against PolygloToxicityPrompts dataset.

PolygloToxicityPrompts contains 425K prompts across 17 languages, evaluating
toxic degeneration in non-English contexts. This exposes safety gaps in
multilingual deployment where training data may be scarcer.

Source: Hugging Face: ToxicityPrompts/PolygloToxicityPrompts
GitHub: https://github.com/kpriyanshu256/polyglo-toxicity-prompts

Usage:
    python scripts/run_polyglotoxicity_eval.py
    python scripts/run_polyglotoxicity_eval.py --limit 1000
    python scripts/run_polyglotoxicity_eval.py --output results/polyglotoxicity_results.json
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


class PolygloToxicityPromptsEvaluator(BenchmarkEvaluatorBase):
    """
    Evaluator for PolygloToxicityPrompts dataset.

    PolygloToxicityPrompts tests toxic degeneration in multilingual contexts,
    exposing safety gaps where training data may be scarcer.
    """

    def __init__(self, data_dir=None):
        super().__init__("PolygloToxicityPrompts", data_dir)

    def load_dataset(self, limit=None):
        """
        Load PolygloToxicityPrompts dataset from Hugging Face or local file.

        Args:
            limit: Maximum number of prompts to load (None = all)

        Returns:
            List of test case dictionaries
        """
        # Try to load from Hugging Face first (preferred method)
        try:
            from datasets import load_dataset
        except ImportError:
            print("\n[ERROR] Hugging Face datasets library not found.")
            print("[INFO] Install with: pip install datasets")
            print("[INFO] PolygloToxicityPrompts is available on Hugging Face:")
            print("[INFO]   Dataset: ToxicityPrompts/PolygloToxicityPrompts")
            sys.exit(1)

        cache_dir = base_dir / "datasets" / "polyglotoxicityprompts"
        cache_dir.mkdir(parents=True, exist_ok=True)

        print("[INFO] Loading PolygloToxicityPrompts from Hugging Face...")
        print("[INFO] Dataset: ToxicityPrompts/PolygloToxicityPrompts")
        print("[INFO] This may take a few minutes on first run")

        try:
            # Try multiple possible dataset configurations
            dataset_configs = [
                ("ptp-en", "English full split"),
                ("ptp-small-en", "English small split"),
                ("wildchat-en", "WildChat English split"),
            ]

            dataset = None
            used_config = None

            for config, description in dataset_configs:
                try:
                    print(f"[INFO] Trying config: {config} ({description})...")
                    dataset = load_dataset(
                        "ToxicityPrompts/PolygloToxicityPrompts",
                        config,
                        cache_dir=str(cache_dir),
                    )
                    used_config = config
                    print(f"[OK] Successfully loaded config: {config}")
                    break
                except Exception as e:
                    continue

            if dataset is None:
                # Try default load
                print("[INFO] Trying default load (no config)...")
                dataset = load_dataset(
                    "ToxicityPrompts/PolygloToxicityPrompts", cache_dir=str(cache_dir)
                )

            # Process Hugging Face dataset
            test_cases = []

            # Get the first available split
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
            print(f"[INFO] Processing split: {split_name} ({data_len} prompts)")

            for i, item in enumerate(data):
                # Convert item to dict if it's a Dataset row object
                if hasattr(item, "keys") and not isinstance(item, dict):
                    item = dict(item)

                # Extract prompt text - handle different structures
                prompt = (
                    item.get("text")
                    or item.get("prompt")
                    or item.get("instruction")
                    or item.get("input")
                )

                if not prompt or not isinstance(prompt, str):
                    continue

                # Get language/category
                language = (
                    item.get("language")
                    or item.get("lang")
                    or item.get("language_code")
                    or "unknown"
                )

                test_cases.append(
                    {
                        "id": f"polyglo_{language}_{i + 1:06d}",
                        "prompt": str(prompt).strip(),
                        "category": language if language else "multilingual",
                    }
                )

                if limit and len(test_cases) >= limit:
                    break

            print(
                f"[OK] Loaded {len(test_cases)} PolygloToxicityPrompts from Hugging Face"
            )
            return test_cases

        except Exception as e:
            print(
                f"\n[ERROR] Failed to load PolygloToxicityPrompts from Hugging Face: {e}"
            )
            print("[INFO] Dataset: ToxicityPrompts/PolygloToxicityPrompts")
            print(
                "[INFO] Make sure you have internet connection and 'datasets' library installed"
            )
            print("[INFO] Try: pip install datasets")
            print(
                "[INFO] Alternative: Download from GitHub and place in datasets/polyglotoxicityprompts/"
            )
            print(
                "[INFO]   GitHub: https://github.com/kpriyanshu256/polyglo-toxicity-prompts"
            )
            sys.exit(1)

    def prepare_prompt(self, test_case):
        """Extract prompt from PolygloToxicityPrompts test case."""
        return test_case["prompt"]


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate LLM Security Firewall against PolygloToxicityPrompts dataset"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of prompts to evaluate (None = all, default: 1000 for testing)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON file path (default: results/polyglotoxicity_YYYYMMDD_HHMMSS.json)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Directory containing PolygloToxicityPrompts dataset",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress",
    )

    args = parser.parse_args()

    # Set default limit to 1000 for testing (full dataset is 425K)
    if args.limit is None:
        print("[INFO] No limit specified. Using default limit of 1000 for testing.")
        print(
            "[INFO] Use --limit to specify a different limit, or --limit 0 for full dataset."
        )
        args.limit = 1000

    # Set output file
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = base_dir / "results" / f"polyglotoxicity_{timestamp}.json"
    else:
        output_file = Path(args.output)

    # Initialize evaluator
    data_dir = Path(args.data_dir) if args.data_dir else None
    evaluator = PolygloToxicityPromptsEvaluator(data_dir=data_dir)

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
