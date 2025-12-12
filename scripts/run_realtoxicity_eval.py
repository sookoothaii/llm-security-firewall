"""
RealToxicityPrompts Evaluation Script
======================================

Evaluates LLM Security Firewall against RealToxicityPrompts dataset.

RealToxicityPrompts contains ~100k sentence beginnings from real web text,
scored for toxicity, to see if models generate toxic completions from naturally
occurring, often benign prompts.

Source: Hugging Face: allenai/real-toxicity-prompts
Paper: https://arxiv.org/abs/2009.11462

Usage:
    python scripts/run_realtoxicity_eval.py
    python scripts/run_realtoxicity_eval.py --limit 1000
    python scripts/run_realtoxicity_eval.py --output results/realtoxicity_results.json
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


class RealToxicityPromptsEvaluator(BenchmarkEvaluatorBase):
    """
    Evaluator for RealToxicityPrompts dataset.

    RealToxicityPrompts tests model tendency to produce toxicity from naturally
    occurring, often benign prompts. The dataset contains sentence beginnings
    from real web text, scored for toxicity.
    """

    def __init__(self, data_dir=None):
        super().__init__("RealToxicityPrompts", data_dir)

    def load_dataset(self, limit=None):
        """
        Load RealToxicityPrompts dataset from Hugging Face.

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

        # Check for cached dataset first
        cache_dir = base_dir / "datasets" / "realtoxicityprompts"
        cache_dir.mkdir(parents=True, exist_ok=True)

        print("[INFO] Loading RealToxicityPrompts from Hugging Face...")
        print(
            "[INFO] This may take a few minutes on first run (dataset is ~100k prompts)"
        )

        try:
            # Load dataset from Hugging Face
            # RealToxicityPrompts has a 'train' split with prompts
            dataset = load_dataset(
                "allenai/real-toxicity-prompts", cache_dir=str(cache_dir)
            )

            # Get the prompts from the dataset
            # RealToxicityPrompts structure:
            # - Each item has 'prompt' (dict with 'text' string and toxicity scores)
            # - 'continuation' (dict with continuation text and scores)
            # - 'challenging' (bool flag)
            test_cases = []

            # Usually in 'train' split
            split_name = "train" if "train" in dataset else list(dataset.keys())[0]
            data = dataset[split_name]

            print(f"[INFO] Processing split: {split_name} ({len(data)} prompts)")

            for i, item in enumerate(data):
                # RealToxicityPrompts structure:
                # - item['prompt'] is a dict with 'text' (string) and toxicity scores
                # - item['continuation'] is a dict with 'text' and toxicity scores
                # - item['challenging'] is a bool

                # Convert item to dict if it's a Dataset row object
                if hasattr(item, "keys") and not isinstance(item, dict):
                    item = dict(item)

                # Extract prompt text from prompt['text']
                prompt_dict = item.get("prompt", {})
                if not isinstance(prompt_dict, dict):
                    # Fallback if prompt is not a dict
                    prompt_dict = {}

                prompt_text = prompt_dict.get("text", "")

                # Skip if no valid prompt text found
                if not prompt_text or not isinstance(prompt_text, str):
                    continue

                # Clean and strip the prompt
                prompt_text = str(prompt_text).strip()
                if not prompt_text:
                    continue

                # Get toxicity score from prompt dict
                toxicity_score = prompt_dict.get("toxicity", None)

                # Get challenging flag
                is_challenging = item.get("challenging", False)

                test_cases.append(
                    {
                        "id": f"realtox_{i + 1:06d}",
                        "prompt": prompt_text,
                        "category": "toxicity",
                        "toxicity_score": toxicity_score,
                        "challenging": is_challenging,
                    }
                )

                if limit and len(test_cases) >= limit:
                    break

            print(f"[OK] Loaded {len(test_cases)} RealToxicityPrompts")
            return test_cases

        except Exception as e:
            print(f"\n[ERROR] Failed to load RealToxicityPrompts dataset: {e}")
            print(
                "[INFO] Make sure you have internet connection and 'datasets' library installed"
            )
            print("[INFO] Try: pip install datasets")
            sys.exit(1)

    def prepare_prompt(self, test_case):
        """Extract prompt from RealToxicityPrompts test case."""
        return test_case["prompt"]


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate LLM Security Firewall against RealToxicityPrompts dataset"
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
        help="Output JSON file path (default: results/realtoxicity_YYYYMMDD_HHMMSS.json)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Directory for cached dataset (default: datasets/realtoxicityprompts)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress",
    )

    args = parser.parse_args()

    # Set default limit to 1000 for testing (full dataset is ~100k)
    if args.limit is None:
        print("[INFO] No limit specified. Using default limit of 1000 for testing.")
        print(
            "[INFO] Use --limit to specify a different limit, or --limit 0 for full dataset."
        )
        args.limit = 1000

    # Set output file
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = base_dir / "results" / f"realtoxicity_{timestamp}.json"
    else:
        output_file = Path(args.output)

    # Initialize evaluator
    data_dir = Path(args.data_dir) if args.data_dir else None
    evaluator = RealToxicityPromptsEvaluator(data_dir=data_dir)

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
