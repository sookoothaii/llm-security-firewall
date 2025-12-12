"""
ToxiGen Evaluation Script
==========================

Evaluates LLM Security Firewall against ToxiGen dataset.

ToxiGen contains 274K machine-generated statements targeting 13 minority groups,
focusing on subtle, implicit toxicity. This catches covert bias and stereotypes
that lack explicit slurs, a key weakness.

Source: Available on Hugging Face

Usage:
    python scripts/run_toxigen_eval.py
    python scripts/run_toxigen_eval.py --limit 1000
    python scripts/run_toxigen_eval.py --output results/toxigen_results.json
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


class ToxiGenEvaluator(BenchmarkEvaluatorBase):
    """
    Evaluator for ToxiGen dataset.

    ToxiGen tests implicit hate speech and subtle toxicity that lacks explicit slurs.
    This catches covert bias and stereotypes, a key weakness in many safety systems.
    """

    def __init__(self, data_dir=None):
        super().__init__("ToxiGen", data_dir)

    def load_dataset(self, limit=None):
        """
        Load ToxiGen dataset from Hugging Face or local file.

        Args:
            limit: Maximum number of prompts to load (None = all)

        Returns:
            List of test case dictionaries
        """
        # Try Hugging Face first
        try:
            from datasets import load_dataset
        except ImportError:
            print("\n[ERROR] Hugging Face datasets library not found.")
            print("[INFO] Install with: pip install datasets")
            print("[INFO] Trying local file instead...")
        else:
            cache_dir = base_dir / "datasets" / "toxigen"
            cache_dir.mkdir(parents=True, exist_ok=True)

            print("[INFO] Loading ToxiGen from Hugging Face...")
            print(
                "[INFO] This may take a few minutes on first run (dataset is ~274k prompts)"
            )

            try:
                # Try common Hugging Face dataset names for ToxiGen
                dataset_names = [
                    "skg/toxigen-data",
                    "toxigen/toxigen",
                    "toxigen",
                ]

                dataset = None
                for name in dataset_names:
                    try:
                        # Try without trust_remote_code first (deprecated in newer datasets versions)
                        try:
                            dataset = load_dataset(
                                name, cache_dir=str(cache_dir)
                            )
                        except Exception as e1:
                            # Fallback: try with trust_remote_code if needed (for older dataset formats)
                            if "trust_remote_code" in str(e1).lower() or "loading script" in str(e1).lower():
                                print(f"[WARNING] Dataset {name} requires trust_remote_code, trying with it...")
                                dataset = load_dataset(
                                    name, cache_dir=str(cache_dir), trust_remote_code=True
                                )
                            else:
                                raise e1
                        print(f"[OK] Loaded ToxiGen from: {name}")
                        break
                    except Exception as e:
                        print(f"[INFO] Failed to load {name}: {e}")
                        continue

                if dataset:
                    test_cases = []
                    split_name = (
                        "train" if "train" in dataset else list(dataset.keys())[0]
                    )
                    data = dataset[split_name]

                    print(
                        f"[INFO] Processing split: {split_name} ({len(data)} prompts)"
                    )

                    for i, item in enumerate(data):
                        # Extract prompt/text
                        prompt = item.get(
                            "text", item.get("prompt", item.get("statement", ""))
                        )
                        if not prompt:
                            continue

                        # Get target group if available
                        target_group = item.get(
                            "target_group",
                            item.get("group", item.get("minority_group", None)),
                        )

                        # Get toxicity type
                        toxicity_type = item.get(
                            "type", item.get("toxicity_type", "implicit")
                        )

                        test_cases.append(
                            {
                                "id": f"toxigen_{target_group or 'unknown'}_{i + 1:06d}",
                                "prompt": prompt.strip(),
                                "category": target_group
                                or toxicity_type
                                or "implicit_toxicity",
                                "target_group": target_group,
                                "toxicity_type": toxicity_type,
                            }
                        )

                        if limit and len(test_cases) >= limit:
                            break

                    print(
                        f"[OK] Loaded {len(test_cases)} ToxiGen prompts from Hugging Face"
                    )
                    return test_cases

            except Exception as e:
                print(f"[INFO] Hugging Face loading failed: {e}")
                print("[INFO] Trying local file instead...")

        # Try local file
        possible_paths = [
            base_dir / "datasets" / "toxigen" / "data.json",
            base_dir / "datasets" / "toxigen" / "data.jsonl",
            base_dir / "datasets" / "toxigen" / "toxigen.json",
            base_dir / "datasets" / "toxigen" / "toxigen.jsonl",
            self.data_dir / "data.json" if self.data_dir else None,
            self.data_dir / "data.jsonl" if self.data_dir else None,
        ]

        possible_paths = [p for p in possible_paths if p]

        data_file = None
        for path in possible_paths:
            if path and path.exists():
                data_file = path
                break

        if not data_file:
            print("\n[ERROR] ToxiGen dataset not found.")
            print("[INFO] Please download ToxiGen dataset:")
            print("  1. Hugging Face: Search for 'toxigen' dataset")
            print("  2. Or download from research paper repository")
            print("  3. Place dataset in: datasets/toxigen/")
            print("\n[INFO] Expected format:")
            print("  - JSON/JSONL file with 'text' or 'statement' field")
            print("  - Optional: 'target_group' field for minority group")
            sys.exit(1)

        print(f"[INFO] Loading ToxiGen from local file: {data_file}")

        # Load from local file
        import json

        test_cases = []

        if data_file.suffix == ".json":
            with open(data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = data.get("data", data.get("statements", [data]))
                else:
                    items = [data]

                for i, item in enumerate(items):
                    prompt = item.get(
                        "text", item.get("statement", item.get("prompt", ""))
                    )
                    if not prompt:
                        continue

                    target_group = item.get("target_group", item.get("group", None))

                    test_cases.append(
                        {
                            "id": f"toxigen_{target_group or 'unknown'}_{i + 1:06d}",
                            "prompt": prompt.strip(),
                            "category": target_group
                            or item.get("type", "implicit_toxicity"),
                        }
                    )

        elif data_file.suffix == ".jsonl":
            with open(data_file, "r", encoding="utf-8") as f:
                for i, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        item = json.loads(line)
                        prompt = item.get(
                            "text", item.get("statement", item.get("prompt", ""))
                        )
                        if not prompt:
                            continue

                        target_group = item.get("target_group", item.get("group", None))

                        test_cases.append(
                            {
                                "id": f"toxigen_{target_group or 'unknown'}_{i + 1:06d}",
                                "prompt": prompt.strip(),
                                "category": target_group
                                or item.get("type", "implicit_toxicity"),
                            }
                        )
                    except json.JSONDecodeError:
                        continue

        if limit:
            test_cases = test_cases[:limit]

        print(f"[OK] Loaded {len(test_cases)} ToxiGen prompts")
        return test_cases

    def prepare_prompt(self, test_case):
        """Extract prompt from ToxiGen test case."""
        return test_case["prompt"]


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate LLM Security Firewall against ToxiGen dataset"
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
        help="Output JSON file path (default: results/toxigen_YYYYMMDD_HHMMSS.json)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Directory containing ToxiGen dataset",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress",
    )

    args = parser.parse_args()

    # Set default limit to 1000 for testing (full dataset is 274K)
    if args.limit is None:
        print("[INFO] No limit specified. Using default limit of 1000 for testing.")
        print(
            "[INFO] Use --limit to specify a different limit, or --limit 0 for full dataset."
        )
        args.limit = 1000

    # Set output file
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = base_dir / "results" / f"toxigen_{timestamp}.json"
    else:
        output_file = Path(args.output)

    # Initialize evaluator
    data_dir = Path(args.data_dir) if args.data_dir else None
    evaluator = ToxiGenEvaluator(data_dir=data_dir)

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
