"""
DoNotAnswer Evaluation Script
==============================

Evaluates LLM Security Firewall against DoNotAnswer dataset.

DoNotAnswer contains 900+ harmful queries across 12 categories to test if a model
correctly refuses to answer. This tests nuanced understanding of ethical refusal,
not just content filtering.

Usage:
    python scripts/run_donotanswer_eval.py
    python scripts/run_donotanswer_eval.py --limit 100
    python scripts/run_donotanswer_eval.py --output results/donotanswer_results.json
"""

import argparse
import json
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


class DoNotAnswerEvaluator(BenchmarkEvaluatorBase):
    """
    Evaluator for DoNotAnswer dataset.

    DoNotAnswer tests if a model correctly refuses to answer harmful queries.
    This is about nuanced understanding of ethical refusal, not just content filtering.
    """

    def __init__(self, data_dir=None):
        super().__init__("DoNotAnswer", data_dir)

    def load_dataset(self, limit=None):
        """
        Load DoNotAnswer dataset from Hugging Face or local file.

        Args:
            limit: Maximum number of queries to load (None = all)

        Returns:
            List of test case dictionaries
        """
        # Try to load from Hugging Face first (preferred method)
        try:
            from datasets import load_dataset
        except ImportError:
            print("\n[ERROR] Hugging Face datasets library not found.")
            print("[INFO] Install with: pip install datasets")
            print("[INFO] Falling back to local file search...")
        else:
            cache_dir = base_dir / "datasets" / "donotanswer"
            cache_dir.mkdir(parents=True, exist_ok=True)

            print("[INFO] Loading DoNotAnswer from Hugging Face...")
            print("[INFO] Dataset: LibrAI/do-not-answer")
            print("[INFO] This may take a few minutes on first run")

            try:
                # Load dataset from Hugging Face
                dataset = load_dataset("LibrAI/do-not-answer", cache_dir=str(cache_dir))

                # Process dataset
                test_cases = []

                # Get the first available split (usually "train")
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

                    # DoNotAnswer format: has "question" field
                    question = item.get("question", "")
                    if not question or not isinstance(question, str):
                        continue

                    # Extract category information
                    risk_area = item.get("risk_area", "")
                    types_of_harm = item.get("types_of_harm", "")
                    specific_harms = item.get("specific_harms", "")

                    # Combine category info
                    category_parts = []
                    if risk_area:
                        category_parts.append(risk_area)
                    if types_of_harm:
                        category_parts.append(types_of_harm)
                    category = (
                        "_".join(category_parts) if category_parts else "harmful_query"
                    )

                    test_cases.append(
                        {
                            "id": f"donotanswer_{item.get('id', i + 1):04d}",
                            "prompt": str(question).strip(),
                            "category": category,
                            "risk_area": risk_area,
                            "types_of_harm": types_of_harm,
                            "specific_harms": specific_harms,
                        }
                    )

                    if limit and len(test_cases) >= limit:
                        break

                print(
                    f"[OK] Loaded {len(test_cases)} DoNotAnswer queries from Hugging Face"
                )
                return test_cases

            except Exception as e:
                print(f"\n[WARNING] Failed to load DoNotAnswer from Hugging Face: {e}")
                print("[INFO] Falling back to local file search...")

        # Fallback: Check multiple possible locations and formats
        possible_paths = [
            # Hugging Face cache
            base_dir / "datasets" / "donotanswer" / "donotanswer.json",
            base_dir / "datasets" / "donotanswer" / "donotanswer.jsonl",
            base_dir / "datasets" / "donotanswer" / "data.json",
            base_dir / "datasets" / "donotanswer" / "data.jsonl",
            # Direct in datasets
            base_dir / "datasets" / "donotanswer.json",
            base_dir / "datasets" / "donotanswer.jsonl",
            # Custom data dir
            self.data_dir / "donotanswer.json" if self.data_dir else None,
            self.data_dir / "donotanswer.jsonl" if self.data_dir else None,
        ]

        # Remove None values
        possible_paths = [p for p in possible_paths if p]

        data_file = None
        for path in possible_paths:
            if path and path.exists():
                data_file = path
                break

        if not data_file:
            print("\n[ERROR] DoNotAnswer dataset not found.")
            print(
                "[INFO] Please download DoNotAnswer dataset to one of these locations:"
            )
            for path in possible_paths[:5]:
                print(f"  - {path}")
            print("\n[INFO] Or install 'datasets' library for auto-download:")
            print("  pip install datasets")
            print("\n[INFO] DoNotAnswer dataset format:")
            print("  - JSON: Array of objects with 'question' or 'prompt' field")
            print("  - JSONL: One JSON object per line")
            print("  - CSV: 'question' or 'prompt' column")
            print("\n[INFO] Expected structure:")
            print("  - Each item should have a question/prompt field")
            print("  - Optional: 'category' field for categorization")
            sys.exit(1)

        print(f"[INFO] Loading DoNotAnswer from: {data_file}")
        test_cases = []

        # Load JSON format
        if data_file.suffix == ".json":
            with open(data_file, "r", encoding="utf-8") as f:
                data = json.load(f)

                # Handle array of items or dict with items
                if isinstance(data, list):
                    items = data
                elif isinstance(data, dict):
                    items = data.get(
                        "data", data.get("queries", data.get("questions", [data]))
                    )
                else:
                    items = [data]

                for i, item in enumerate(items):
                    prompt = item.get(
                        "question", item.get("prompt", item.get("text", ""))
                    )
                    if not prompt:
                        continue

                    test_cases.append(
                        {
                            "id": item.get("id", f"donotanswer_{i + 1:04d}"),
                            "prompt": prompt.strip(),
                            "category": item.get(
                                "category", item.get("type", "harmful_query")
                            ),
                        }
                    )

        # Load JSONL format
        elif data_file.suffix == ".jsonl":
            with open(data_file, "r", encoding="utf-8") as f:
                for i, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        item = json.loads(line)
                        prompt = item.get(
                            "question", item.get("prompt", item.get("text", ""))
                        )
                        if not prompt:
                            continue

                        test_cases.append(
                            {
                                "id": item.get("id", f"donotanswer_{i + 1:04d}"),
                                "prompt": prompt.strip(),
                                "category": item.get(
                                    "category", item.get("type", "harmful_query")
                                ),
                            }
                        )
                    except json.JSONDecodeError:
                        continue

        # Load CSV format
        elif data_file.suffix == ".csv":
            import csv

            with open(data_file, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    prompt = row.get("question", row.get("prompt", row.get("text", "")))
                    if not prompt:
                        continue

                    test_cases.append(
                        {
                            "id": row.get("id", f"donotanswer_{i + 1:04d}"),
                            "prompt": prompt.strip(),
                            "category": row.get(
                                "category", row.get("type", "harmful_query")
                            ),
                        }
                    )

        if limit:
            test_cases = test_cases[:limit]

        print(f"[OK] Loaded {len(test_cases)} DoNotAnswer queries")
        return test_cases

    def prepare_prompt(self, test_case):
        """Extract prompt from DoNotAnswer test case."""
        return test_case["prompt"]


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate LLM Security Firewall against DoNotAnswer dataset"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of queries to evaluate (None = all)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON file path (default: results/donotanswer_YYYYMMDD_HHMMSS.json)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Directory containing DoNotAnswer dataset (default: datasets/donotanswer)",
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
        output_file = base_dir / "results" / f"donotanswer_{timestamp}.json"
    else:
        output_file = Path(args.output)

    # Initialize evaluator
    data_dir = Path(args.data_dir) if args.data_dir else None
    evaluator = DoNotAnswerEvaluator(data_dir=data_dir)

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
