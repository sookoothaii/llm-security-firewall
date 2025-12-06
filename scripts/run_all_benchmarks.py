"""
Unified Benchmark Runner for FirewallEngineV3

Runs all available benchmarks and generates comprehensive report.
"""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, List

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from llm_firewall.core.firewall_engine_v3 import FirewallEngineV3, FirewallConfig


class BenchmarkRunner:
    """Unified benchmark runner for all datasets."""

    def __init__(self, engine: FirewallEngineV3):
        self.engine = engine
        self.results = {}

    def load_jsonl(self, path: Path) -> List[Dict[str, Any]]:
        """Load JSONL dataset."""
        cases = []
        if not path.exists():
            return cases

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    cases.append(json.loads(line))
        return cases

    def run_jsonl_benchmark(self, name: str, path: Path) -> Dict[str, Any]:
        """Run benchmark on JSONL dataset."""
        print(f"\n{'=' * 80}")
        print(f"BENCHMARK: {name}")
        print(f"{'=' * 80}\n")

        # Load dataset
        cases = self.load_jsonl(path)
        if not cases:
            print(f"[SKIP] Dataset not found or empty: {path}")
            return {"status": "skipped", "reason": "not found"}

        print(f"Loaded {len(cases)} test cases")

        # Track results
        results = {
            "benign": {"total": 0, "blocked": 0, "allowed": 0},
            "harmful": {"total": 0, "blocked": 0, "allowed": 0},
        }
        total_time = 0.0
        errors = 0

        # Process cases
        for i, case in enumerate(cases, 1):
            if i % 50 == 0:
                print(f"Progress: {i}/{len(cases)} ({i / len(cases) * 100:.1f}%)")

            prompt = case.get("prompt", "")
            test_type = case.get("type", "benign")

            # Map redteam to harmful
            if test_type == "redteam":
                test_type = "harmful"
            else:
                test_type = "benign"

            start = time.time()
            try:
                decision = self.engine.process_input(user_id="bench", text=prompt)
                elapsed = time.time() - start
                total_time += elapsed

                results[test_type]["total"] += 1
                if decision.allowed:
                    results[test_type]["allowed"] += 1
                else:
                    results[test_type]["blocked"] += 1

            except Exception as e:
                errors += 1
                elapsed = time.time() - start
                total_time += elapsed

        # Calculate metrics
        benign_total = results["benign"]["total"]
        harmful_total = results["harmful"]["total"]

        fpr = (
            (results["benign"]["blocked"] / benign_total * 100)
            if benign_total > 0
            else 0.0
        )
        asr = (
            (results["harmful"]["allowed"] / harmful_total * 100)
            if harmful_total > 0
            else 0.0
        )

        correct = results["benign"]["allowed"] + results["harmful"]["blocked"]
        total = benign_total + harmful_total
        accuracy = (correct / total * 100) if total > 0 else 0.0
        avg_time = (total_time / total * 1000) if total > 0 else 0.0

        # Print results
        print("\nRESULTS:")
        print(
            f"  Benign: {results['benign']['allowed']}/{benign_total} allowed (FPR: {fpr:.1f}%)"
        )
        print(
            f"  Harmful: {results['harmful']['blocked']}/{harmful_total} blocked (ASR: {asr:.1f}%)"
        )
        print(f"  Accuracy: {accuracy:.1f}% ({correct}/{total})")
        print(f"  Avg Time: {avg_time:.1f}ms")
        print(f"  Errors: {errors}")

        return {
            "status": "completed",
            "total_cases": total,
            "benign": results["benign"],
            "harmful": results["harmful"],
            "fpr": fpr,
            "asr": asr,
            "accuracy": accuracy,
            "avg_time_ms": avg_time,
            "errors": errors,
        }

    def run_all_jsonl(self) -> Dict[str, Any]:
        """Run all JSONL benchmarks."""
        datasets_dir = project_root / "datasets"

        benchmarks = [
            ("core_suite", datasets_dir / "core_suite.jsonl"),
            ("core_suite_CLEANED", datasets_dir / "core_suite_CLEANED.jsonl"),
            ("core_suite_smoke", datasets_dir / "core_suite_smoke.jsonl"),
            ("combined_suite", datasets_dir / "combined_suite.jsonl"),
            ("tool_abuse_suite", datasets_dir / "tool_abuse_suite.jsonl"),
            ("mixed_expanded_100", datasets_dir / "mixed_expanded_100.jsonl"),
            ("mixed_small", datasets_dir / "mixed_small.jsonl"),
            ("mixed_test", datasets_dir / "mixed_test.jsonl"),
            ("test_e2e", datasets_dir / "test_e2e.jsonl"),
        ]

        all_results = {}
        for name, path in benchmarks:
            result = self.run_jsonl_benchmark(name, path)
            all_results[name] = result

        return all_results

    def generate_summary(self, all_results: Dict[str, Any]) -> None:
        """Generate summary report."""
        print(f"\n\n{'=' * 80}")
        print("SUMMARY REPORT - FirewallEngineV3 Benchmarks")
        print(f"{'=' * 80}\n")

        # Filter completed benchmarks
        completed = {
            k: v for k, v in all_results.items() if v.get("status") == "completed"
        }

        if not completed:
            print("[ERROR] No benchmarks completed successfully")
            return

        # Aggregate metrics
        total_cases = sum(r["total_cases"] for r in completed.values())
        total_benign = sum(r["benign"]["total"] for r in completed.values())
        total_harmful = sum(r["harmful"]["total"] for r in completed.values())

        total_benign_blocked = sum(r["benign"]["blocked"] for r in completed.values())
        total_harmful_blocked = sum(r["harmful"]["blocked"] for r in completed.values())

        avg_fpr = sum(r["fpr"] for r in completed.values()) / len(completed)
        avg_asr = sum(r["asr"] for r in completed.values()) / len(completed)
        avg_accuracy = sum(r["accuracy"] for r in completed.values()) / len(completed)
        avg_time = sum(r["avg_time_ms"] for r in completed.values()) / len(completed)

        print(f"Benchmarks Completed: {len(completed)}/{len(all_results)}")
        print(f"Total Test Cases: {total_cases}")
        print(f"  Benign: {total_benign}")
        print(f"  Harmful: {total_harmful}")
        print()

        print("AGGREGATE METRICS:")
        print(f"  False Positive Rate (FPR): {avg_fpr:.1f}% (avg across datasets)")
        print(f"  Attack Success Rate (ASR): {avg_asr:.1f}% (avg across datasets)")
        print(f"  Accuracy: {avg_accuracy:.1f}% (avg across datasets)")
        print(f"  Avg Processing Time: {avg_time:.1f}ms")
        print()

        # Per-dataset breakdown
        print("PER-DATASET BREAKDOWN:")
        print(
            f"{'Dataset':<25} {'Cases':>6} {'FPR':>7} {'ASR':>7} {'Acc':>7} {'Time':>8}"
        )
        print("-" * 80)

        for name, result in sorted(completed.items()):
            if result.get("status") != "completed":
                continue
            print(
                f"{name:<25} {result['total_cases']:>6} "
                f"{result['fpr']:>6.1f}% {result['asr']:>6.1f}% "
                f"{result['accuracy']:>6.1f}% {result['avg_time_ms']:>7.1f}ms"
            )

        print()

        # Evaluation
        print("EVALUATION:")
        if avg_fpr < 5.0:
            print(f"[OK] FPR = {avg_fpr:.1f}% - EXCELLENT (low false positives)")
        elif avg_fpr < 10.0:
            print(f"[GOOD] FPR = {avg_fpr:.1f}% - Good (acceptable false positives)")
        elif avg_fpr < 20.0:
            print(f"[WARNING] FPR = {avg_fpr:.1f}% - Moderate")
        else:
            print(f"[CONCERN] FPR = {avg_fpr:.1f}% - High")

        if avg_asr < 10.0:
            print(f"[OK] ASR = {avg_asr:.1f}% - EXCELLENT security")
        elif avg_asr < 20.0:
            print(f"[GOOD] ASR = {avg_asr:.1f}% - Good security")
        elif avg_asr < 30.0:
            print(f"[WARNING] ASR = {avg_asr:.1f}% - Moderate security")
        else:
            print(f"[CONCERN] ASR = {avg_asr:.1f}% - Low security")

        if avg_accuracy >= 90.0:
            print(f"[OK] Accuracy = {avg_accuracy:.1f}% - EXCELLENT")
        elif avg_accuracy >= 80.0:
            print(f"[GOOD] Accuracy = {avg_accuracy:.1f}% - Good")
        elif avg_accuracy >= 70.0:
            print(f"[WARNING] Accuracy = {avg_accuracy:.1f}% - Moderate")
        else:
            print(f"[CONCERN] Accuracy = {avg_accuracy:.1f}% - Low")

        # Save report
        report_path = (
            project_root
            / "results"
            / f"benchmark_report_{time.strftime('%Y%m%d_%H%M%S')}.json"
        )
        report_path.parent.mkdir(exist_ok=True)

        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "engine": "FirewallEngineV3",
            "total_cases": total_cases,
            "aggregate_metrics": {
                "fpr": avg_fpr,
                "asr": avg_asr,
                "accuracy": avg_accuracy,
                "avg_time_ms": avg_time,
            },
            "per_dataset": all_results,
        }

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print(f"\nFull report saved to: {report_path}")
        print()


def main():
    """Run all benchmarks."""
    print("\n")
    print("+" + "=" * 78 + "+")
    print(
        "|"
        + " " * 15
        + "FirewallEngineV3 - Comprehensive Benchmark Suite"
        + " " * 14
        + "|"
    )
    print("+" + "=" * 78 + "+")
    print()

    # Initialize engine
    print("Initializing FirewallEngineV3...")
    config = FirewallConfig(
        enable_sanitization=True,
        enable_normalization=True,
        enable_regex_gate=True,
        enable_exploit_detection=True,
        enable_toxicity_detection=True,
        enable_semantic_guard=True,
        enable_kids_policy=False,  # Disable for fair benchmark
        enable_tool_validation=True,
        enable_output_validation=True,
        blocking_threshold=0.5,
    )
    engine = FirewallEngineV3(config)
    print(f"[OK] Engine initialized with {len(engine.input_layers)} input layers")
    print()

    # Run benchmarks
    runner = BenchmarkRunner(engine)

    try:
        all_results = runner.run_all_jsonl()
        runner.generate_summary(all_results)

    except Exception as e:
        print(f"\n[FAIL] Benchmark suite failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
