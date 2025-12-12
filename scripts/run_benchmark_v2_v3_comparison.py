"""
Benchmark V2 vs V3 Comparison Script
=====================================

Runs all benchmarks with both FirewallEngineV2 and FirewallEngineV3,
provides detailed progress information, and generates a comparison report.

Usage:
    python scripts/run_benchmark_v2_v3_comparison.py
    python scripts/run_benchmark_v2_v3_comparison.py --benchmark harmbench
    python scripts/run_benchmark_v2_v3_comparison.py --limit 100
"""

import argparse
import json
import sys
import os
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

# CRITICAL: Enforce GPU usage BEFORE any imports that might initialize ML models
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
    
    print(f"[GPU CHECK] CUDA available: {torch.cuda.is_available()}")
    print(f"[GPU CHECK] Device: {torch.cuda.get_device_name(0)}")
    print(f"[GPU CHECK] CUDA Version: {torch.version.cuda}")
    
    os.environ['TORCH_DEVICE'] = 'cuda'
    if 'CUDA_VISIBLE_DEVICES' not in os.environ:
        os.environ['CUDA_VISIBLE_DEVICES'] = '0'
    
    print(f"[GPU CHECK] GPU enforcement: TORCH_DEVICE=cuda set\n")
except ImportError:
    print("[WARNING] PyTorch not available - cannot verify GPU")
except Exception as e:
    print(f"[ERROR] GPU check failed: {e}")
    sys.exit(1)

# Add parent directory to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir / "src"))

try:
    from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2
    from llm_firewall.core.firewall_engine_v3 import FirewallEngineV3, EmergencyFixFirewallConfig
except ImportError as e:
    print(f"[ERROR] Failed to import firewall engines: {e}")
    sys.exit(1)


@dataclass
class BenchmarkResult:
    """Result for a single benchmark run."""
    engine_version: str
    benchmark_name: str
    total_tests: int
    blocked: int
    allowed: int
    asr: float
    fpr: Optional[float] = None
    avg_risk_score: float = 0.0
    avg_latency_ms: float = 0.0
    duration_seconds: float = 0.0
    errors: int = 0


@dataclass
class ComparisonReport:
    """Comparison report between V2 and V3."""
    benchmark_name: str
    v2_result: BenchmarkResult
    v3_result: BenchmarkResult
    asr_improvement: float  # Negative = better (lower ASR)
    fpr_improvement: Optional[float] = None  # Negative = better (lower FPR)
    speed_improvement: float  # Positive = faster
    recommendation: str


def print_progress(current: int, total: int, prefix: str = "", suffix: str = ""):
    """Print progress bar."""
    percent = (current / total) * 100 if total > 0 else 0
    bar_length = 50
    filled = int(bar_length * current / total) if total > 0 else 0
    bar = "=" * filled + "-" * (bar_length - filled)
    print(f"\r{prefix}[{bar}] {percent:.1f}% {suffix}", end="", flush=True)
    if current >= total:
        print()  # New line when complete


def run_benchmark_with_engine(
    engine_version: str,
    benchmark_name: str,
    test_cases: List[Dict[str, Any]],
    verbose: bool = False
) -> BenchmarkResult:
    """
    Run benchmark with specified engine version.
    
    Args:
        engine_version: "v2" or "v3"
        benchmark_name: Name of the benchmark
        test_cases: List of test case dictionaries
        verbose: Print detailed progress
        
    Returns:
        BenchmarkResult
    """
    print(f"\n{'='*80}")
    print(f"RUNNING: {benchmark_name.upper()} with FirewallEngine{engine_version.upper()}")
    print(f"{'='*80}")
    
    # Initialize engine
    print(f"\n[1] Initializing FirewallEngine{engine_version.upper()}...")
    start_init = time.time()
    
    if engine_version == "v2":
        engine = FirewallEngineV2()
    elif engine_version == "v3":
        config = EmergencyFixFirewallConfig(enable_kids_policy=False)
        engine = FirewallEngineV3(config)
    else:
        raise ValueError(f"Unknown engine version: {engine_version}")
    
    init_time = time.time() - start_init
    print(f"[OK] Engine initialized in {init_time:.2f}s")
    
    # Log device information
    import os
    import torch
    if torch.cuda.is_available():
        device = "cuda"
        device_name = torch.cuda.get_device_name(0)
        print(f"[INFO] Using GPU: {device_name}")
    else:
        device = "cpu"
        print(f"[WARNING] Using CPU (GPU not available)")
    
    print(f"[INFO] TORCH_DEVICE env: {os.environ.get('TORCH_DEVICE', 'not set')}")
    print(f"[INFO] CUDA_VISIBLE_DEVICES: {os.environ.get('CUDA_VISIBLE_DEVICES', 'not set')}")
    
    # Run evaluation
    print(f"\n[2] Evaluating {len(test_cases)} test cases...")
    print(f"[INFO] Progress will be shown every 10%")
    
    results = []
    blocked = 0
    allowed = 0
    total_risk = 0.0
    total_latency = 0.0
    errors = 0
    
    start_time = time.time()
    
    for i, test_case in enumerate(test_cases, 1):
        # Progress update every 10%
        if i % max(1, len(test_cases) // 10) == 0 or i == len(test_cases):
            progress_pct = (i / len(test_cases)) * 100
            print_progress(
                i, len(test_cases),
                prefix=f"[{engine_version.upper()}] ",
                suffix=f"({i}/{len(test_cases)}) - Blocked: {blocked}, Allowed: {allowed}, ASR: {(allowed/i)*100:.1f}%"
            )
        
        try:
            # Extract prompt
            prompt = test_case.get("prompt", test_case.get("text", ""))
            if not prompt:
                continue
            
            # Evaluate
            eval_start = time.time()
            
            if engine_version == "v2":
                decision = engine.process_input("benchmark_test", prompt)
            else:  # v3
                decision = engine.process_input("benchmark_test", prompt)
            
            eval_time = (time.time() - eval_start) * 1000  # ms
            total_latency += eval_time
            
            # Track results
            if decision.allowed:
                allowed += 1
            else:
                blocked += 1
            
            total_risk += decision.risk_score
            
            if verbose and i <= 5:  # Show first 5 in verbose mode
                status = "ALLOWED" if decision.allowed else "BLOCKED"
                print(f"\n  [{i}] {status} - Risk: {decision.risk_score:.3f}, Latency: {eval_time:.1f}ms")
                if hasattr(decision, 'reason'):
                    print(f"      Reason: {decision.reason[:100]}")
        
        except Exception as e:
            errors += 1
            if verbose:
                print(f"\n[ERROR] Test case {i} failed: {e}")
    
    duration = time.time() - start_time
    
    # Calculate metrics
    total_tests = len(test_cases) - errors
    asr = (allowed / total_tests * 100) if total_tests > 0 else 0.0
    avg_risk = total_risk / total_tests if total_tests > 0 else 0.0
    avg_latency = total_latency / total_tests if total_tests > 0 else 0.0
    
    print(f"\n[3] Results Summary:")
    print(f"    Total Tests: {total_tests}")
    print(f"    Blocked: {blocked} ({blocked/total_tests*100:.1f}%)")
    print(f"    Allowed: {allowed} ({allowed/total_tests*100:.1f}%)")
    print(f"    ASR: {asr:.2f}%")
    print(f"    Avg Risk Score: {avg_risk:.3f}")
    print(f"    Avg Latency: {avg_latency:.1f}ms")
    print(f"    Duration: {duration:.2f}s")
    if errors > 0:
        print(f"    Errors: {errors}")
    
    return BenchmarkResult(
        engine_version=engine_version.upper(),
        benchmark_name=benchmark_name,
        total_tests=total_tests,
        blocked=blocked,
        allowed=allowed,
        asr=asr,
        avg_risk_score=avg_risk,
        avg_latency_ms=avg_latency,
        duration_seconds=duration,
        errors=errors
    )


def compare_results(v2_result: BenchmarkResult, v3_result: BenchmarkResult) -> ComparisonReport:
    """Compare V2 and V3 results."""
    asr_improvement = v3_result.asr - v2_result.asr  # Negative = better
    speed_improvement = ((v2_result.duration_seconds - v3_result.duration_seconds) / v2_result.duration_seconds) * 100 if v2_result.duration_seconds > 0 else 0.0
    
    # Determine recommendation
    if asr_improvement < -2.0:  # V3 has significantly lower ASR
        recommendation = "V3 RECOMMENDED: Significantly better security (ASR improved by {:.1f}%)".format(abs(asr_improvement))
    elif asr_improvement > 2.0:  # V2 has significantly lower ASR
        recommendation = "V2 RECOMMENDED: Better security (ASR {:.1f}% lower)".format(asr_improvement)
    elif speed_improvement > 10:  # V3 is significantly faster
        recommendation = "V3 RECOMMENDED: Similar security, significantly faster ({:.1f}% speedup)".format(speed_improvement)
    elif speed_improvement < -10:  # V2 is significantly faster
        recommendation = "V2 RECOMMENDED: Similar security, faster ({:.1f}% speedup)".format(abs(speed_improvement))
    else:
        recommendation = "SIMILAR PERFORMANCE: Both engines perform comparably"
    
    fpr_improvement = None
    if v2_result.fpr is not None and v3_result.fpr is not None:
        fpr_improvement = v3_result.fpr - v2_result.fpr  # Negative = better
    
    return ComparisonReport(
        benchmark_name=v2_result.benchmark_name,
        v2_result=v2_result,
        v3_result=v3_result,
        asr_improvement=asr_improvement,
        fpr_improvement=fpr_improvement,
        speed_improvement=speed_improvement,
        recommendation=recommendation
    )


def print_comparison_report(report: ComparisonReport):
    """Print formatted comparison report."""
    print(f"\n{'='*80}")
    print(f"COMPARISON REPORT: {report.benchmark_name.upper()}")
    print(f"{'='*80}")
    
    print(f"\n{'Metric':<30} {'V2':<20} {'V3':<20} {'Difference':<15}")
    print("-" * 85)
    print(f"{'Attack Success Rate (ASR)':<30} {report.v2_result.asr:>6.2f}%{'':<13} {report.v3_result.asr:>6.2f}%{'':<13} {report.asr_improvement:>+6.2f}%")
    if report.fpr_improvement is not None:
        print(f"{'False Positive Rate (FPR)':<30} {report.v2_result.fpr:>6.2f}%{'':<13} {report.v3_result.fpr:>6.2f}%{'':<13} {report.fpr_improvement:>+6.2f}%")
    print(f"{'Blocked':<30} {report.v2_result.blocked:>6}{'':<14} {report.v3_result.blocked:>6}{'':<14} {report.v3_result.blocked - report.v2_result.blocked:>+6}")
    print(f"{'Allowed':<30} {report.v2_result.allowed:>6}{'':<14} {report.v3_result.allowed:>6}{'':<14} {report.v3_result.allowed - report.v2_result.allowed:>+6}")
    print(f"{'Avg Risk Score':<30} {report.v2_result.avg_risk_score:>6.3f}{'':<14} {report.v3_result.avg_risk_score:>6.3f}{'':<14} {report.v3_result.avg_risk_score - report.v2_result.avg_risk_score:>+6.3f}")
    print(f"{'Avg Latency (ms)':<30} {report.v2_result.avg_latency_ms:>6.1f}{'':<14} {report.v3_result.avg_latency_ms:>6.1f}{'':<14} {report.v3_result.avg_latency_ms - report.v2_result.avg_latency_ms:>+6.1f}")
    print(f"{'Duration (s)':<30} {report.v2_result.duration_seconds:>6.2f}{'':<14} {report.v3_result.duration_seconds:>6.2f}{'':<14} {report.v3_result.duration_seconds - report.v2_result.duration_seconds:>+6.2f}")
    
    print(f"\n{'RECOMMENDATION:':<30} {report.recommendation}")
    print(f"{'='*80}\n")


def load_core_suite() -> List[Dict[str, Any]]:
    """Load core_suite.jsonl dataset."""
    dataset_path = base_dir / "datasets" / "core_suite.jsonl"
    
    if not dataset_path.exists():
        print(f"[ERROR] Dataset not found at: {dataset_path}")
        return []
    
    prompts = []
    with open(dataset_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                prompts.append(data)
    
    return prompts


def load_harmbench() -> List[Dict[str, Any]]:
    """Load HarmBench dataset."""
    import csv
    
    harmbench_dir = base_dir / "tests" / "benchmarks" / "harmbench" / "data" / "behavior_datasets"
    
    if not harmbench_dir.exists():
        print(f"[ERROR] HarmBench not found at: {harmbench_dir}")
        return []
    
    csv_files = list(harmbench_dir.glob("*.csv"))
    if not csv_files:
        print(f"[ERROR] No CSV files in {harmbench_dir}")
        return []
    
    prompts = []
    for csv_file in csv_files:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                behavior = row.get("Behavior", "")
                if behavior:
                    prompts.append({
                        "prompt": behavior,
                        "category": row.get("SemanticCategory", "unknown"),
                        "id": row.get("BehaviorID", f"hb_{len(prompts)}")
                    })
    
    return prompts


def main():
    parser = argparse.ArgumentParser(
        description="Compare FirewallEngineV2 vs FirewallEngineV3 on benchmarks"
    )
    parser.add_argument(
        "--benchmark",
        type=str,
        default="core_suite",
        choices=["core_suite", "harmbench"],
        help="Benchmark to run (default: core_suite)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit number of test cases (default: all)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress for each test case"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON file path"
    )
    
    args = parser.parse_args()
    
    print("="*80)
    print("FIREWALL ENGINE V2 vs V3 COMPARISON")
    print("="*80)
    print(f"Benchmark: {args.benchmark}")
    print(f"Limit: {args.limit if args.limit else 'All'}")
    print(f"Verbose: {args.verbose}")
    
    # Load test cases
    print(f"\n[0] Loading test cases...")
    if args.benchmark == "core_suite":
        test_cases = load_core_suite()
    elif args.benchmark == "harmbench":
        test_cases = load_harmbench()
    else:
        print(f"[ERROR] Benchmark '{args.benchmark}' not yet implemented")
        print("[INFO] Currently supported: core_suite, harmbench")
        sys.exit(1)
    
    if args.limit:
        test_cases = test_cases[:args.limit]
    
    print(f"[OK] Loaded {len(test_cases)} test cases")
    
    # Run V2
    v2_result = run_benchmark_with_engine("v2", args.benchmark, test_cases, args.verbose)
    
    # Run V3
    v3_result = run_benchmark_with_engine("v3", args.benchmark, test_cases, args.verbose)
    
    # Compare
    comparison = compare_results(v2_result, v3_result)
    print_comparison_report(comparison)
    
    # Save results
    if args.output:
        output_file = Path(args.output)
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = base_dir / "results" / f"v2_v3_comparison_{args.benchmark}_{timestamp}.json"
    
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump({
            "benchmark": args.benchmark,
            "timestamp": datetime.now().isoformat(),
            "v2_result": asdict(v2_result),
            "v3_result": asdict(v3_result),
            "comparison": {
                "asr_improvement": comparison.asr_improvement,
                "fpr_improvement": comparison.fpr_improvement,
                "speed_improvement": comparison.speed_improvement,
                "recommendation": comparison.recommendation
            }
        }, f, indent=2)
    
    print(f"[OK] Results saved to: {output_file}")
    print("\n[COMPLETE] Comparison finished!")


if __name__ == "__main__":
    main()

