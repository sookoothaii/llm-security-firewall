"""
Performance Benchmark for Decision Cache.

Tests:
- Cache hit rate (should be ≥ 70% on second run)
- Cache hit latency (should be ≤ 1 ms median)
"""

import sys
import time
import random
import string
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from llm_firewall.cache.decision_cache import get_cached, set_cached, initialize_cache
from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2


def generate_random_prompt(length: int = 50) -> str:
    """Generate random prompt for testing."""
    return "".join(random.choices(string.ascii_letters + string.digits + " ", k=length))


def benchmark_cache(
    num_prompts: int = 1000,
    tenant_id: str = "benchmark_tenant",
    redis_pool=None,
):
    """
    Benchmark decision cache performance.

    Args:
        num_prompts: Number of prompts to test
        tenant_id: Tenant identifier
        redis_pool: Optional TenantRedisPool instance
    """
    print("=" * 80)
    print("Decision Cache Performance Benchmark")
    print("=" * 80)
    print(f"Number of prompts: {num_prompts}")
    print(f"Tenant ID: {tenant_id}")
    print()

    # Initialize cache
    initialize_cache(redis_pool)

    # Initialize firewall
    firewall = FirewallEngineV2(
        allowed_tools=["web_search", "calculator"],
        strict_mode=True,
        enable_sanitization=True,
    )

    # Generate test prompts
    print("Generating test prompts...")
    prompts = [
        generate_random_prompt(random.randint(20, 100)) for _ in range(num_prompts)
    ]
    print(f"Generated {len(prompts)} prompts")
    print()

    # First run: Cold cache (all misses)
    print("=" * 80)
    print("RUN 1: Cold Cache (All Misses)")
    print("=" * 80)
    first_run_times = []
    cache_hits_1 = 0
    cache_misses_1 = 0

    start_time = time.time()
    for i, prompt in enumerate(prompts):
        # Check cache
        cache_start = time.time()
        cached = get_cached(tenant_id, prompt)
        cache_check_time = time.time() - cache_start

        if cached:
            cache_hits_1 += 1
            decision_time = cache_check_time
        else:
            cache_misses_1 += 1
            # Process through firewall
            process_start = time.time()
            decision = firewall.process_input(
                user_id=f"benchmark_user_{i}",
                text=prompt,
                tenant_id=tenant_id,
            )
            process_time = time.time() - process_start

            # Cache decision
            decision_dict = {
                "allowed": decision.allowed,
                "reason": decision.reason,
                "sanitized_text": decision.sanitized_text,
                "risk_score": decision.risk_score,
                "detected_threats": decision.detected_threats or [],
                "metadata": decision.metadata or {},
            }
            set_cached(tenant_id, prompt, decision_dict)

            decision_time = process_time

        first_run_times.append(decision_time)

        if (i + 1) % 100 == 0:
            print(f"Processed {i + 1}/{num_prompts} prompts...")

    first_run_total = time.time() - start_time
    first_run_avg = sum(first_run_times) / len(first_run_times) * 1000  # ms
    first_run_p99 = (
        sorted(first_run_times)[int(len(first_run_times) * 0.99)] * 1000
    )  # ms

    print()
    print(f"Total time: {first_run_total:.2f} s")
    print(f"Average latency: {first_run_avg:.2f} ms")
    print(f"P99 latency: {first_run_p99:.2f} ms")
    print(f"Cache hits: {cache_hits_1} ({cache_hits_1 / num_prompts * 100:.1f}%)")
    print(f"Cache misses: {cache_misses_1} ({cache_misses_1 / num_prompts * 100:.1f}%)")
    print()

    # Second run: Warm cache (should have hits)
    print("=" * 80)
    print("RUN 2: Warm Cache (Expected Hits)")
    print("=" * 80)
    second_run_times = []
    cache_hits_2 = 0
    cache_misses_2 = 0
    cache_hit_times = []

    start_time = time.time()
    for i, prompt in enumerate(prompts):
        # Check cache
        cache_start = time.time()
        cached = get_cached(tenant_id, prompt)
        cache_check_time = time.time() - cache_start

        if cached:
            cache_hits_2 += 1
            cache_hit_times.append(cache_check_time * 1000)  # ms
            decision_time = cache_check_time
        else:
            cache_misses_2 += 1
            # Process through firewall (shouldn't happen in warm cache)
            process_start = time.time()
            decision = firewall.process_input(
                user_id=f"benchmark_user_{i}",
                text=prompt,
                tenant_id=tenant_id,
            )
            process_time = time.time() - process_start

            decision_time = process_time

        second_run_times.append(decision_time)

        if (i + 1) % 100 == 0:
            print(f"Processed {i + 1}/{num_prompts} prompts...")

    second_run_total = time.time() - start_time
    second_run_avg = sum(second_run_times) / len(second_run_times) * 1000  # ms
    second_run_p99 = (
        sorted(second_run_times)[int(len(second_run_times) * 0.99)] * 1000
    )  # ms

    if cache_hit_times:
        cache_hit_median = sorted(cache_hit_times)[len(cache_hit_times) // 2]
        cache_hit_p99 = sorted(cache_hit_times)[int(len(cache_hit_times) * 0.99)]
    else:
        cache_hit_median = 0
        cache_hit_p99 = 0

    print()
    print(f"Total time: {second_run_total:.2f} s")
    print(f"Average latency: {second_run_avg:.2f} ms")
    print(f"P99 latency: {second_run_p99:.2f} ms")
    print(f"Cache hits: {cache_hits_2} ({cache_hits_2 / num_prompts * 100:.1f}%)")
    print(f"Cache misses: {cache_misses_2} ({cache_misses_2 / num_prompts * 100:.1f}%)")
    print()
    print("Cache Hit Performance:")
    print(f"  Median latency: {cache_hit_median:.2f} ms")
    print(f"  P99 latency: {cache_hit_p99:.2f} ms")
    print()

    # Results summary
    print("=" * 80)
    print("RESULTS SUMMARY")
    print("=" * 80)
    print(f"Cache hit rate (Run 2): {cache_hits_2 / num_prompts * 100:.1f}%")
    print("Target: >= 70%")
    print(f"Status: {'PASS' if cache_hits_2 / num_prompts >= 0.70 else 'FAIL'}")
    print()
    print(f"Cache hit median latency: {cache_hit_median:.2f} ms")
    print("Target: <= 1.0 ms")
    print(f"Status: {'PASS' if cache_hit_median <= 1.0 else 'FAIL'}")
    print()
    print(f"Speedup (Run 1 vs Run 2): {first_run_total / second_run_total:.2f}x")
    print()

    return {
        "num_prompts": num_prompts,
        "run1_total_time": first_run_total,
        "run1_avg_latency_ms": first_run_avg,
        "run1_p99_latency_ms": first_run_p99,
        "run1_cache_hits": cache_hits_1,
        "run1_cache_misses": cache_misses_1,
        "run2_total_time": second_run_total,
        "run2_avg_latency_ms": second_run_avg,
        "run2_p99_latency_ms": second_run_p99,
        "run2_cache_hits": cache_hits_2,
        "run2_cache_misses": cache_misses_2,
        "cache_hit_median_ms": cache_hit_median,
        "cache_hit_p99_ms": cache_hit_p99,
        "cache_hit_rate": cache_hits_2 / num_prompts,
        "speedup": first_run_total / second_run_total,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Benchmark decision cache performance")
    parser.add_argument(
        "--num-prompts",
        type=int,
        default=1000,
        help="Number of prompts to test (default: 1000)",
    )
    parser.add_argument(
        "--tenant-id",
        type=str,
        default="benchmark_tenant",
        help="Tenant ID for testing (default: benchmark_tenant)",
    )

    args = parser.parse_args()

    results = benchmark_cache(
        num_prompts=args.num_prompts,
        tenant_id=args.tenant_id,
    )

    # Exit with error if benchmarks fail
    if results["cache_hit_rate"] < 0.70:
        print("FAIL: Benchmark FAILED: Cache hit rate < 70%")
        sys.exit(1)

    if results["cache_hit_median_ms"] > 1.0:
        print("FAIL: Benchmark FAILED: Cache hit median latency > 1.0 ms")
        sys.exit(1)

    print("OK: All benchmarks PASSED")
    sys.exit(0)
