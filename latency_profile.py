"""Latency Profiling for Layer 0 Performance"""
import argparse
import time
import random
import json
from datetime import datetime
from src.llm_firewall import SecurityFirewall, FirewallConfig

ap = argparse.ArgumentParser()
ap.add_argument("--n", type=int, default=5000, help="Number of samples")
ap.add_argument("--p_mal", type=float, default=0.2, help="Proportion of malicious samples")
ap.add_argument("--warmup", type=int, default=200, help="Warmup iterations")
args = ap.parse_args()

cfg = FirewallConfig()
fw = SecurityFirewall(cfg)

# Sample texts
benign = [
    "This is a regular paragraph about project status.",
    "README section: Installation steps and usage notes.",
    "The function calculates the average of input values.",
    "Documentation: Please see the wiki for details.",
    "Configuration file contains database connection parameters.",
]

malicious = [
    "alert('xss')",
    "eval('code')",
    "system('cmd')",
    "display('dialog')",
    "run('command')",
    "测试alert('xss')",
    "🅰lert('bypass')",
    "jAvAscript:alert('ocr')",
]


def one():
    """Generate random sample"""
    if random.random() < args.p_mal:
        return random.choice(malicious)
    return random.choice(benign)


print("=" * 80)
print("LATENCY PROFILING")
print("=" * 80)
print(f"Samples: {args.n}")
print(f"Warmup: {args.warmup}")
print(f"Malicious rate: {args.p_mal * 100:.0f}%")
print("=" * 80)
print()

# Warmup
print(f"Warming up ({args.warmup} iterations)...")
for _ in range(args.warmup):
    _ = fw.validate_input(one())

# Measurement
print(f"Measuring ({args.n} iterations)...")
t_total = []
t_detected = []
t_passed = []

for i in range(args.n):
    x = one()
    t0 = time.perf_counter()
    is_safe, reason = fw.validate_input(x)
    dt = (time.perf_counter() - t0) * 1000  # Convert to ms
    
    t_total.append(dt)
    if is_safe:
        t_passed.append(dt)
    else:
        t_detected.append(dt)
    
    if (i + 1) % 1000 == 0:
        print(f"  {i+1}/{args.n} samples...")

print()


def pct(arr, p):
    """Calculate percentile"""
    if not arr:
        return 0.0
    k = max(0, min(len(arr) - 1, int(p * len(arr))))
    return sorted(arr)[k]


# Calculate percentiles
print("=" * 80)
print("RESULTS")
print("=" * 80)

print("\nOVERALL LATENCY:")
print(f"  Samples: {len(t_total)}")
print(f"  Mean: {sum(t_total)/len(t_total):.2f} ms")
print(f"  P50: {pct(t_total, 0.50):.2f} ms")
print(f"  P90: {pct(t_total, 0.90):.2f} ms")
print(f"  P99: {pct(t_total, 0.99):.2f} ms")

if t_detected:
    print("\nDETECTED (BLOCKED):")
    print(f"  Samples: {len(t_detected)}")
    print(f"  Mean: {sum(t_detected)/len(t_detected):.2f} ms")
    print(f"  P50: {pct(t_detected, 0.50):.2f} ms")
    print(f"  P90: {pct(t_detected, 0.90):.2f} ms")
    print(f"  P99: {pct(t_detected, 0.99):.2f} ms")

if t_passed:
    print("\nPASSED (SAFE):")
    print(f"  Samples: {len(t_passed)}")
    print(f"  Mean: {sum(t_passed)/len(t_passed):.2f} ms")
    print(f"  P50: {pct(t_passed, 0.50):.2f} ms")
    print(f"  P90: {pct(t_passed, 0.90):.2f} ms")
    print(f"  P99: {pct(t_passed, 0.99):.2f} ms")

print("=" * 80)

# Save
res = {
    "timestamp": datetime.now().isoformat(),
    "samples": len(t_total),
    "warmup": args.warmup,
    "malicious_rate": args.p_mal,
    "overall": {
        "mean_ms": sum(t_total) / len(t_total),
        "p50_ms": pct(t_total, 0.50),
        "p90_ms": pct(t_total, 0.90),
        "p99_ms": pct(t_total, 0.99),
    },
    "detected": {
        "count": len(t_detected),
        "mean_ms": sum(t_detected) / len(t_detected) if t_detected else 0,
        "p50_ms": pct(t_detected, 0.50) if t_detected else 0,
        "p90_ms": pct(t_detected, 0.90) if t_detected else 0,
        "p99_ms": pct(t_detected, 0.99) if t_detected else 0,
    },
    "passed": {
        "count": len(t_passed),
        "mean_ms": sum(t_passed) / len(t_passed) if t_passed else 0,
        "p50_ms": pct(t_passed, 0.50) if t_passed else 0,
        "p90_ms": pct(t_passed, 0.90) if t_passed else 0,
        "p99_ms": pct(t_passed, 0.99) if t_passed else 0,
    }
}

out_file = f"latency_profile_{len(t_total)}samples_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(res, f, indent=2)

print(f"\nProfile saved to: {out_file}")

