#!/usr/bin/env python3
"""
METRIKEN JETZT - Keine Ausreden!
Nutzt existierende Test-Infrastruktur
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests_firewall.test_ultra_break_v4_dos import run_detectors_timed

# Test corpus - realistisch
test_texts = [
    "Hello, normal user message",
    "import numpy as np",
    "SELECT * FROM users;",
    "def test(): return 42",
    "SGVsbG8=",  # Base64
    "../../etc/passwd",
    "javascript:alert('xss')",
    "\u202ehidden",  # Bidi
    "const x = 'test';",
    "Die API nutzt JWT",
] * 10  # 100 texts

print("=== ECHTE METRIKEN - 100 TEXTS ===\n")

times_ms = []

for i, text in enumerate(test_texts):
    try:
        hits, elapsed = run_detectors_timed(text)
        latency_ms = elapsed * 1000  # Convert to ms
        times_ms.append(latency_ms)
    except Exception as e:
        print(f"Error on text {i}: {e}")
        continue

    if (i + 1) % 20 == 0:
        print(f"{i + 1}/100 completed")

# METRIKEN
times_sorted = sorted(times_ms)
n = len(times_sorted)
p50_idx = n // 2
p95_idx = int(n * 0.95)
p99_idx = int(n * 0.99)

mean = sum(times_ms) / n
p50 = times_sorted[p50_idx]
p95 = times_sorted[p95_idx]
p99 = times_sorted[p99_idx]
min_t = min(times_ms)
max_t = max(times_ms)

print("\n" + "=" * 60)
print("PERFORMANCE METRIKEN (Full Pipeline, N=100):")
print("=" * 60)
print(f"Min:    {min_t:.3f} ms")
print(f"Mean:   {mean:.3f} ms")
print(f"Median: {p50:.3f} ms")
print(f"p95:    {p95:.3f} ms")
print(f"p99:    {p99:.3f} ms")
print(f"Max:    {max_t:.3f} ms")
print("")
print("RC3 Target:  p95 <= 12.0 ms")
print(f"Actual p95:  {p95:.3f} ms")
print(f"Status:      {'✓ PASS' if p95 <= 12 else '✗ FAIL'}")
print(f"Gap:         {p95 - 12:.3f} ms {'under' if p95 <= 12 else 'over'} target")
print("")
print(f"Throughput:  ~{1000 / mean:.1f} requests/second")
