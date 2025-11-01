#!/usr/bin/env python3
"""
QUICK PERFORMANCE METRICS - ECHTE ZAHLEN JETZT
Keine Ausreden - direkt aus DoS Tests kopiert
"""

import sys
import time
sys.path.insert(0, '../../')

# Import direkt aus working test file
from tests_firewall.test_ultra_break_v4_dos import run_detectors_timed

# Test texts (klein aber repräsentativ)
test_corpus = [
    "Hello world, normal text",
    "import numpy as np\nx = np.array([1,2,3])",
    "SELECT * FROM users WHERE id = 1;",
    "\u202e\u200bhidden",  # Bidi + ZW
    "SGVsbG8gV29ybGQ=",  # Base64
    "../../etc/passwd",
    "def test():\n    return 42",
    "javascript:alert('xss')",
    "Die API erfordert JWT Token",
    "const x = 'test';"
] * 10  # 100 texts

print("=== QUICK PERFORMANCE BENCHMARK - ECHTE METRIKEN ===\n")
print("Using working DoS test infrastructure...\n")

times = []

for i, text in enumerate(test_corpus):
    start = time.perf_counter()
    action, risk, hits = run_detectors_timed(text)
    end = time.perf_counter()
    
    latency_ms = (end - start) * 1000
    times.append(latency_ms)
    
    if (i+1) % 20 == 0:
        print(f"Progress: {i+1}/{len(test_corpus)}")

# METRIKEN
times_sorted = sorted(times)
p50 = times_sorted[len(times) // 2]
p95 = times_sorted[int(len(times) * 0.95)]
p99 = times_sorted[int(len(times) * 0.99)]
mean = sum(times) / len(times)
max_lat = max(times)
min_lat = min(times)

print("\n" + "="*50)
print("ECHTE METRIKEN (100 Texte, Full Pipeline):")
print("="*50)
print(f"Min:   {min_lat:.2f} ms")
print(f"Mean:  {mean:.2f} ms")
print(f"p50:   {p50:.2f} ms")
print(f"p95:   {p95:.2f} ms")
print(f"p99:   {p99:.2f} ms")
print(f"Max:   {max_lat:.2f} ms")
print(f"\nRC3 Target: p95 <= 12ms")
print(f"Status: {'PASS' if p95 <= 12 else 'FAIL'} (p95 = {p95:.2f}ms)")
print(f"Gap:    {p95 - 12:.2f}ms {'below' if p95 <= 12 else 'above'} target")

