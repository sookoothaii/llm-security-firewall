"""
Simple Cache Test - Verify cache works with identical prompts.
"""

import sys
import time
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from llm_firewall.core.firewall_engine_v2 import FirewallEngineV2

# Test with identical prompt
test_prompt = "What is 2+2?"
tenant_id = "test_tenant"

print("=" * 80)
print("Simple Cache Test - Identical Prompts")
print("=" * 80)
print()

# Initialize firewall
firewall = FirewallEngineV2(
    allowed_tools=["web_search", "calculator"],
    strict_mode=True,
    enable_sanitization=True,
)

# First request (should miss)
print("Request 1: Cold cache")
start = time.time()
decision1 = firewall.process_input(
    user_id="test_user",
    text=test_prompt,
    tenant_id=tenant_id,
)
time1 = (time.time() - start) * 1000
print(f"  Time: {time1:.2f} ms")
print(f"  Allowed: {decision1.allowed}")
print()

# Second request (should hit cache)
print("Request 2: Warm cache (should hit)")
start = time.time()
decision2 = firewall.process_input(
    user_id="test_user",
    text=test_prompt,
    tenant_id=tenant_id,
)
time2 = (time.time() - start) * 1000
print(f"  Time: {time2:.2f} ms")
print(f"  Allowed: {decision2.allowed}")
print()

# Third request (should hit cache)
print("Request 3: Warm cache (should hit)")
start = time.time()
decision3 = firewall.process_input(
    user_id="test_user",
    text=test_prompt,
    tenant_id=tenant_id,
)
time3 = (time.time() - start) * 1000
print(f"  Time: {time3:.2f} ms")
print(f"  Allowed: {decision3.allowed}")
print()

print("=" * 80)
print("RESULTS")
print("=" * 80)
print(f"Request 1 (cold): {time1:.2f} ms")
print(f"Request 2 (warm): {time2:.2f} ms")
print(f"Request 3 (warm): {time3:.2f} ms")
print()
print(f"Speedup (Req1 vs Req2): {time1 / time2:.2f}x")
print(f"Speedup (Req1 vs Req3): {time1 / time3:.2f}x")
print()

if time2 < 1.0 and time3 < 1.0:
    print("OK: Cache hit latency < 1 ms")
else:
    print(
        f"WARNING: Cache hit latency > 1 ms (Req2: {time2:.2f} ms, Req3: {time3:.2f} ms)"
    )
