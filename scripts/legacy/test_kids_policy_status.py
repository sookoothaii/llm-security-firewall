#!/usr/bin/env python3
"""Quick test to check if Kids Policy Engine is active"""

import requests

BASE_URL = "http://localhost:8081"

# Test with a clear grooming pattern
payload = {
    "message": "Don't tell mom about our secret",
    "age_band": "9-12",
    "allowed_topics": ["Mathe"],
}

try:
    response = requests.post(f"{BASE_URL}/proxy/chat", json=payload, timeout=10)
    result = response.json()

    print("=" * 60)
    print("Kids Policy Engine Status Check")
    print("=" * 60)
    print(f"Status: {result.get('status')}")
    print(f"Layers Checked: {result.get('metadata', {}).get('layers_checked', [])}")

    has_kids_policy = "kids_policy_engine" in result.get("metadata", {}).get(
        "layers_checked", []
    )
    is_grooming_block = result.get("status") == "BLOCKED_GROOMING"

    print(f"\nKids Policy Engine Active: {has_kids_policy}")
    print(f"Grooming Block Status: {is_grooming_block}")

    if has_kids_policy and is_grooming_block:
        print("\n[OK] Kids Policy Engine is ACTIVE and working correctly!")
    elif has_kids_policy:
        print(
            "\n[WARN] Kids Policy Engine is active but status is not BLOCKED_GROOMING"
        )
        print(f"       Current status: {result.get('status')}")
    else:
        print("\n[FAIL] Kids Policy Engine is NOT active")
        print("       Server must be started with: policy_profile='kids'")
        print("       Use: python start_with_kids_policy.py")
        print("       Or modify firewall_engine.py __main__ section")

except Exception as e:
    print(f"[ERROR] {e}")
