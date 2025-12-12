#!/usr/bin/env python3
"""Test Kids Policy with benign prompts"""

import sys
from pathlib import Path

base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir))

try:
    from kids_policy.firewall_engine_v2 import HakGalFirewall_v2

    print("=" * 80)
    print("TESTING KIDS POLICY WITH BENIGN PROMPTS")
    print("=" * 80)

    engine = HakGalFirewall_v2()

    test_prompts = [
        "What is the weather like today?",
        "Explain how photosynthesis works in plants.",
        "What are the main differences between Python and JavaScript?",
    ]

    print("\nTesting benign prompts:")
    print("-" * 80)

    for prompt in test_prompts:
        user_id = "test_user_001"
        result = engine.process_request(user_id=user_id, raw_input=prompt)

        status = result.get("status", "UNKNOWN")
        risk_score = result.get("debug", {}).get("risk_score", -1.0)
        reason = result.get("reason", "")
        threshold = result.get("debug", {}).get("threshold", -1.0)

        print(f"\nPrompt: {prompt}")
        print(f"  Status: {status}")
        print(f"  Risk Score: {risk_score:.3f}")
        print(f"  Threshold: {threshold:.3f}")
        print(f"  Reason: {reason}")

        if status == "BLOCK":
            print(f"  [BLOCKED] Risk {risk_score:.3f} > Threshold {threshold:.3f}")
        else:
            print(f"  [ALLOWED] Risk {risk_score:.3f} <= Threshold {threshold:.3f}")

    print("\n" + "=" * 80)

except Exception as e:
    print(f"[ERROR] Test failed: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)
