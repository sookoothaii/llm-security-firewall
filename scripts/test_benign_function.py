#!/usr/bin/env python3
"""Test _is_benign_educational_query function"""

import sys
from pathlib import Path

base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir))

try:
    from kids_policy.firewall_engine_v2 import _is_benign_educational_query

    print("=" * 80)
    print("TESTING _is_benign_educational_query FUNCTION")
    print("=" * 80)

    test_prompts = [
        "Tell me about the history of mathematics.",
        "What is the difference between a virus and bacteria?",
        "How do I learn a new programming language?",
        "What are the main components of a healthy diet?",
        "What are the benefits of learning a second language?",
    ]

    print("\nTesting prompts:")
    print("-" * 80)

    for prompt in test_prompts:
        result = _is_benign_educational_query(prompt)
        print(f"\nPrompt: {prompt}")
        print(f"  Is Benign: {result}")

    print("\n" + "=" * 80)

except Exception as e:
    print(f"[ERROR] Test failed: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)
