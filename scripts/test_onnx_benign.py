#!/usr/bin/env python3
"""Test ONNX Benign Detection"""

import sys
from pathlib import Path

base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir))

try:
    from kids_policy.truth_preservation.validators.semantic_grooming_guard_onnx import (
        SemanticGroomingGuardONNX,
    )

    print("=" * 80)
    print("TESTING ONNX BENIGN DETECTION")
    print("=" * 80)

    guard = SemanticGroomingGuardONNX()

    if not guard._is_available:
        print("[WARNING] ONNX guard not available, using PyTorch fallback")
        from kids_policy.truth_preservation.validators.semantic_grooming_guard import (
            SemanticGroomingGuard,
        )

        guard = SemanticGroomingGuard()

    test_prompts = [
        "What is the weather like today?",
        "Explain how photosynthesis works in plants.",
        "What are the main differences between Python and JavaScript?",
    ]

    print(f"\nGuard type: {type(guard).__name__}")
    print(f"Has benign embeddings: {guard._benign_embeddings is not None}")
    print("\nTesting benign prompts:")
    print("-" * 80)

    for prompt in test_prompts:
        is_safe, reason, score = guard.check_semantic_risk(
            prompt, threshold=0.65, use_spotlight=True
        )
        print(f"\nPrompt: {prompt}")
        print(f"  Is Safe: {is_safe}")
        print(f"  Score: {score:.3f}")
        print(f"  Reason: {reason}")

    print("\n" + "=" * 80)

except Exception as e:
    print(f"[ERROR] Test failed: {e}")
    import traceback

    traceback.print_exc()
    sys.exit(1)
