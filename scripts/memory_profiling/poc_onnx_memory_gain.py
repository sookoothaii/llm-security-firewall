#!/usr/bin/env python3
"""
Proof of Concept: ONNX Memory Gain
==================================

Tests whether ONNX eliminates PyTorch baseline dependency.

This PoC measures memory usage at each step to determine:
1. How much of the 1.3GB baseline is caused by PyTorch/sentence-transformers imports
2. Whether ONNX class is truly free from this baseline
"""

import sys
import os
import gc
from pathlib import Path

try:
    import psutil
except ImportError:
    print("ERROR: psutil not installed. Install with: pip install psutil")
    sys.exit(1)

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "src"))
sys.path.insert(0, str(project_root))

process = psutil.Process(os.getpid())


def print_mem(label: str):
    """Print current memory usage."""
    gc.collect()
    rss_mb = process.memory_info().rss / 1024 / 1024
    print(f"{label}: {rss_mb:.1f} MB")
    return rss_mb


print("=" * 70)
print("PROOF OF CONCEPT: ONNX Memory Gain")
print("=" * 70)
print("\nTesting whether ONNX eliminates PyTorch baseline dependency.\n")

# Step 1: Python baseline
baseline = print_mem("1. Python Start")

# Step 2: Import firewall (should be minimal)
try:
    import llm_firewall  # noqa: F401

    step2 = print_mem("2. Nach Firewall-Import")
except ImportError as e:
    print(f"WARNING: Cannot import llm_firewall: {e}")
    step2 = baseline

# Step 3: Import ONNX class FIRST (should NOT trigger PyTorch)
print("\n--- IMPORTING ONNX CLASS (FIRST - NO PYTORCH) ---")
try:
    from kids_policy.truth_preservation.validators.semantic_grooming_guard_onnx import (
        SemanticGroomingGuardONNX,
    )

    step3 = print_mem("3. Nach Import ONNX-Klasse")

    # Initialize ONNX class
    print("\nInitializing ONNX class...")
    guard_onnx = SemanticGroomingGuardONNX()
    step3_init = print_mem("4. Nach ONNX Initialisierung")

    # Test inference
    result_onnx = guard_onnx.check_semantic_risk("Test sentence.", threshold=0.65)
    step3_infer = print_mem("5. Nach ONNX Inferenz")

    onnx_available = True
except ImportError as e:
    print(f"WARNING: Cannot import SemanticGroomingGuardONNX: {e}")
    step3 = step2
    step3_init = step2
    step3_infer = step2
    onnx_available = False
except Exception as e:
    print(f"ERROR during ONNX initialization: {e}")
    import traceback

    traceback.print_exc()
    step3 = step2
    step3_init = step2
    step3_infer = step2
    onnx_available = False

# Clean up ONNX instance
if onnx_available:
    try:
        SemanticGroomingGuardONNX.reset()
        del guard_onnx
        gc.collect()
        step_cleanup = print_mem("6. Nach ONNX Cleanup")
    except:
        pass

# Step 4: Import ORIGINAL PyTorch class (this should trigger PyTorch/sentence-transformers)
print("\n--- IMPORTING ORIGINAL PYTORCH CLASS ---")
try:
    from kids_policy.truth_preservation.validators.semantic_grooming_guard import (
        SemanticGroomingGuard,
    )

    step4 = print_mem("7. Nach Import ORIGINAL (PyTorch)")

    # Initialize PyTorch class
    print("\nInitializing PyTorch class...")
    guard_pytorch = SemanticGroomingGuard()
    step4_init = print_mem("8. Nach PyTorch Initialisierung")

    # Test inference
    result_pytorch = guard_pytorch.check_semantic_risk("Test sentence.", threshold=0.65)
    step4_infer = print_mem("9. Nach PyTorch Inferenz")

    pytorch_available = True
except ImportError as e:
    print(f"WARNING: Cannot import SemanticGroomingGuard: {e}")
    step4 = step3_infer if onnx_available else step2
    step4_init = step4
    step4_infer = step4
    pytorch_available = False
except Exception as e:
    print(f"ERROR during PyTorch initialization: {e}")
    step4 = step3_infer if onnx_available else step2
    step4_init = step4
    step4_infer = step4
    pytorch_available = False

# Summary
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

if onnx_available:
    onnx_import_cost = step3 - step2
    onnx_init_cost = step3_init - step3
    onnx_total_cost = step3_infer - step2
    print(f"\nONNX Import Cost: {onnx_import_cost:.1f} MB")
    print(f"ONNX Init Cost: {onnx_init_cost:.1f} MB")
    print(f"ONNX Total Cost: {onnx_total_cost:.1f} MB")
else:
    print("\nONNX class not available")

if pytorch_available:
    # PyTorch cost is measured AFTER ONNX, so we need baseline from step2
    # But PyTorch import happens at step4, so cost is step4 - step2
    # However, ONNX might have already loaded some dependencies
    # So we measure: step4 - step3_infer (additional cost after ONNX)
    pytorch_additional_import = step4 - step3_infer if onnx_available else step4 - step2
    pytorch_init_cost = step4_init - step4
    pytorch_total_cost = step4_infer - step2
    pytorch_import_cost = step4 - step2  # Total import cost from baseline

    print(f"\nPyTorch Import Cost (from baseline): {pytorch_import_cost:.1f} MB")
    print(f"PyTorch Additional Cost (after ONNX): {pytorch_additional_import:.1f} MB")
    print(f"PyTorch Init Cost: {pytorch_init_cost:.1f} MB")
    print(f"PyTorch Total Cost: {pytorch_total_cost:.1f} MB")

    if onnx_available:
        savings = pytorch_total_cost - onnx_total_cost
        savings_pct = (
            (savings / pytorch_total_cost * 100) if pytorch_total_cost > 0 else 0
        )
        print(f"\nMemory Savings: {savings:.1f} MB ({savings_pct:.1f}% reduction)")

        if savings > 100:  # Significant savings threshold
            print("\n[SUCCESS] ONNX eliminates PyTorch baseline!")
        elif savings > 0:
            print("\n[PARTIAL] ONNX reduces memory, but PyTorch still loaded")
            print("   Possible causes:")
            print("   - PyTorch/sentence-transformers imported transitively in ONNX")
            print("   - ONNX Runtime overhead")
        else:
            print("\n[WARNING] ONNX does not eliminate PyTorch baseline")
            print("   Possible causes:")
            print("   - PyTorch/sentence-transformers imported transitively")
            print("   - ONNX Runtime overhead higher than expected")
            print("   - Tokenizer (transformers) still requires PyTorch")
else:
    print("\nPyTorch class not available for comparison")

print("\n" + "=" * 70)
