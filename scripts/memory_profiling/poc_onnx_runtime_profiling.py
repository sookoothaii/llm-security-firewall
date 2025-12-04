#!/usr/bin/env python3
"""
ONNX Runtime Profiling
======================

Tests memory cost of ONNX Runtime import and different provider configurations.
"""

import sys
import os
import gc
from pathlib import Path

try:
    import psutil
except ImportError:
    print("ERROR: psutil not installed")
    sys.exit(1)

process = psutil.Process(os.getpid())


def mem(label: str):
    """Get current memory usage in MB."""
    gc.collect()
    rss_mb = process.memory_info().rss / 1024 / 1024
    print(f"{label}: {rss_mb:.1f} MB")
    return rss_mb


print("=" * 70)
print("ONNX RUNTIME PROFILING")
print("=" * 70)

baseline = mem("1. Python Start")

# Test: Import onnxruntime
print("\n--- IMPORTING ONNXRUNTIME ---")
try:
    import onnxruntime as ort

    step1 = mem("2. Nach 'import onnxruntime'")

    # Get available providers
    available_providers = ort.get_available_providers()
    print(f"Available providers: {available_providers}")

    # Find ONNX model path
    project_root = Path(__file__).parent.parent.parent
    onnx_model_path = project_root / "models" / "onnx" / "all-MiniLM-L6-v2.onnx"

    if not onnx_model_path.exists():
        print(f"\nERROR: ONNX model not found at {onnx_model_path}")
        print("Skipping session creation tests...")
    else:
        print("\n--- CREATING ONNX SESSIONS ---")
        print(f"Model path: {onnx_model_path}")

        # Test different provider configurations
        provider_configs = [
            (["CPUExecutionProvider"], "CPU only"),
            (["CUDAExecutionProvider", "CPUExecutionProvider"], "CUDA + CPU"),
        ]

        for providers, description in provider_configs:
            # Filter to only available providers
            available = [p for p in providers if p in available_providers]
            if not available:
                print(f"\nSkipping {description}: No providers available")
                continue

            try:
                print(f"\n--- Testing {description} ---")
                print(f"Using providers: {available}")

                session = ort.InferenceSession(
                    str(onnx_model_path), providers=available
                )
                step_session = mem(f"3. Session mit {available[0]}")

                # Get session info
                print(f"Session providers: {session.get_providers()}")
                print(f"Inputs: {[inp.name for inp in session.get_inputs()]}")
                print(f"Outputs: {[out.name for out in session.get_outputs()]}")

                del session
                gc.collect()
                step_cleanup = mem(f"4. Nach {available[0]} Cleanup")

            except Exception as e:
                print(f"ERROR creating session with {description}: {e}")

        # Calculate costs
        import_cost = step1 - baseline
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"ONNX Runtime Import Cost: {import_cost:.1f} MB")

        if onnx_model_path.exists():
            model_size_mb = onnx_model_path.stat().st_size / 1024 / 1024
            print(f"ONNX Model Size: {model_size_mb:.1f} MB")

except ImportError as e:
    print(f"ERROR: Cannot import onnxruntime: {e}")
except Exception as e:
    print(f"ERROR: {e}")
    import traceback

    traceback.print_exc()

print("\n" + "=" * 70)
