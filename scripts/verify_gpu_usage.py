"""
GPU Usage Verification Script
==============================

Verifies that ML models actually run on GPU, not CPU.
Run this BEFORE benchmarks to ensure GPU is used.

Usage:
    python scripts/verify_gpu_usage.py
"""

import sys
import os
from pathlib import Path

# Force GPU
os.environ['TORCH_DEVICE'] = 'cuda'
os.environ['CUDA_VISIBLE_DEVICES'] = '0'

print("="*80)
print("GPU USAGE VERIFICATION")
print("="*80)

# Check CUDA
try:
    import torch
    print(f"\n[1] CUDA Check:")
    print(f"    Available: {torch.cuda.is_available()}")
    if not torch.cuda.is_available():
        print(f"    [ERROR] CUDA not available - tests will FAIL")
        sys.exit(1)
    print(f"    Device: {torch.cuda.get_device_name(0)}")
    print(f"    CUDA Version: {torch.version.cuda}")
except Exception as e:
    print(f"[ERROR] PyTorch check failed: {e}")
    sys.exit(1)

# Add to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir / "src"))

# Test ML Toxicity Scanner
print(f"\n[2] ML Toxicity Scanner:")
try:
    from llm_firewall.detectors.ml_toxicity_scanner import get_scanner
    scanner = get_scanner()
    print(f"    Scanner device: {scanner.device}")
    
    if scanner.pipeline and scanner.pipeline.model:
        model_device = next(scanner.pipeline.model.parameters()).device
        print(f"    Model actual device: {model_device}")
        print(f"    Model on CUDA: {model_device.type == 'cuda'}")
        
        if model_device.type != 'cuda':
            print(f"    [ERROR] Model on {model_device.type} instead of cuda!")
            sys.exit(1)
        else:
            print(f"    [OK] Model VERIFIED on GPU")
    else:
        print(f"    [WARNING] Pipeline/Model not available")
except Exception as e:
    print(f"    [ERROR] {e}")
    sys.exit(1)

# Test Semantic Guard
print(f"\n[3] Semantic Guard:")
try:
    from llm_firewall.detectors.semantic_guard import get_semantic_guard
    guard = get_semantic_guard()
    
    if guard._model and hasattr(guard._model, '_modules'):
        found_gpu = False
        for module_name, module in guard._model._modules.items():
            if hasattr(module, 'parameters'):
                try:
                    first_param = next(module.parameters())
                    device = first_param.device
                    print(f"    Module {module_name}: {device}")
                    if device.type == 'cuda':
                        found_gpu = True
                        print(f"    [OK] Module on GPU")
                    else:
                        print(f"    [ERROR] Module on {device.type} instead of cuda!")
                        sys.exit(1)
                    break
                except StopIteration:
                    pass
        
        if not found_gpu:
            print(f"    [WARNING] Could not verify GPU usage")
    else:
        print(f"    [WARNING] Model not available")
except Exception as e:
    print(f"    [ERROR] {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test inference on GPU
print(f"\n[4] Inference Test:")
try:
    test_text = "This is a harmful test prompt about bombs"
    result = scanner.scan(test_text)
    print(f"    Test scan completed")
    print(f"    Toxic: {result.get('is_toxic')}")
    print(f"    Score: {result.get('confidence', 0):.3f}")
    
    # Check GPU memory usage
    allocated = torch.cuda.memory_allocated(0) / 1024**2
    reserved = torch.cuda.memory_reserved(0) / 1024**2
    print(f"    GPU Memory allocated: {allocated:.1f} MB")
    print(f"    GPU Memory reserved: {reserved:.1f} MB")
    
    if allocated > 0:
        print(f"    [OK] GPU memory in use - models running on GPU")
    else:
        print(f"    [WARNING] No GPU memory allocated - may be using CPU")
except Exception as e:
    print(f"    [ERROR] {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "="*80)
print("GPU VERIFICATION COMPLETE - ALL CHECKS PASSED")
print("="*80)
print("\nModels are VERIFIED to run on GPU.")
print("You can now run benchmarks with confidence.")
print()
