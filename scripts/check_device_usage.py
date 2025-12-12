"""
Device Usage Diagnostic Script
================================

Checks which device (CPU/GPU) is actually being used by ML components.
Run this to verify GPU enforcement is working.

Usage:
    python scripts/check_device_usage.py
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
base_dir = Path(__file__).parent.parent
sys.path.insert(0, str(base_dir / "src"))

# Force GPU
os.environ['TORCH_DEVICE'] = 'cuda'
os.environ['CUDA_VISIBLE_DEVICES'] = '0'

print("="*80)
print("DEVICE USAGE DIAGNOSTIC")
print("="*80)

# Check torch
try:
    import torch
    print(f"\n[TORCH]")
    print(f"  CUDA available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"  GPU device: {torch.cuda.get_device_name(0)}")
        print(f"  Current device: {torch.cuda.current_device()}")
    else:
        print(f"  [ERROR] CUDA not available!")
except Exception as e:
    print(f"[ERROR] Torch check failed: {e}")

# Check environment
print(f"\n[ENVIRONMENT]")
print(f"  TORCH_DEVICE: {os.environ.get('TORCH_DEVICE', 'NOT_SET')}")
print(f"  CUDA_VISIBLE_DEVICES: {os.environ.get('CUDA_VISIBLE_DEVICES', 'NOT_SET')}")

# Initialize firewall components and check device
print(f"\n[FIREWALL COMPONENTS]")

try:
    from llm_firewall.detectors.ml_toxicity_scanner import get_scanner
    
    print(f"\n  1. ML Toxicity Scanner:")
    scanner = get_scanner()
    print(f"     Device: {scanner.device}")
    print(f"     Type: {type(scanner.device)}")
    
    # Check if model is actually on GPU
    if hasattr(scanner, 'pipeline') and scanner.pipeline is not None:
        model = scanner.pipeline.model
        device = next(model.parameters()).device
        print(f"     Model actual device: {device}")
        print(f"     Model is on CUDA: {device.type == 'cuda'}")
    
except Exception as e:
    print(f"     [ERROR] {e}")
    import traceback
    traceback.print_exc()

try:
    from llm_firewall.detectors.semantic_guard import get_semantic_guard
    
    print(f"\n  2. Semantic Guard:")
    guard = get_semantic_guard()
    print(f"     Device: {guard.device}")
    
    # Check actual model device
    if hasattr(guard, 'model') and guard.model is not None:
        # SentenceTransformer stores device differently
        if hasattr(guard.model, '_target_device'):
            print(f"     Model target device: {guard.model._target_device}")
        if hasattr(guard.model, 'device'):
            print(f"     Model device: {guard.model.device}")
            
except Exception as e:
    print(f"     [ERROR] {e}")
    import traceback
    traceback.print_exc()

try:
    from llm_firewall.safety.embedding_detector import EmbeddingDetector
    
    print(f"\n  3. Embedding Detector:")
    detector = EmbeddingDetector()
    print(f"     Device: {detector.device}")
    
    # Check model device
    if hasattr(detector, 'model') and detector.model is not None:
        if hasattr(detector.model, '_target_device'):
            print(f"     Model target device: {detector.model._target_device}")
            
except Exception as e:
    print(f"     [ERROR] {e}")
    import traceback
    traceback.print_exc()

# Test actual inference on GPU
print(f"\n[INFERENCE TEST]")
try:
    test_text = "This is a test prompt"
    print(f"  Testing with: '{test_text}'")
    
    # Test scanner inference
    print(f"\n  Testing ML Toxicity Scanner...")
    result = scanner.scan(test_text, user_id="test")
    print(f"    Result: {result.is_toxic}")
    print(f"    Score: {result.toxicity_score:.3f}")
    
    # Check if GPU was actually used
    if torch.cuda.is_available():
        print(f"    GPU memory allocated: {torch.cuda.memory_allocated(0) / 1024**2:.1f} MB")
        print(f"    GPU memory cached: {torch.cuda.memory_reserved(0) / 1024**2:.1f} MB")
        
except Exception as e:
    print(f"    [ERROR] {e}")
    import traceback
    traceback.print_exc()

print(f"\n" + "="*80)
print("DIAGNOSTIC COMPLETE")
print("="*80)
print()
