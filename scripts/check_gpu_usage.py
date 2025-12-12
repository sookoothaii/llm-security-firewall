#!/usr/bin/env python3
"""
GPU Usage Checker
=================

Prüft ob CUDA verfügbar ist und ob die Services GPU nutzen.
"""

import sys

print("=" * 80)
print("GPU/CUDA Status Check")
print("=" * 80)
print()

# Check PyTorch CUDA
try:
    import torch
    print("✓ PyTorch installed")
    print(f"  CUDA available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"  CUDA device count: {torch.cuda.device_count()}")
        print(f"  Current device: {torch.cuda.current_device()}")
        print(f"  Device name: {torch.cuda.get_device_name(0)}")
        
        # Check GPU memory
        if hasattr(torch.cuda, 'get_device_properties'):
            props = torch.cuda.get_device_properties(0)
            print(f"  Total memory: {props.total_memory / 1024**3:.2f} GB")
        
        # Check allocated memory
        if torch.cuda.is_available():
            allocated = torch.cuda.memory_allocated(0) / 1024**3
            reserved = torch.cuda.memory_reserved(0) / 1024**3
            print(f"  Allocated memory: {allocated:.2f} GB")
            print(f"  Reserved memory: {reserved:.2f} GB")
    else:
        print("  ❌ CUDA NOT AVAILABLE - Models will use CPU (slow!)")
        print("  Check CUDA installation and PyTorch CUDA support")
except ImportError:
    print("❌ PyTorch not installed")

print()

# Check if transformers can use GPU
try:
    from transformers import pipeline
    print("✓ Transformers installed")
    if torch.cuda.is_available():
        print("  Transformers can use GPU")
    else:
        print("  ⚠ Transformers will use CPU")
except ImportError:
    print("❌ Transformers not installed")

print()

# Check actual model loading (if possible)
if torch.cuda.is_available():
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        print("Testing model load on GPU...")
        
        model_name = "microsoft/codebert-base"
        print(f"  Loading {model_name}...")
        
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(
            model_name,
            num_labels=2
        )
        
        # Move to GPU
        device = "cuda:0"
        model = model.to(device)
        model.eval()
        
        # Check actual device
        first_param = next(model.parameters())
        actual_device = first_param.device
        print(f"  ✓ Model loaded on device: {actual_device}")
        
        if actual_device.type == 'cuda':
            print("  ✅ Model is on GPU!")
        else:
            print(f"  ❌ Model is on {actual_device.type} instead of CUDA")
        
        # Test inference
        print("  Testing inference...")
        import torch
        test_input = tokenizer("SELECT * FROM users", return_tensors="pt").to(device)
        with torch.no_grad():
            output = model(**test_input)
        print(f"  ✓ Inference works on {actual_device}")
        
    except Exception as e:
        print(f"  ❌ Error loading model: {e}")
        import traceback
        traceback.print_exc()

print()
print("=" * 80)
print("Recommendation:")
if torch.cuda.is_available():
    print("✅ GPU is available - services should use it automatically")
    print("   If models are slow, check service logs for 'device: cpu' warnings")
else:
    print("❌ GPU not available - install CUDA-enabled PyTorch:")
    print("   pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118")
print("=" * 80)

