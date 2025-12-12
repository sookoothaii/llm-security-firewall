"""
Quick Script to check if Quantum Model can be loaded
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

print("Checking Quantum Model availability...")
print(f"Current directory: {Path.cwd()}")
print(f"Script location: {Path(__file__).parent}")

# Check model path
model_path = Path(__file__).parent.parent.parent / "models" / "quantum_cnn_trained" / "best_model.pt"
print(f"\nModel path (relative to project root): {model_path}")
print(f"Model exists: {model_path.exists()}")
print(f"Absolute path: {model_path.resolve()}")

# Check dependencies
print("\nChecking dependencies...")
try:
    import torch
    print(f"✓ PyTorch: {torch.__version__}")
except ImportError:
    print("✗ PyTorch: NOT INSTALLED")

try:
    from transformers import AutoTokenizer
    print("✓ Transformers: Available")
except ImportError:
    print("✗ Transformers: NOT INSTALLED")

try:
    from llm_firewall.ml import QuantumInspiredCNN
    print("✓ QuantumInspiredCNN: Available")
except ImportError as e:
    print(f"✗ QuantumInspiredCNN: {e}")

# Try to load model
print("\nTrying to load model...")
try:
    from quantum_model_loader import load_quantum_inspired_model
    
    if model_path.exists():
        print(f"Loading from: {model_path}")
        model, tokenizer = load_quantum_inspired_model(
            vocab_size=10000,
            model_path=str(model_path)
        )
        if model is not None:
            print("✓ Model loaded successfully!")
        else:
            print("✗ Model is None after loading")
    else:
        print("✗ Model file not found, trying fallback...")
        model, tokenizer = load_quantum_inspired_model(vocab_size=10000)
        if model is not None:
            print("✓ Fallback model loaded successfully!")
        else:
            print("✗ Fallback model is None")
except Exception as e:
    print(f"✗ Error loading model: {e}")
    import traceback
    traceback.print_exc()

