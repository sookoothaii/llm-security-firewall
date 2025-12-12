"""
Diagnose-Script: Warum wird das ML-Modell nicht geladen?
"""
import sys
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

print("=" * 80)
print("ML-MODEL LOADING DIAGNOSE")
print("=" * 80)

# 1. Prüfe Konfiguration
print("\n[1] KONFIGURATION:")
print(f"   Service-Verzeichnis: {Path(__file__).parent}")
print(f"   Projekt-Root: {Path(__file__).parent.parent.parent}")

# 2. Prüfe USE_QUANTUM_MODEL
print("\n[2] QUANTUM MODEL EINSTELLUNGEN:")
try:
    # Simuliere die Konfiguration aus main.py
    USE_QUANTUM_MODEL = True
    QUANTUM_MODEL_PATH = str(Path(__file__).parent.parent.parent / "models" / "quantum_cnn_trained" / "best_model.pt")
    print(f"   USE_QUANTUM_MODEL: {USE_QUANTUM_MODEL}")
    print(f"   QUANTUM_MODEL_PATH: {QUANTUM_MODEL_PATH}")
    print(f"   Model existiert: {Path(QUANTUM_MODEL_PATH).exists()}")
except Exception as e:
    print(f"   ❌ Fehler: {e}")

# 3. Prüfe HAS_QUANTUM_ML
print("\n[3] QUANTUM ML MODULE:")
try:
    from quantum_model_loader import load_quantum_inspired_model
    HAS_QUANTUM_ML = True
    print(f"   ✓ quantum_model_loader importiert")
except ImportError as e:
    HAS_QUANTUM_ML = False
    print(f"   ❌ quantum_model_loader nicht importierbar: {e}")

# 4. Prüfe Dependencies
print("\n[4] DEPENDENCIES:")
try:
    import torch
    print(f"   ✓ PyTorch: {torch.__version__}")
except ImportError:
    print(f"   ❌ PyTorch: NICHT INSTALLIERT")

try:
    from transformers import AutoTokenizer
    print(f"   ✓ Transformers: Verfügbar")
except ImportError:
    print(f"   ❌ Transformers: NICHT INSTALLIERT")

try:
    from llm_firewall.ml import QuantumInspiredCNN
    print(f"   ✓ QuantumInspiredCNN: Verfügbar")
except ImportError as e:
    print(f"   ❌ QuantumInspiredCNN: {e}")

# 5. Versuche Modell zu laden
print("\n[5] MODELL-LADEN TEST:")
if HAS_QUANTUM_ML and USE_QUANTUM_MODEL:
    try:
        print(f"   Versuche Modell zu laden von: {QUANTUM_MODEL_PATH}")
        model, tokenizer = load_quantum_inspired_model(
            vocab_size=10000,
            model_path=QUANTUM_MODEL_PATH if Path(QUANTUM_MODEL_PATH).exists() else None
        )
        if model is not None:
            print(f"   ✅ Modell erfolgreich geladen!")
            print(f"   Model-Typ: {type(model)}")
            print(f"   Tokenizer-Typ: {type(tokenizer)}")
        else:
            print(f"   ❌ Modell ist None nach dem Laden")
    except Exception as e:
        print(f"   ❌ Fehler beim Laden: {e}")
        import traceback
        traceback.print_exc()
else:
    print(f"   ⚠️  Modell-Laden übersprungen (HAS_QUANTUM_ML={HAS_QUANTUM_ML}, USE_QUANTUM_MODEL={USE_QUANTUM_MODEL})")

# 6. Simuliere load_ml_model() aus main.py
print("\n[6] SIMULIERE load_ml_model() AUS main.py:")
try:
    # Simuliere die Funktion
    quantum_model = None
    quantum_tokenizer = None
    has_quantum_model = False
    
    if USE_QUANTUM_MODEL and HAS_QUANTUM_ML:
        try:
            model_path = QUANTUM_MODEL_PATH
            if Path(model_path).exists():
                print(f"   Lade Modell von: {model_path}")
                quantum_model, quantum_tokenizer = load_quantum_inspired_model(
                    vocab_size=10000,
                    model_path=model_path
                )
            else:
                print(f"   ⚠️  Modell nicht gefunden, versuche Fallback...")
                quantum_model, quantum_tokenizer = load_quantum_inspired_model(vocab_size=10000)
            
            if quantum_model is not None:
                has_quantum_model = True
                print(f"   ✅ has_quantum_model = {has_quantum_model}")
            else:
                print(f"   ❌ has_quantum_model = {has_quantum_model} (Modell ist None)")
        except Exception as e:
            print(f"   ❌ Exception beim Laden: {e}")
            import traceback
            traceback.print_exc()
    else:
        print(f"   ⚠️  Bedingungen nicht erfüllt: USE_QUANTUM_MODEL={USE_QUANTUM_MODEL}, HAS_QUANTUM_ML={HAS_QUANTUM_ML}")
        
except Exception as e:
    print(f"   ❌ Fehler in Simulation: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)
print("DIAGNOSE ABGESCHLOSSEN")
print("=" * 80)

