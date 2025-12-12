"""
Quantum-Inspired Model Loader für Code-Intent Detector
======================================================

Lädt Quantum-Inspired CNN als Alternative zu CodeBERT.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import sys
from pathlib import Path
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

quantum_model = None
quantum_tokenizer = None
has_quantum_model = False


def load_quantum_inspired_model(vocab_size: int = 10000, model_path: Optional[str] = None):
    """
    Lade Quantum-Inspired CNN Model.
    
    Args:
        vocab_size: Vokabular-Größe
        model_path: Optionaler Pfad zu trainiertem Model
    
    Returns:
        (model, tokenizer) oder (None, None) bei Fehler
    """
    global quantum_model, quantum_tokenizer, has_quantum_model
    
    if quantum_model is not None:
        return quantum_model, quantum_tokenizer
    
    try:
        import torch
        from llm_firewall.ml import QuantumInspiredCNN, HybridDetector
        
        # Wenn Model-Pfad vorhanden, lade trainiertes Model
        if model_path and Path(model_path).exists():
            logger.info(f"Loading trained Quantum-Inspired model from {model_path}")
            # Load checkpoint
            # FIX (2025-12-09): PyTorch 2.9.1 requires weights_only=False for models with numpy objects
            # This is safe because it's our own trained model (trusted source)
            try:
                # Try with weights_only=False (required for models with numpy objects)
                checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
            except Exception as e:
                logger.error(f"❌ Failed to load checkpoint: {e}")
                raise
            
            # Extrahiere Hyperparameter aus Checkpoint
            if 'hyperparameters' in checkpoint:
                hp = checkpoint['hyperparameters']
                vocab_size = hp.get('vocab_size', vocab_size)
                embedding_dim = hp.get('embedding_dim', 128)
                hidden_dims = hp.get('hidden_dims', [256, 128, 64])
                kernel_sizes = hp.get('kernel_sizes', [3, 5, 7])
                dropout = hp.get('dropout', 0.5)
            else:
                # Fallback zu Standardwerten
                embedding_dim = 128
                hidden_dims = [256, 128, 64]
                kernel_sizes = [3, 5, 7]
                dropout = 0.5
            
            # Create model with correct architecture
            quantum_model = QuantumInspiredCNN(
                vocab_size=vocab_size,
                embedding_dim=embedding_dim,
                num_classes=2,
                hidden_dims=hidden_dims,
                kernel_sizes=kernel_sizes,
                dropout=dropout
            )
            
            # Lade State Dict
            if 'model_state_dict' in checkpoint:
                quantum_model.load_state_dict(checkpoint['model_state_dict'])
            else:
                # Direktes State Dict
                quantum_model.load_state_dict(checkpoint)
            
            quantum_model.eval()
            
            logger.info(f"✓ Champion model loaded (Epoch: {checkpoint.get('epoch', 'N/A')}, Val Loss: {checkpoint.get('val_loss', 'N/A'):.4f})")
        else:
            # Erstelle neues Model (für Inference ohne Training)
            logger.info("Creating new Quantum-Inspired CNN model")
            quantum_model = QuantumInspiredCNN(
                vocab_size=vocab_size,
                embedding_dim=128,
                num_classes=2,  # malicious/benign
                hidden_dims=[256, 128, 64],
                kernel_sizes=[3, 5, 7]
            )
            quantum_model.eval()
        
        # Simple tokenizer (character/word-based)
        # In Production: Verwende richtigen Tokenizer
        quantum_tokenizer = SimpleTokenizer(vocab_size=vocab_size)
        
        has_quantum_model = True
        logger.info("Quantum-Inspired model loaded successfully")
        
        return quantum_model, quantum_tokenizer
    
    except ImportError as e:
        logger.warning(f"Quantum-Inspired ML not available: {e}")
        return None, None
    except Exception as e:
        logger.error(f"Failed to load Quantum-Inspired model: {e}")
        return None, None


class SimpleTokenizer:
    """Einfacher Tokenizer für Quantum-Inspired Model (Fallback)."""
    
    def __init__(self, vocab_size: int = 10000):
        self.vocab_size = vocab_size
        # Simple character-based encoding
        self.char_to_id = {chr(i): i % vocab_size for i in range(256)}
        self.id_to_char = {v: k for k, v in self.char_to_id.items()}
    
    def encode(self, text: str, max_length: int = 512) -> list:
        """Encode text to token IDs."""
        tokens = [self.char_to_id.get(c, 0) for c in text[:max_length]]
        # Pad to max_length
        while len(tokens) < max_length:
            tokens.append(0)
        return tokens[:max_length]
    
    def __call__(self, text: str, return_tensors: str = "pt", max_length: int = 512, **kwargs):
        """Tokenizer call interface."""
        import torch
        
        token_ids = self.encode(text, max_length=max_length)
        
        if return_tensors == "pt":
            return {"input_ids": torch.tensor([token_ids])}
        else:
            return {"input_ids": [token_ids]}
