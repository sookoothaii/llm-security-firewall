"""
Weighted Ensemble Detector

Combines V1 (good FPR) and V2 (perfect bypass detection) models
to get best of both worlds.

Usage:
    ensemble = WeightedEnsembleDetector(v1_model, v2_model, v2_weight=0.7)
    score, confidence, metadata = ensemble.predict(text)
"""

import logging
from typing import Dict, Tuple, Optional
import torch
import numpy as np

logger = logging.getLogger(__name__)


class ModelWrapper:
    """Wrapper for QuantumInspiredCNN models to provide unified interface."""
    
    def __init__(self, model, tokenizer, device: str = 'cpu'):
        self.model = model
        self.tokenizer = tokenizer
        self.device = device
        self.model.eval()
    
    def predict_with_confidence(self, text: str) -> Tuple[float, float]:
        """
        Predict malicious score and confidence.
        
        Returns:
            (score, confidence) where:
            - score: 0.0 (benign) to 1.0 (malicious)
            - confidence: 0.0 to 1.0
        """
        # Tokenize
        token_ids = self.tokenizer.encode(text, max_length=512)
        input_tensor = torch.tensor([token_ids], dtype=torch.long).to(self.device)
        
        # Predict
        with torch.no_grad():
            output = self.model(input_tensor)
            probabilities = torch.softmax(output, dim=1)
            
            # Get predicted class and confidence
            _, predicted = torch.max(output, 1)
            pred_class = predicted.item()
            
            # Score: probability of malicious class (class 1)
            malicious_prob = probabilities[0][1].item()
            
            # Confidence: max probability
            confidence = probabilities[0][pred_class].item()
            
            # Return score (0=benign, 1=malicious) and confidence
            return float(malicious_prob), float(confidence)


class AdaptiveEnsembleDetector:
    """
    Adaptive Ensemble that uses V2 only when confident, otherwise falls back to V1.
    
    Strategy:
    - V2 handles high-confidence malicious cases (security)
    - V2 handles high-confidence benign cases (safety)
    - V1 handles uncertain cases (better FPR)
    """
    
    def __init__(
        self,
        v1_model_wrapper: ModelWrapper,
        v2_model_wrapper: ModelWrapper,
        v2_confidence_threshold: float = 0.8,
        v2_malicious_threshold: float = 0.8,
        v2_benign_threshold: float = 0.2
    ):
        """
        Initialize adaptive ensemble detector.
        
        Args:
            v1_model_wrapper: Wrapped V1 model
            v2_model_wrapper: Wrapped V2 model
            v2_confidence_threshold: Minimum confidence for V2 to be used
            v2_malicious_threshold: Score threshold for V2 high-confidence malicious
            v2_benign_threshold: Score threshold for V2 high-confidence benign
        """
        self.v1_model = v1_model_wrapper
        self.v2_model = v2_model_wrapper
        self.v2_confidence_threshold = v2_confidence_threshold
        self.v2_malicious_threshold = v2_malicious_threshold
        self.v2_benign_threshold = v2_benign_threshold
        
        logger.info(f"Adaptive Ensemble initialized: V2 confidence threshold={v2_confidence_threshold}")
    
    def predict(self, text: str) -> Tuple[float, float, Dict]:
        """
        Predict using adaptive ensemble strategy.
        
        Args:
            text: Input text to classify
            
        Returns:
            Tuple of (score, confidence, metadata)
        """
        # Get individual predictions
        v1_score, v1_conf = self.v1_model.predict_with_confidence(text)
        v2_score, v2_conf = self.v2_model.predict_with_confidence(text)
        
        # Decision logic
        decision_mode = None
        final_score = None
        final_confidence = None
        
        # V2 high confidence malicious (block)
        if v2_score >= self.v2_malicious_threshold and v2_conf >= self.v2_confidence_threshold:
            final_score = v2_score
            final_confidence = v2_conf
            decision_mode = "v2_high_confidence_malicious"
        
        # V2 high confidence benign (allow)
        elif v2_score <= self.v2_benign_threshold and v2_conf >= self.v2_confidence_threshold:
            final_score = v2_score
            final_confidence = v2_conf
            decision_mode = "v2_high_confidence_benign"
        
        # Fallback to V1 (uncertain cases)
        else:
            final_score = v1_score
            final_confidence = v1_conf
            decision_mode = "v1_fallback"
        
        # Metadata
        disagreement = abs(v1_score - v2_score)
        is_malicious = final_score >= 0.5
        
        metadata = {
            "v1_score": float(v1_score),
            "v1_confidence": float(v1_conf),
            "v1_prediction": "malicious" if v1_score >= 0.5 else "benign",
            "v2_score": float(v2_score),
            "v2_confidence": float(v2_conf),
            "v2_prediction": "malicious" if v2_score >= 0.5 else "benign",
            "final_score": float(final_score),
            "final_confidence": float(final_confidence),
            "decision_mode": decision_mode,
            "disagreement": float(disagreement),
            "is_malicious": bool(is_malicious),
            "v2_used": decision_mode.startswith("v2")
        }
        
        return float(final_score), float(final_confidence), metadata


class WeightedEnsembleDetector:
    """
    Ensemble that combines V1 (good FPR) and V2 (perfect bypass detection).
    
    Strategy:
    - V2 gets higher weight for security (catches bypasses)
    - V1 provides better FPR for user experience
    - Weighted combination balances both
    """
    
    def __init__(
        self,
        v1_model_wrapper: ModelWrapper,
        v2_model_wrapper: ModelWrapper,
        v2_weight: float = 0.7,
        decision_threshold: float = 0.5
    ):
        """
        Initialize ensemble detector.
        
        Args:
            v1_model_wrapper: Wrapped V1 model
            v2_model_wrapper: Wrapped V2 model
            v2_weight: Weight for V2 (0.0-1.0). Higher = more security focused
            decision_threshold: Threshold for malicious classification (0.0-1.0)
        """
        self.v1_model = v1_model_wrapper
        self.v2_model = v2_model_wrapper
        self.v2_weight = v2_weight
        self.v1_weight = 1.0 - v2_weight
        self.decision_threshold = decision_threshold
        
        if not (0.0 <= v2_weight <= 1.0):
            raise ValueError(f"v2_weight must be between 0.0 and 1.0, got {v2_weight}")
        
        logger.info(f"Ensemble initialized: V2 weight={v2_weight}, V1 weight={self.v1_weight}")
    
    def predict(self, text: str) -> Tuple[float, float, Dict]:
        """
        Predict using ensemble of V1 and V2.
        
        Args:
            text: Input text to classify
            
        Returns:
            Tuple of (combined_score, combined_confidence, metadata)
            - combined_score: 0.0 (benign) to 1.0 (malicious)
            - combined_confidence: 0.0 to 1.0
            - metadata: Detailed information about predictions
        """
        # Get individual predictions
        v1_score, v1_conf = self.v1_model.predict_with_confidence(text)
        v2_score, v2_conf = self.v2_model.predict_with_confidence(text)
        
        # Weighted combination of scores
        combined_score = (
            v1_score * self.v1_weight +
            v2_score * self.v2_weight
        )
        
        # Combined confidence (weighted average)
        combined_confidence = (
            v1_conf * self.v1_weight +
            v2_conf * self.v2_weight
        )
        
        # Calculate disagreement (important metric)
        disagreement = abs(v1_score - v2_score)
        
        # Determine prediction
        is_malicious = combined_score >= self.decision_threshold
        
        # Metadata for monitoring and analysis
        metadata = {
            "v1_score": float(v1_score),
            "v1_confidence": float(v1_conf),
            "v1_prediction": "malicious" if v1_score >= 0.5 else "benign",
            "v2_score": float(v2_score),
            "v2_confidence": float(v2_conf),
            "v2_prediction": "malicious" if v2_score >= 0.5 else "benign",
            "combined_score": float(combined_score),
            "combined_confidence": float(combined_confidence),
            "ensemble_weight_v2": self.v2_weight,
            "ensemble_weight_v1": self.v1_weight,
            "disagreement": float(disagreement),
            "is_malicious": bool(is_malicious),
            "decision_threshold": self.decision_threshold
        }
        
        return float(combined_score), float(combined_confidence), metadata
    
    def predict_batch(self, texts: list) -> list:
        """
        Predict on batch of texts.
        
        Args:
            texts: List of input texts
            
        Returns:
            List of (score, confidence, metadata) tuples
        """
        results = []
        for text in texts:
            score, conf, meta = self.predict(text)
            results.append((score, conf, meta))
        return results
    
    def analyze_disagreement(self, texts: list, threshold: float = 0.5) -> Dict:
        """
        Analyze where V1 and V2 disagree significantly.
        
        Args:
            texts: List of input texts
            threshold: Disagreement threshold (0.0-1.0)
            
        Returns:
            Dict with disagreement statistics and samples
        """
        disagreements = []
        agreements = []
        
        for text in texts:
            v1_score, _ = self.v1_model.predict_with_confidence(text)
            v2_score, _ = self.v2_model.predict_with_confidence(text)
            
            disagreement = abs(v1_score - v2_score)
            
            if disagreement > threshold:
                disagreements.append({
                    "text": text[:100] + "..." if len(text) > 100 else text,
                    "v1_score": float(v1_score),
                    "v2_score": float(v2_score),
                    "disagreement": float(disagreement),
                    "v1_pred": "malicious" if v1_score >= 0.5 else "benign",
                    "v2_pred": "malicious" if v2_score >= 0.5 else "benign"
                })
            else:
                agreements.append({
                    "text": text[:50] + "..." if len(text) > 50 else text,
                    "v1_score": float(v1_score),
                    "v2_score": float(v2_score),
                    "disagreement": float(disagreement)
                })
        
        return {
            "total_samples": len(texts),
            "disagreements": len(disagreements),
            "agreements": len(agreements),
            "disagreement_rate": len(disagreements) / len(texts) if texts else 0.0,
            "avg_disagreement": np.mean([d["disagreement"] for d in disagreements]) if disagreements else 0.0,
            "disagreement_samples": disagreements[:20],  # Top 20 for review
            "agreement_samples": agreements[:10]  # Sample of agreements
        }


def load_ensemble_models(
    v1_model_path: str,
    v2_model_path: str,
    device: str = 'cpu'
) -> Tuple[ModelWrapper, ModelWrapper]:
    """
    Load V1 and V2 models and wrap them.
    
    Args:
        v1_model_path: Path to V1 model checkpoint
        v2_model_path: Path to V2 model checkpoint
        device: Device (cpu/cuda)
        
    Returns:
        Tuple of (v1_wrapper, v2_wrapper)
    """
    import sys
    from pathlib import Path
    
    project_root = Path(__file__).parent.parent.parent.parent.parent
    src_path = project_root / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))
    
    from llm_firewall.ml import QuantumInspiredCNN
    
    class SimpleTokenizer:
        def __init__(self, vocab_size: int = 10000):
            self.vocab_size = vocab_size
        def encode(self, text: str, max_length: int = 512) -> list:
            tokens = [ord(c) % self.vocab_size for c in text[:max_length]]
            while len(tokens) < max_length:
                tokens.append(0)
            return tokens[:max_length]
    
    def load_model(model_path: str) -> torch.nn.Module:
        checkpoint = torch.load(model_path, map_location=device, weights_only=False)
        
        if 'hyperparameters' in checkpoint:
            hp = checkpoint['hyperparameters']
            vocab_size = hp.get('vocab_size', 10000)
            embedding_dim = hp.get('embedding_dim', 128)
            hidden_dims = hp.get('hidden_dims', [256, 128, 64])
            kernel_sizes = hp.get('kernel_sizes', [3, 5, 7])
            dropout = hp.get('dropout', 0.2)
        else:
            vocab_size = 10000
            embedding_dim = 128
            hidden_dims = [256, 128, 64]
            kernel_sizes = [3, 5, 7]
            dropout = 0.2
        
        model = QuantumInspiredCNN(
            vocab_size=vocab_size,
            embedding_dim=embedding_dim,
            num_classes=2,
            hidden_dims=hidden_dims,
            kernel_sizes=kernel_sizes,
            dropout=dropout
        )
        
        if 'model_state_dict' in checkpoint:
            model.load_state_dict(checkpoint['model_state_dict'])
        else:
            model.load_state_dict(checkpoint)
        
        model = model.to(device)
        model.eval()
        return model
    
    # Load models
    logger.info(f"Loading V1 model from {v1_model_path}...")
    v1_model = load_model(v1_model_path)
    
    logger.info(f"Loading V2 model from {v2_model_path}...")
    v2_model = load_model(v2_model_path)
    
    # Create tokenizer
    tokenizer = SimpleTokenizer(vocab_size=10000)
    
    # Wrap models
    v1_wrapper = ModelWrapper(v1_model, tokenizer, device)
    v2_wrapper = ModelWrapper(v2_model, tokenizer, device)
    
    logger.info("Models loaded and wrapped successfully")
    
    return v1_wrapper, v2_wrapper

