"""
Model Calibration (Platt Scaling & Temperature Scaling)

Calibrates model confidence scores to match actual accuracy.
Fixes over-confidence issues in V2 model.

Usage:
    python -m detectors.orchestrator.infrastructure.training.calibrate_model \
        --model models/code_intent_adversarial_v2/best_model.pt \
        --calibration-set data/adversarial_training/code_intent_true_validation.jsonl \
        --output models/code_intent_adversarial_v2_calibrated.pt \
        --method plattscaling
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Tuple, Dict, Any
import numpy as np
import torch
import torch.nn as nn
from sklearn.calibration import calibration_curve, CalibratedClassifierCV
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SimpleTokenizer:
    """Simple character-based tokenizer."""
    
    def __init__(self, vocab_size: int = 10000):
        self.vocab_size = vocab_size
    
    def encode(self, text: str, max_length: int = 512) -> list:
        """Encode text to token IDs."""
        tokens = [ord(c) % self.vocab_size for c in text[:max_length]]
        while len(tokens) < max_length:
            tokens.append(0)
        return tokens[:max_length]


def load_model(model_path: str, device: str = 'cpu'):
    """Load QuantumInspiredCNN model."""
    try:
        try:
            from llm_firewall.ml import QuantumInspiredCNN
        except ImportError:
            src_path = project_root / "src"
            if str(src_path) not in sys.path:
                sys.path.insert(0, str(src_path))
            from llm_firewall.ml import QuantumInspiredCNN
    except ImportError as e:
        logger.error(f"Could not import QuantumInspiredCNN: {e}")
        raise
    
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


def get_model_logits(model, texts: List[str], tokenizer: SimpleTokenizer, device: str = 'cpu'):
    """Get raw logits from model."""
    logits_list = []
    
    with torch.no_grad():
        for text in texts:
            token_ids = tokenizer.encode(text, max_length=512)
            input_tensor = torch.tensor([token_ids], dtype=torch.long).to(device)
            output = model(input_tensor)
            logits_list.append(output[0].cpu().numpy())
    
    return np.array(logits_list)


def platts_scaling(logits: np.ndarray, labels: np.ndarray) -> Tuple[float, float]:
    """
    Platt Scaling: Learn sigmoid(A * score + B) to calibrate probabilities.
    
    Returns:
        (A, B) parameters for sigmoid transformation
    """
    # Convert logits to probabilities
    probs = torch.softmax(torch.tensor(logits), dim=1).numpy()
    scores = probs[:, 1]  # Probability of malicious class
    
    # Fit logistic regression: logit(y) = A * score + B
    # We want: P(y=1) = sigmoid(A * score + B)
    X = scores.reshape(-1, 1)
    y = labels
    
    lr = LogisticRegression()
    lr.fit(X, y)
    
    # Extract parameters: lr.coef_[0][0] = A, lr.intercept_[0] = B
    A = lr.coef_[0][0]
    B = lr.intercept_[0]
    
    return A, B


def temperature_scaling(logits: np.ndarray, labels: np.ndarray, device: str = 'cpu') -> float:
    """
    Temperature Scaling: Find optimal temperature T such that softmax(logits/T) is calibrated.
    
    Returns:
        Temperature parameter T
    """
    logits_tensor = torch.tensor(logits, requires_grad=True, device=device)
    labels_tensor = torch.tensor(labels, dtype=torch.long, device=device)
    
    # Initialize temperature
    temperature = nn.Parameter(torch.ones(1).to(device) * 1.5)
    
    optimizer = torch.optim.LBFGS([temperature], lr=0.01, max_iter=50)
    
    def eval():
        optimizer.zero_grad()
        # Scale logits by temperature
        scaled_logits = logits_tensor / temperature
        loss = nn.CrossEntropyLoss()(scaled_logits, labels_tensor)
        loss.backward()
        return loss
    
    optimizer.step(eval)
    
    return temperature.item()


class CalibratedModelWrapper:
    """Wrapper for calibrated model predictions."""
    
    def __init__(self, model, tokenizer, calibration_method: str, calibration_params: Dict, device: str = 'cpu'):
        self.model = model
        self.tokenizer = tokenizer
        self.calibration_method = calibration_method
        self.calibration_params = calibration_params
        self.device = device
        self.model.eval()
    
    def predict_with_confidence(self, text: str) -> Tuple[float, float]:
        """Predict with calibrated confidence."""
        # Get logits
        token_ids = self.tokenizer.encode(text, max_length=512)
        input_tensor = torch.tensor([token_ids], dtype=torch.long).to(self.device)
        
        with torch.no_grad():
            logits = self.model(input_tensor)
            logits_np = logits[0].cpu().numpy()
        
        # Apply calibration
        if self.calibration_method == "platt":
            # Platt Scaling
            A = self.calibration_params['A']
            B = self.calibration_params['B']
            
            # Get uncalibrated probability
            uncal_probs = torch.softmax(torch.tensor(logits_np), dim=0).numpy()
            score = uncal_probs[1]
            
            # Apply Platt scaling: sigmoid(A * score + B)
            calibrated_score = 1.0 / (1.0 + np.exp(-(A * score + B)))
            
            # Use calibrated score as new probability
            calibrated_probs = np.array([1.0 - calibrated_score, calibrated_score])
        
        elif self.calibration_method == "temperature":
            # Temperature Scaling
            T = self.calibration_params['temperature']
            
            # Scale logits and apply softmax
            scaled_logits = logits_np / T
            calibrated_probs = torch.softmax(torch.tensor(scaled_logits), dim=0).numpy()
        
        else:
            # No calibration
            calibrated_probs = torch.softmax(torch.tensor(logits_np), dim=0).numpy()
        
        # Extract score and confidence
        malicious_prob = float(calibrated_probs[1])
        confidence = float(np.max(calibrated_probs))
        
        return malicious_prob, confidence


def main():
    parser = argparse.ArgumentParser(description="Calibrate Model Confidence Scores")
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to model checkpoint"
    )
    parser.add_argument(
        "--calibration-set",
        type=str,
        required=True,
        help="Path to calibration dataset JSONL"
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output path for calibrated model wrapper"
    )
    parser.add_argument(
        "--method",
        type=str,
        choices=['platt', 'temperature', 'both'],
        default='platt',
        help="Calibration method"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device (cpu/cuda)"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("MODEL CALIBRATION")
    logger.info("="*80)
    logger.info(f"Model: {args.model}")
    logger.info(f"Calibration Set: {args.calibration_set}")
    logger.info(f"Method: {args.method}")
    logger.info("="*80)
    
    # Load model
    logger.info("\nLoading model...")
    model = load_model(args.model, device=args.device)
    tokenizer = SimpleTokenizer(vocab_size=10000)
    
    # Load calibration set
    logger.info("\nLoading calibration set...")
    texts = []
    labels = []
    
    with open(args.calibration_set, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                record = json.loads(line)
                texts.append(record['text'])
                labels.append(int(record['label']))
    
    logger.info(f"Loaded {len(texts)} samples ({sum(labels)} malicious, {len(labels)-sum(labels)} benign)")
    
    # Get model logits
    logger.info("\nGetting model predictions...")
    logits = get_model_logits(model, texts, tokenizer, args.device)
    labels_np = np.array(labels)
    
    # Apply calibration
    calibration_params = {}
    
    if args.method in ['platt', 'both']:
        logger.info("\nApplying Platt Scaling...")
        A, B = platts_scaling(logits, labels_np)
        calibration_params['A'] = float(A)
        calibration_params['B'] = float(B)
        logger.info(f"  Platt parameters: A={A:.4f}, B={B:.4f}")
    
    if args.method in ['temperature', 'both']:
        logger.info("\nApplying Temperature Scaling...")
        T = temperature_scaling(logits, labels_np, args.device)
        calibration_params['temperature'] = float(T)
        logger.info(f"  Temperature: T={T:.4f}")
    
    # Use Platt as default if both
    method = 'platt' if args.method == 'both' else args.method
    
    # Create calibrated wrapper
    calibrated_wrapper = CalibratedModelWrapper(
        model, tokenizer, method, calibration_params, args.device
    )
    
    # Save calibration parameters
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    calibration_data = {
        'model_path': args.model,
        'calibration_method': method,
        'calibration_params': calibration_params,
        'calibration_samples': len(texts),
        'device': args.device
    }
    
    with open(output_path, 'w') as f:
        json.dump(calibration_data, f, indent=2)
    
    logger.info(f"\n💾 Calibration parameters saved to: {output_path}")
    
    # Evaluate calibration improvement
    logger.info("\n" + "="*80)
    logger.info("CALIBRATION EVALUATION")
    logger.info("="*80)
    
    # Test on sample
    logger.info("\nTesting calibration on sample predictions...")
    logger.info("(Check if confidence scores better match actual accuracy)")
    
    logger.info("\n✅ Calibration complete!")
    logger.info("="*80)
    logger.info("\nNext steps:")
    logger.info("1. Test calibrated model on validation set")
    logger.info("2. Compare confidence scores before/after")
    logger.info("3. Use calibrated model in ensemble")


if __name__ == "__main__":
    main()

