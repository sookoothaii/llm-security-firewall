"""
Adversarial Training Script for Code Intent Detector

Fine-tunes the Code Intent model (QuantumInspiredCNN) with adversarial examples
to reduce False Negative Rate (Bypass Rate).

Usage:
    python -m detectors.orchestrator.infrastructure.training.train_adversarial_code_intent \
        --train-data data/adversarial_training/code_intent_train_adversarial.jsonl \
        --val-data data/adversarial_training/code_intent_val_adversarial.jsonl \
        --original-data data/train/quantum_cnn_training.jsonl \
        --output-dir models/code_intent_adversarial_v1 \
        --epochs 5 \
        --mix-ratio 0.3
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple
from datetime import datetime
import random

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SimpleTokenizer:
    """Simple character-based tokenizer (compatible with QuantumInspiredCNN)."""
    
    def __init__(self, vocab_size: int = 10000):
        self.vocab_size = vocab_size
    
    def encode(self, text: str, max_length: int = 512) -> list:
        """Encode text to token IDs."""
        tokens = [ord(c) % self.vocab_size for c in text[:max_length]]
        # Pad to max_length
        while len(tokens) < max_length:
            tokens.append(0)
        return tokens[:max_length]


class CodeIntentDataset(Dataset):
    """Dataset for Code Intent classification."""
    
    def __init__(self, jsonl_path: Path, tokenizer: SimpleTokenizer, max_length: int = 512):
        """
        Initialize dataset from JSONL file.
        
        Args:
            jsonl_path: Path to JSONL file with {"text": str, "label": int}
            tokenizer: SimpleTokenizer instance
            max_length: Maximum sequence length
        """
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.samples = []
        
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    record = json.loads(line)
                    self.samples.append({
                        'text': record['text'],
                        'label': int(record['label'])
                    })
        
        logger.info(f"Loaded {len(self.samples)} samples from {jsonl_path}")
    
    def __len__(self) -> int:
        return len(self.samples)
    
    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, int]:
        """Return tokenized text and label."""
        sample = self.samples[idx]
        text = sample['text']
        label = sample['label']
        
        # Use tokenizer
        token_ids = self.tokenizer.encode(text, max_length=self.max_length)
        
        return torch.tensor(token_ids, dtype=torch.long), label


def load_and_mix_data(
    adversarial_path: Path,
    original_path: Path = None,
    mix_ratio: float = 0.3
) -> Tuple[List[Dict], List[Dict]]:
    """
    Load and mix original and adversarial training data.
    
    Args:
        adversarial_path: Path to adversarial training JSONL
        original_path: Optional path to original training JSONL
        mix_ratio: Ratio of adversarial samples (0.0-1.0)
        
    Returns:
        Tuple of (train_samples, val_samples)
    """
    # Load adversarial data
    adv_samples = []
    with open(adversarial_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                adv_samples.append(json.loads(line))
    
    logger.info(f"Loaded {len(adv_samples)} adversarial samples")
    
    # Load original data (if provided)
    orig_samples = []
    if original_path and original_path.exists():
        with open(original_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    orig_samples.append(json.loads(line))
        logger.info(f"Loaded {len(orig_samples)} original samples")
    
    # Mix data
    if orig_samples:
        # Split adversarial into train/val
        adv_train_count = int(len(adv_samples) * 0.8)
        adv_train = adv_samples[:adv_train_count]
        adv_val = adv_samples[adv_train_count:]
        
        # Take subset of original based on mix_ratio
        orig_train_count = int(len(adv_train) * (1 - mix_ratio) / mix_ratio)
        orig_train = orig_samples[:min(orig_train_count, len(orig_samples))]
        
        # Mix
        train_samples = adv_train + orig_train
        random.shuffle(train_samples)
        
        # Use adversarial val + some original val
        orig_val = orig_samples[len(orig_train):len(orig_train)+len(adv_val)]
        val_samples = adv_val + orig_val
        random.shuffle(val_samples)
        
        logger.info(f"Mixed dataset: {len(train_samples)} train ({len(adv_train)} adversarial, {len(orig_train)} original)")
        logger.info(f"                 {len(val_samples)} val ({len(adv_val)} adversarial, {len(orig_val)} original)")
    else:
        # No original data - use adversarial only
        split_idx = int(len(adv_samples) * 0.8)
        train_samples = adv_samples[:split_idx]
        val_samples = adv_samples[split_idx:]
        logger.info(f"Using adversarial-only dataset: {len(train_samples)} train, {len(val_samples)} val")
    
    return train_samples, val_samples


def save_jsonl(samples: List[Dict], path: Path):
    """Save samples to JSONL file."""
    with open(path, 'w', encoding='utf-8') as f:
        for sample in samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')


def load_model(model_path: str = None, vocab_size: int = 10000) -> nn.Module:
    """Load QuantumInspiredCNN model."""
    try:
        # Try different import paths
        try:
            from llm_firewall.ml import QuantumInspiredCNN
        except ImportError:
            # Add src to path
            src_path = project_root / "src"
            if str(src_path) not in sys.path:
                sys.path.insert(0, str(src_path))
            from llm_firewall.ml import QuantumInspiredCNN
    except ImportError as e:
        logger.error(f"Could not import QuantumInspiredCNN: {e}")
        logger.error("Make sure src/llm_firewall/ml is available.")
        raise
    
    # Default hyperparameters (match training spec)
    embedding_dim = 128
    hidden_dims = [256, 128, 64]
    kernel_sizes = [3, 5, 7]
    dropout = 0.2
    
    # Load from checkpoint if provided
    if model_path and Path(model_path).exists():
        logger.info(f"Loading model from checkpoint: {model_path}")
        checkpoint = torch.load(model_path, map_location='cpu', weights_only=False)
        
        if 'hyperparameters' in checkpoint:
            hp = checkpoint['hyperparameters']
            vocab_size = hp.get('vocab_size', vocab_size)
            embedding_dim = hp.get('embedding_dim', embedding_dim)
            hidden_dims = hp.get('hidden_dims', hidden_dims)
            kernel_sizes = hp.get('kernel_sizes', kernel_sizes)
            dropout = hp.get('dropout', dropout)
        
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
        
        logger.info("✓ Model loaded from checkpoint")
    else:
        # Create new model
        logger.info("Creating new model (no checkpoint provided)")
        model = QuantumInspiredCNN(
            vocab_size=vocab_size,
            embedding_dim=embedding_dim,
            num_classes=2,
            hidden_dims=hidden_dims,
            kernel_sizes=kernel_sizes,
            dropout=dropout
        )
    
    return model


def train_model(
    model: nn.Module,
    train_dataset: Dataset,
    val_dataset: Dataset,
    output_dir: Path,
    epochs: int = 5,
    batch_size: int = 32,
    learning_rate: float = 1e-3,
    device: str = 'cpu'
) -> nn.Module:
    """Fine-tune model with adversarial training."""
    model = model.to(device)
    
    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    
    # Loss and optimizer
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=2)
    
    best_val_loss = float('inf')
    best_model_state = None
    training_history = []
    
    logger.info("="*80)
    logger.info("STARTING ADVERSARIAL TRAINING")
    logger.info("="*80)
    logger.info(f"Device: {device}")
    logger.info(f"Train samples: {len(train_dataset)}")
    logger.info(f"Val samples: {len(val_dataset)}")
    logger.info(f"Epochs: {epochs}, Batch size: {batch_size}, LR: {learning_rate}")
    logger.info("="*80)
    
    for epoch in range(epochs):
        # Training
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        
        for batch_idx, (inputs, labels) in enumerate(train_loader):
            inputs = inputs.to(device)
            labels = labels.to(device)
            
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            train_total += labels.size(0)
            train_correct += (predicted == labels).sum().item()
            
            if (batch_idx + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{epochs}, Batch {batch_idx+1}/{len(train_loader)}, "
                          f"Loss: {loss.item():.4f}")
        
        avg_train_loss = train_loss / len(train_loader)
        train_acc = 100 * train_correct / train_total
        
        # Validation
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        
        with torch.no_grad():
            for inputs, labels in val_loader:
                inputs = inputs.to(device)
                labels = labels.to(device)
                
                outputs = model(inputs)
                loss = criterion(outputs, labels)
                
                val_loss += loss.item()
                _, predicted = torch.max(outputs.data, 1)
                val_total += labels.size(0)
                val_correct += (predicted == labels).sum().item()
        
        avg_val_loss = val_loss / len(val_loader)
        val_acc = 100 * val_correct / val_total
        
        scheduler.step(avg_val_loss)
        
        logger.info(f"\nEpoch {epoch+1}/{epochs} Results:")
        logger.info(f"  Train Loss: {avg_train_loss:.4f}, Train Acc: {train_acc:.2f}%")
        logger.info(f"  Val Loss: {avg_val_loss:.4f}, Val Acc: {val_acc:.2f}%")
        logger.info("")
        
        training_history.append({
            'epoch': epoch + 1,
            'train_loss': avg_train_loss,
            'train_acc': train_acc,
            'val_loss': avg_val_loss,
            'val_acc': val_acc
        })
        
        # Save best model
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            best_model_state = model.state_dict().copy()
            logger.info(f"  ✓ New best model (val_loss: {best_val_loss:.4f})")
    
    # Load best model
    if best_model_state:
        model.load_state_dict(best_model_state)
        logger.info("✓ Loaded best model for final evaluation")
    
    # Save model
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = output_dir / "best_model.pt"
    
    checkpoint = {
        'model_state_dict': model.state_dict(),
        'hyperparameters': {
            'vocab_size': 10000,  # Default vocab_size
            'embedding_dim': 128,
            'hidden_dims': [256, 128, 64],
            'kernel_sizes': [3, 5, 7],
            'dropout': 0.2
        },
        'training_history': training_history,
        'best_val_loss': best_val_loss,
        'epoch': epochs
    }
    
    torch.save(checkpoint, checkpoint_path)
    logger.info(f"✓ Saved model to {checkpoint_path}")
    
    # Save training history
    history_path = output_dir / "training_history.json"
    with open(history_path, 'w') as f:
        json.dump(training_history, f, indent=2)
    logger.info(f"✓ Saved training history to {history_path}")
    
    return model


def validate_against_baseline(
    model: nn.Module,
    baseline_bypasses: List[str],
    vocab_size: int = 10000,
    max_length: int = 512,
    device: str = 'cpu'
) -> Dict[str, Any]:
    """Validate model against baseline bypass samples."""
    model.eval()
    model = model.to(device)
    
    detected = 0
    missed = 0
    
    with torch.no_grad():
        for text in baseline_bypasses:
            # Tokenize
            tokens = [ord(c) % vocab_size for c in text[:max_length]]
            if len(tokens) < max_length:
                tokens.extend([0] * (max_length - len(tokens)))
            else:
                tokens = tokens[:max_length]
            
            input_tensor = torch.tensor([tokens], dtype=torch.long).to(device)
            
            # Predict
            output = model(input_tensor)
            _, predicted = torch.max(output, 1)
            
            # Check if detected (predicted as malicious = 1)
            if predicted.item() == 1:
                detected += 1
            else:
                missed += 1
    
    total = len(baseline_bypasses)
    detection_rate = (detected / total) * 100 if total > 0 else 0
    
    return {
        'total': total,
        'detected': detected,
        'missed': missed,
        'detection_rate': detection_rate,
        'bypass_rate': 100 - detection_rate
    }


def main():
    """Main training execution."""
    parser = argparse.ArgumentParser(description="Adversarial Training for Code Intent Detector")
    parser.add_argument(
        "--train-data",
        type=str,
        required=True,
        help="Path to adversarial training JSONL"
    )
    parser.add_argument(
        "--val-data",
        type=str,
        required=True,
        help="Path to adversarial validation JSONL"
    )
    parser.add_argument(
        "--original-data",
        type=str,
        default=None,
        help="Optional path to original training data JSONL"
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default=None,
        help="Optional path to base model checkpoint to fine-tune"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="models/code_intent_adversarial_v1",
        help="Output directory for trained model"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=5,
        help="Number of training epochs"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=32,
        help="Batch size"
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=1e-3,
        help="Learning rate"
    )
    parser.add_argument(
        "--mix-ratio",
        type=float,
        default=0.3,
        help="Ratio of adversarial samples in mixed dataset (0.0-1.0)"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device (cpu/cuda)"
    )
    parser.add_argument(
        "--validate-baseline",
        action="store_true",
        help="Validate against baseline bypasses after training"
    )
    
    args = parser.parse_args()
    
    # Load and mix data
    logger.info("Loading and mixing datasets...")
    train_samples, val_samples = load_and_mix_data(
        adversarial_path=Path(args.train_data),
        original_path=Path(args.original_data) if args.original_data else None,
        mix_ratio=args.mix_ratio
    )
    
    # Save mixed datasets
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    mixed_train_path = output_dir / "train_mixed.jsonl"
    mixed_val_path = output_dir / "val_mixed.jsonl"
    
    save_jsonl(train_samples, mixed_train_path)
    save_jsonl(val_samples, mixed_val_path)
    logger.info(f"Saved mixed datasets: {mixed_train_path}, {mixed_val_path}")
    
    # Create tokenizer
    vocab_size = 10000
    tokenizer = SimpleTokenizer(vocab_size=vocab_size)
    
    # Create datasets
    train_dataset = CodeIntentDataset(mixed_train_path, tokenizer)
    val_dataset = CodeIntentDataset(mixed_val_path, tokenizer)
    
    # Load model
    logger.info("Loading model...")
    model = load_model(model_path=args.base_model)
    
    # Train
    logger.info("Starting training...")
    trained_model = train_model(
        model=model,
        train_dataset=train_dataset,
        val_dataset=val_dataset,
        output_dir=output_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        device=args.device
    )
    
    # Validate against baseline (if requested)
    if args.validate_baseline:
        logger.info("\n" + "="*80)
        logger.info("VALIDATING AGAINST BASELINE BYPASSES")
        logger.info("="*80)
        
        # Load baseline bypasses
        baseline_bypasses = []
        baseline_results_dir = project_root / "test_results" / "adversarial"
        for results_file in baseline_results_dir.glob("baseline_code_intent*.json"):
            with open(results_file, 'r') as f:
                results = json.load(f)
                for test_result in results.get("test_results", []):
                    if test_result.get("bypass", False) and test_result.get("label") == 1:
                        sample = test_result.get("sample", "")
                        if sample:
                            baseline_bypasses.append(sample)
        
        # Remove duplicates
        baseline_bypasses = list(dict.fromkeys(baseline_bypasses))
        
        logger.info(f"Testing against {len(baseline_bypasses)} baseline bypasses...")
        
        validation_results = validate_against_baseline(
            model=trained_model,
            baseline_bypasses=baseline_bypasses,
            device=args.device
        )
        
        logger.info(f"\nValidation Results:")
        logger.info(f"  Total bypasses: {validation_results['total']}")
        logger.info(f"  Detected: {validation_results['detected']} ({validation_results['detection_rate']:.1f}%)")
        logger.info(f"  Missed: {validation_results['missed']} ({validation_results['bypass_rate']:.1f}%)")
        logger.info("="*80)
        
        # Save validation results
        validation_path = output_dir / "baseline_validation.json"
        with open(validation_path, 'w') as f:
            json.dump(validation_results, f, indent=2)
        logger.info(f"Saved validation results to {validation_path}")
    
    logger.info("\n" + "="*80)
    logger.info("TRAINING COMPLETE")
    logger.info("="*80)
    logger.info(f"Model saved to: {output_dir}")
    logger.info("\nNext steps:")
    logger.info("1. Evaluate model with baseline test suite")
    logger.info("2. Compare bypass rates: before vs after training")
    logger.info("3. Deploy improved model if bypass rate reduced")
    logger.info("="*80)


if __name__ == "__main__":
    main()

