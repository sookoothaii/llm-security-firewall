"""
Main Training Script - V3 Whitelist-Learner (Phase 2)

Multi-Task Learning:
- Task 1: Standard Classification (Focal Loss)
- Task 2: Whitelist Pattern Matching (MSE Loss)
- Task 3: V2.1 Imitation Learning (KL Divergence) - Optional

Usage:
    python -m detectors.orchestrator.infrastructure.training.train_whitelist_learner \
        --data data/adversarial_training/v3_whitelist_learner/train.jsonl \
        --validation data/adversarial_training/v3_whitelist_learner/validation.jsonl \
        --pattern-embeddings models/v3_whitelist_learner/pattern_embeddings.pt \
        --output models/v3_whitelist_learner/ \
        --epochs 7 \
        --batch-size 16 \
        --learning-rate 2e-5
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm
import numpy as np

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.infrastructure.training.models import (
    WhitelistAwareCodeIntentModel,
    FocalLoss,
    create_model
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class WhitelistDataset(Dataset):
    """Dataset für Main Training."""
    
    def __init__(self, data_path: Path):
        """Load training data."""
        self.samples = []
        
        with open(data_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    sample = json.loads(line)
                    self.samples.append({
                        'text': sample['text'],
                        'label': sample['label'],  # 0=benign, 1=malicious
                        'pattern': sample.get('pattern'),  # Whitelist pattern or None
                        'category': sample.get('category', 'unknown')
                    })
        
        logger.info(f"Loaded {len(self.samples)} samples")
        logger.info(f"  Malicious: {sum(s['label'] for s in self.samples)}")
        logger.info(f"  Benign: {len(self.samples) - sum(s['label'] for s in self.samples)}")
        logger.info(f"  With Pattern: {sum(1 for s in self.samples if s['pattern'])}")
    
    def __len__(self):
        return len(self.samples)
    
    def __getitem__(self, idx):
        return self.samples[idx]


def train_epoch(
    model: WhitelistAwareCodeIntentModel,
    dataloader: DataLoader,
    optimizer: optim.Optimizer,
    focal_loss: FocalLoss,
    device: str,
    epoch: int,
    use_pattern_loss: bool = True,
    use_imitation: bool = False,
    teacher_model: Optional[Any] = None
) -> Dict[str, float]:
    """
    Train one epoch.
    
    Returns:
        Dictionary with loss values
    """
    model.train()
    total_class_loss = 0.0
    total_pattern_loss = 0.0
    total_imitation_loss = 0.0
    num_batches = 0
    
    # Pattern name to index mapping
    pattern_to_idx = {
        'technical_question': 0,
        'educational': 1,
        'best_practice': 2,
        'explanation': 3
    }
    
    progress_bar = tqdm(dataloader, desc=f"Epoch {epoch+1}")
    
    for batch in progress_bar:
        texts = [item['text'] for item in batch]
        labels = torch.tensor([item['label'] for item in batch], dtype=torch.long).to(device)
        patterns = [item.get('pattern') for item in batch]
        
        # Forward pass
        output = model.forward(
            texts=texts,
            return_patterns=use_pattern_loss,
            return_similarities=False
        )
        
        # Task 1: Classification Loss (Focal Loss)
        class_logits = output['whitelist_logits']
        class_loss = focal_loss(class_logits, labels)
        
        # Task 2: Pattern Loss (MSE for pattern prediction)
        pattern_loss = torch.tensor(0.0).to(device)
        if use_pattern_loss and output.get('pattern_logits') is not None:
            pattern_logits = output['pattern_logits']
            
            # Create pattern targets
            pattern_targets = []
            for pattern in patterns:
                if pattern and pattern in pattern_to_idx:
                    target = torch.zeros(4).to(device)
                    target[pattern_to_idx[pattern]] = 1.0
                    pattern_targets.append(target)
                else:
                    # No pattern = all zeros
                    pattern_targets.append(torch.zeros(4).to(device))
            
            if pattern_targets:
                pattern_targets_tensor = torch.stack(pattern_targets)
                pattern_loss = F.mse_loss(
                    F.softmax(pattern_logits, dim=-1),
                    pattern_targets_tensor
                )
        
        # Task 3: Imitation Loss (KL Divergence) - Optional
        imitation_loss = torch.tensor(0.0).to(device)
        if use_imitation and teacher_model:
            try:
                # Get teacher predictions
                teacher_outputs = teacher_model.predict(texts)
                teacher_probs = torch.tensor([
                    [1.0 - p['malicious_probability'], p['malicious_probability']]
                    for p in teacher_outputs
                ]).to(device)
                
                # Student predictions
                student_probs = F.softmax(class_logits, dim=-1)
                
                # KL Divergence
                imitation_loss = F.kl_div(
                    F.log_softmax(class_logits, dim=-1),
                    teacher_probs,
                    reduction='batchmean'
                )
            except Exception as e:
                logger.warning(f"Imitation learning failed: {e}")
                imitation_loss = torch.tensor(0.0).to(device)
        
        # Combined loss
        # Weights: 0.6 classification, 0.2 pattern, 0.2 imitation
        total_loss = (
            0.6 * class_loss +
            0.2 * pattern_loss +
            0.2 * imitation_loss
        )
        
        # Backward
        optimizer.zero_grad()
        total_loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        
        # Accumulate losses
        total_class_loss += class_loss.item()
        total_pattern_loss += pattern_loss.item()
        total_imitation_loss += imitation_loss.item()
        num_batches += 1
        
        progress_bar.set_postfix({
            'class': f'{class_loss.item():.3f}',
            'pattern': f'{pattern_loss.item():.3f}',
            'total': f'{total_loss.item():.3f}'
        })
    
    return {
        'class_loss': total_class_loss / num_batches if num_batches > 0 else 0.0,
        'pattern_loss': total_pattern_loss / num_batches if num_batches > 0 else 0.0,
        'imitation_loss': total_imitation_loss / num_batches if num_batches > 0 else 0.0
    }


def validate(
    model: WhitelistAwareCodeIntentModel,
    dataloader: DataLoader,
    device: str
) -> Dict[str, float]:
    """Validate model."""
    model.eval()
    correct = 0
    total = 0
    benign_correct = 0
    benign_total = 0
    malicious_correct = 0
    malicious_total = 0
    
    with torch.no_grad():
        for batch in dataloader:
            texts = [item['text'] for item in batch]
            labels = torch.tensor([item['label'] for item in batch], dtype=torch.long).to(device)
            
            output = model.forward(texts=texts, return_patterns=False)
            logits = output['whitelist_logits']
            predictions = torch.argmax(logits, dim=-1)
            
            correct += (predictions == labels).sum().item()
            total += len(labels)
            
            # Per-class accuracy
            for pred, label in zip(predictions, labels):
                if label == 0:  # benign
                    benign_total += 1
                    if pred == label:
                        benign_correct += 1
                else:  # malicious
                    malicious_total += 1
                    if pred == label:
                        malicious_correct += 1
    
    return {
        'accuracy': correct / total if total > 0 else 0.0,
        'benign_accuracy': benign_correct / benign_total if benign_total > 0 else 0.0,
        'malicious_accuracy': malicious_correct / malicious_total if malicious_total > 0 else 0.0
    }


def main():
    parser = argparse.ArgumentParser(
        description="Train V3 Whitelist-Learner (Main Training)"
    )
    parser.add_argument(
        "--data",
        type=str,
        required=True,
        help="Path to training data (JSONL)"
    )
    parser.add_argument(
        "--validation",
        type=str,
        required=True,
        help="Path to validation data (JSONL)"
    )
    parser.add_argument(
        "--pattern-embeddings",
        type=str,
        help="Path to pre-trained pattern embeddings checkpoint"
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output directory for model checkpoints"
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default="microsoft/codebert-base",
        help="Base model name"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=7,
        help="Number of epochs"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
        help="Batch size"
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=2e-5,
        help="Learning rate"
    )
    parser.add_argument(
        "--use-pattern-loss",
        action="store_true",
        default=True,
        help="Use pattern matching loss"
    )
    parser.add_argument(
        "--use-imitation",
        action="store_true",
        help="Use V2.1 imitation learning (requires V2.1 model)"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("V3 WHITELIST-LEARNER MAIN TRAINING - PHASE 2")
    logger.info("="*80)
    logger.info(f"Training Data: {args.data}")
    logger.info(f"Validation Data: {args.validation}")
    logger.info(f"Pattern Embeddings: {args.pattern_embeddings}")
    logger.info(f"Output: {args.output}")
    logger.info(f"Epochs: {args.epochs}")
    logger.info(f"Batch Size: {args.batch_size}")
    logger.info(f"Learning Rate: {args.learning_rate}")
    logger.info(f"Use Pattern Loss: {args.use_pattern_loss}")
    logger.info(f"Use Imitation: {args.use_imitation}")
    logger.info(f"Device: {args.device}")
    logger.info("="*80)
    
    # Create model
    logger.info("\nCreating model...")
    model = create_model(
        base_model_name=args.base_model,
        num_patterns=4,
        pattern_dim=768,
        hidden_dim=256,
        dropout=0.2,
        freeze_encoder=False,
        device=args.device
    )
    
    # Load pattern embeddings if provided
    if args.pattern_embeddings and Path(args.pattern_embeddings).exists():
        logger.info(f"\nLoading pattern embeddings from: {args.pattern_embeddings}")
        checkpoint = torch.load(args.pattern_embeddings, map_location=args.device, weights_only=False)
        pattern_embeddings = checkpoint['pattern_embeddings']
        
        for name, embedding in pattern_embeddings.items():
            model.whitelist_patterns[name].data = embedding.to(args.device)
        
        logger.info(f"✓ Pattern embeddings loaded (Epoch {checkpoint.get('epoch', 'unknown')}, Loss: {checkpoint.get('loss', 'unknown'):.4f})")
    
    # Load datasets
    logger.info("\nLoading datasets...")
    train_dataset = WhitelistDataset(Path(args.data))
    val_dataset = WhitelistDataset(Path(args.validation))
    
    train_loader = DataLoader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=True,
        collate_fn=lambda x: x
    )
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=args.batch_size,
        shuffle=False,
        collate_fn=lambda x: x
    )
    
    # Setup optimizer
    optimizer = optim.AdamW(
        model.parameters(),
        lr=args.learning_rate,
        weight_decay=0.01
    )
    
    # Setup loss
    focal_loss = FocalLoss(alpha=[0.3, 0.7], gamma=2.0).to(args.device)
    
    # Teacher model for imitation (optional)
    teacher_model = None
    if args.use_imitation:
        try:
            from detectors.orchestrator.domain.hotfix import load_v21_hotfix_detector
            teacher_model = load_v21_hotfix_detector(
                v1_model_path="models/code_intent_adversarial_v1/best_model.pt",
                v2_model_path="models/code_intent_adversarial_v2/best_model.pt",
                device=args.device
            )
            logger.info("✓ V2.1 Hotfix loaded as teacher model")
        except Exception as e:
            logger.warning(f"Could not load V2.1 teacher model: {e}")
            logger.warning("Continuing without imitation learning")
            args.use_imitation = False
    
    # Training loop
    logger.info("\nStarting training...")
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    best_val_accuracy = 0.0
    
    for epoch in range(args.epochs):
        # Train
        train_losses = train_epoch(
            model=model,
            dataloader=train_loader,
            optimizer=optimizer,
            focal_loss=focal_loss,
            device=args.device,
            epoch=epoch,
            use_pattern_loss=args.use_pattern_loss,
            use_imitation=args.use_imitation,
            teacher_model=teacher_model
        )
        
        # Validate
        val_metrics = validate(model, val_loader, args.device)
        
        logger.info(f"\nEpoch {epoch+1}/{args.epochs}:")
        logger.info(f"  Train Losses:")
        logger.info(f"    Classification: {train_losses['class_loss']:.4f}")
        logger.info(f"    Pattern: {train_losses['pattern_loss']:.4f}")
        logger.info(f"    Imitation: {train_losses['imitation_loss']:.4f}")
        logger.info(f"  Validation:")
        logger.info(f"    Accuracy: {val_metrics['accuracy']:.4f}")
        logger.info(f"    Benign Accuracy: {val_metrics['benign_accuracy']:.4f}")
        logger.info(f"    Malicious Accuracy: {val_metrics['malicious_accuracy']:.4f}")
        
        # Save checkpoint
        if val_metrics['accuracy'] > best_val_accuracy:
            best_val_accuracy = val_metrics['accuracy']
            checkpoint_path = output_dir / f"best_model_epoch_{epoch+1}.pt"
            
            torch.save({
                'epoch': epoch + 1,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'val_accuracy': val_metrics['accuracy'],
                'val_benign_accuracy': val_metrics['benign_accuracy'],
                'val_malicious_accuracy': val_metrics['malicious_accuracy'],
                'train_losses': train_losses,
                'pattern_embeddings': model.get_pattern_embeddings()
            }, checkpoint_path)
            
            logger.info(f"💾 Saved best model to: {checkpoint_path} (accuracy: {val_metrics['accuracy']:.4f})")
    
    logger.info("\n" + "="*80)
    logger.info("✅ Main training complete!")
    logger.info("="*80)
    logger.info(f"\nBest validation accuracy: {best_val_accuracy:.4f}")
    logger.info(f"\nNext step: Fine-tuning with V2.1 (optional)")

if __name__ == "__main__":
    main()

