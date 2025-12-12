"""
Train Whitelist Classifier

Binäre Klassifikation für Whitelist-Erkennung.
Optimiert für hohen Recall auf Whitelist-Cases.

Usage:
    python -m detectors.orchestrator.infrastructure.training.train_whitelist_classifier \
        --data data/adversarial_training/whitelist_module/train.jsonl \
        --validation data/adversarial_training/whitelist_module/validation.jsonl \
        --output models/whitelist_classifier/ \
        --epochs 5 \
        --batch-size 16 \
        --learning-rate 2e-5
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm
import numpy as np
from sklearn.metrics import precision_recall_fscore_support, accuracy_score

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.infrastructure.training.models.whitelist_classifier import (
    WhitelistClassifier,
    create_whitelist_classifier
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class WhitelistDataset(Dataset):
    """Dataset für Whitelist Classifier."""
    
    def __init__(self, data_path: Path):
        """Load training data."""
        self.samples = []
        
        with open(data_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    sample = json.loads(line)
                    self.samples.append({
                        'text': sample['text'],
                        'label': sample['label']  # 1=Whitelist, 0=Not Whitelist
                    })
        
        logger.info(f"Loaded {len(self.samples)} samples")
        logger.info(f"  Whitelist (1): {sum(s['label'] for s in self.samples)}")
        logger.info(f"  Not Whitelist (0): {len(self.samples) - sum(s['label'] for s in self.samples)}")
    
    def __len__(self):
        return len(self.samples)
    
    def __getitem__(self, idx):
        return self.samples[idx]


def train_epoch(
    model: WhitelistClassifier,
    dataloader: DataLoader,
    optimizer: optim.Optimizer,
    criterion: nn.Module,
    device: str,
    epoch: int,
    pos_weight: float = 2.0
) -> Dict[str, float]:
    """Train one epoch."""
    model.train()
    total_loss = 0.0
    num_batches = 0
    
    progress_bar = tqdm(dataloader, desc=f"Epoch {epoch+1}")
    
    for batch in progress_bar:
        texts = [item['text'] for item in batch]
        labels = torch.tensor(
            [item['label'] for item in batch],
            dtype=torch.float32
        ).to(device).unsqueeze(1)
        
        # Forward
        logits = model.forward(texts=texts)
        
        # Loss with positive weight
        loss = criterion(logits, labels)
        
        # Apply positive weight manually if needed
        if pos_weight > 1.0:
            # Weight positive samples more
            pos_mask = (labels == 1.0).float()
            loss = loss * (1.0 + (pos_weight - 1.0) * pos_mask)
            loss = loss.mean()
        
        # Backward
        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimizer.step()
        
        total_loss += loss.item()
        num_batches += 1
        
        progress_bar.set_postfix({'loss': loss.item()})
    
    return {'loss': total_loss / num_batches if num_batches > 0 else 0.0}


def validate(
    model: WhitelistClassifier,
    dataloader: DataLoader,
    device: str,
    threshold: float = 0.5
) -> Dict[str, float]:
    """Validate model."""
    model.eval()
    all_predictions = []
    all_labels = []
    
    with torch.no_grad():
        for batch in dataloader:
            texts = [item['text'] for item in batch]
            labels = [item['label'] for item in batch]
            
            logits = model.forward(texts=texts)
            probabilities = torch.sigmoid(logits).squeeze(-1)
            predictions = (probabilities >= threshold).long().cpu().numpy()
            
            all_predictions.extend(predictions)
            all_labels.extend(labels)
    
    # Calculate metrics
    accuracy = accuracy_score(all_labels, all_predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(
        all_labels, all_predictions, average='binary', zero_division=0
    )
    
    # Per-class metrics
    precision_pos, recall_pos, f1_pos, _ = precision_recall_fscore_support(
        all_labels, all_predictions, average=None, zero_division=0, labels=[0, 1]
    )
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'precision_whitelist': precision_pos[1] if len(precision_pos) > 1 else 0.0,
        'recall_whitelist': recall_pos[1] if len(recall_pos) > 1 else 0.0,
        'f1_whitelist': f1_pos[1] if len(f1_pos) > 1 else 0.0
    }


def main():
    parser = argparse.ArgumentParser(description="Train Whitelist Classifier")
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
        "--output",
        type=str,
        required=True,
        help="Output directory for model checkpoints"
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default="distilbert-base-uncased",
        help="Base model name"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=5,
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
        "--pos-weight",
        type=float,
        default=2.0,
        help="Positive weight for loss (higher = more focus on Whitelist recall)"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Classification threshold"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("WHITELIST CLASSIFIER TRAINING")
    logger.info("="*80)
    logger.info(f"Training Data: {args.data}")
    logger.info(f"Validation Data: {args.validation}")
    logger.info(f"Output: {args.output}")
    logger.info(f"Base Model: {args.base_model}")
    logger.info(f"Epochs: {args.epochs}")
    logger.info(f"Batch Size: {args.batch_size}")
    logger.info(f"Learning Rate: {args.learning_rate}")
    logger.info(f"Positive Weight: {args.pos_weight}")
    logger.info(f"Device: {args.device}")
    logger.info("="*80)
    
    # Create model
    logger.info("\nCreating model...")
    model = create_whitelist_classifier(
        base_model_name=args.base_model,
        dropout=0.1,
        freeze_encoder=False,
        device=args.device
    )
    
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
    
    # Setup loss (BCE with positive weight)
    criterion = nn.BCEWithLogitsLoss(reduction='none')
    
    # Training loop
    logger.info("\nStarting training...")
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    best_recall = 0.0
    best_f1 = 0.0
    
    for epoch in range(args.epochs):
        # Train
        train_losses = train_epoch(
            model=model,
            dataloader=train_loader,
            optimizer=optimizer,
            criterion=criterion,
            device=args.device,
            epoch=epoch,
            pos_weight=args.pos_weight
        )
        
        # Validate
        val_metrics = validate(model, val_loader, args.device, threshold=args.threshold)
        
        logger.info(f"\nEpoch {epoch+1}/{args.epochs}:")
        logger.info(f"  Train Loss: {train_losses['loss']:.4f}")
        logger.info(f"  Validation:")
        logger.info(f"    Accuracy: {val_metrics['accuracy']:.4f}")
        logger.info(f"    Precision: {val_metrics['precision']:.4f}")
        logger.info(f"    Recall: {val_metrics['recall']:.4f}")
        logger.info(f"    F1: {val_metrics['f1']:.4f}")
        logger.info(f"  Whitelist-Specific:")
        logger.info(f"    Precision: {val_metrics['precision_whitelist']:.4f}")
        logger.info(f"    Recall: {val_metrics['recall_whitelist']:.4f} ⭐ (Target: ≥ 0.95)")
        logger.info(f"    F1: {val_metrics['f1_whitelist']:.4f}")
        
        # Save checkpoint
        should_save = False
        if val_metrics['recall_whitelist'] > best_recall:
            best_recall = val_metrics['recall_whitelist']
            should_save = True
            reason = "best_recall"
        elif val_metrics['f1_whitelist'] > best_f1:
            best_f1 = val_metrics['f1_whitelist']
            should_save = True
            reason = "best_f1"
        
        if should_save:
            checkpoint_path = output_dir / f"best_model_epoch_{epoch+1}.pt"
            
            torch.save({
                'epoch': epoch + 1,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'val_metrics': val_metrics,
                'train_loss': train_losses['loss'],
                'best_recall': best_recall,
                'best_f1': best_f1
            }, checkpoint_path)
            
            logger.info(f"💾 Saved checkpoint to: {checkpoint_path} ({reason})")
    
    logger.info("\n" + "="*80)
    logger.info("✅ Training complete!")
    logger.info("="*80)
    logger.info(f"\nBest Whitelist Recall: {best_recall:.4f}")
    logger.info(f"Target: ≥ 0.95")
    
    if best_recall >= 0.95:
        logger.info("✅ TARGET ACHIEVED - Whitelist Recall ≥ 95%")
    else:
        logger.info("⚠️ Target not achieved - Consider:")
        logger.info("  - More training epochs")
        logger.info("  - Higher positive weight")
        logger.info("  - More positive samples")
    
    logger.info(f"\nNext step: Integrate with V2.1 Hotfix")

if __name__ == "__main__":
    main()

