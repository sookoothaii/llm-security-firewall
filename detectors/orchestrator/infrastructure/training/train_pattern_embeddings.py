"""
Pattern Embedding Pre-Training - Phase 1

Trainiert die learnable Whitelist Pattern Embeddings bevor das vollständige Modell trainiert wird.

Usage:
    python -m detectors.orchestrator.infrastructure.training.train_pattern_embeddings \
        --data data/adversarial_training/v3_whitelist_learner/train_patterns.jsonl \
        --output models/v3_whitelist_learner/pattern_embeddings.pt \
        --epochs 3 \
        --batch-size 32 \
        --learning-rate 1e-3
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

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.infrastructure.training.models import (
    WhitelistAwareCodeIntentModel,
    create_model
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PatternDataset(Dataset):
    """Dataset für Pattern Pre-Training."""
    
    def __init__(self, data_path: Path):
        """Load pattern training data."""
        self.samples = []
        
        with open(data_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    sample = json.loads(line)
                    self.samples.append({
                        'text': sample['text'],
                        'pattern': sample['pattern'],
                        'category': sample.get('category', 'unknown')
                    })
        
        logger.info(f"Loaded {len(self.samples)} pattern samples")
        logger.info(f"Patterns: {dict(Counter(s['pattern'] for s in self.samples))}")
    
    def __len__(self):
        return len(self.samples)
    
    def __getitem__(self, idx):
        return self.samples[idx]


def train_pattern_embeddings(
    model: WhitelistAwareCodeIntentModel,
    dataloader: DataLoader,
    optimizer: optim.Optimizer,
    device: str,
    epoch: int
) -> float:
    """
    Train pattern embeddings for one epoch.
    
    Args:
        model: WhitelistAwareCodeIntentModel
        dataloader: Pattern training dataloader
        optimizer: Optimizer
        device: Device
        epoch: Current epoch
        
    Returns:
        Average loss
    """
    model.train()
    total_loss = 0.0
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
        patterns = [item['pattern'] for item in batch]
        
        # Get text embeddings
        text_embeddings = model.encode_text(texts)
        
        # Get pattern embeddings
        pattern_embeddings = torch.stack([
            model.whitelist_patterns[pattern]
            for pattern in patterns
        ])
        
        # Compute cosine similarity (should be high for matching patterns)
        # Target: similarity = 1.0 for matching pattern
        similarities = model.compute_pattern_similarities(text_embeddings)
        
        # Loss: maximize similarity for correct pattern
        losses = []
        for i, pattern in enumerate(patterns):
            # Get similarity for this pattern
            pattern_sim = similarities[pattern][i]
            
            # Target is 1.0 (high similarity)
            # Use MSE loss: (1.0 - similarity)^2
            loss = (1.0 - pattern_sim) ** 2
            losses.append(loss)
        
        loss = torch.stack(losses).mean()
        
        # Backward
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
        num_batches += 1
        
        progress_bar.set_postfix({'loss': loss.item()})
    
    avg_loss = total_loss / num_batches if num_batches > 0 else 0.0
    return avg_loss


def main():
    parser = argparse.ArgumentParser(
        description="Train Pattern Embeddings (Phase 1)"
    )
    parser.add_argument(
        "--data",
        type=str,
        required=True,
        help="Path to pattern training data (JSONL)"
    )
    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output path for pattern embeddings checkpoint"
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default="microsoft/codebert-base",
        help="Base model name (default: microsoft/codebert-base)"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of epochs (default: 3)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=32,
        help="Batch size (default: 32)"
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=1e-3,
        help="Learning rate (default: 1e-3)"
    )
    parser.add_argument(
        "--freeze-encoder",
        action="store_true",
        help="Freeze CodeBERT encoder (only train pattern embeddings)"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device (default: cuda if available)"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("PATTERN EMBEDDING PRE-TRAINING - PHASE 1")
    logger.info("="*80)
    logger.info(f"Data: {args.data}")
    logger.info(f"Output: {args.output}")
    logger.info(f"Base Model: {args.base_model}")
    logger.info(f"Epochs: {args.epochs}")
    logger.info(f"Batch Size: {args.batch_size}")
    logger.info(f"Learning Rate: {args.learning_rate}")
    logger.info(f"Freeze Encoder: {args.freeze_encoder}")
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
        freeze_encoder=args.freeze_encoder,
        device=args.device
    )
    
    # Load dataset
    logger.info("\nLoading dataset...")
    dataset = PatternDataset(Path(args.data))
    dataloader = DataLoader(
        dataset,
        batch_size=args.batch_size,
        shuffle=True,
        collate_fn=lambda x: x  # Keep as list of dicts
    )
    
    # Setup optimizer (only pattern embeddings if freeze_encoder)
    if args.freeze_encoder:
        optimizer = optim.AdamW(
            model.whitelist_patterns.parameters(),
            lr=args.learning_rate
        )
        logger.info("Optimizer: Only pattern embeddings (encoder frozen)")
    else:
        optimizer = optim.AdamW(
            [
                {'params': model.whitelist_patterns.parameters(), 'lr': args.learning_rate},
                {'params': model.encoder.parameters(), 'lr': args.learning_rate * 0.1}  # Lower LR for encoder
            ]
        )
        logger.info("Optimizer: Pattern embeddings + encoder (lower LR for encoder)")
    
    # Training loop
    logger.info("\nStarting training...")
    best_loss = float('inf')
    
    for epoch in range(args.epochs):
        avg_loss = train_pattern_embeddings(
            model=model,
            dataloader=dataloader,
            optimizer=optimizer,
            device=args.device,
            epoch=epoch
        )
        
        logger.info(f"Epoch {epoch+1}/{args.epochs} - Loss: {avg_loss:.4f}")
        
        # Save checkpoint
        if avg_loss < best_loss:
            best_loss = avg_loss
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save pattern embeddings
            pattern_embeddings = model.get_pattern_embeddings()
            checkpoint = {
                'pattern_embeddings': pattern_embeddings,
                'epoch': epoch + 1,
                'loss': avg_loss,
                'model_config': {
                    'base_model': args.base_model,
                    'num_patterns': 4,
                    'pattern_dim': 768
                }
            }
            
            torch.save(checkpoint, output_path)
            logger.info(f"💾 Saved checkpoint to: {output_path} (loss: {avg_loss:.4f})")
    
    logger.info("\n" + "="*80)
    logger.info("✅ Pattern embedding pre-training complete!")
    logger.info("="*80)
    logger.info(f"\nPattern embeddings saved to: {args.output}")
    logger.info("\nNext step: Main training with train_whitelist_learner.py")


if __name__ == "__main__":
    from collections import Counter
    main()

