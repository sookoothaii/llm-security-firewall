"""
5-Fold Cross-Validation für Whitelist Classifier

Validiert den Whitelist Classifier mit Cross-Validation um Overfitting zu erkennen.

Usage:
    python -m detectors.orchestrator.infrastructure.training.cross_validate_whitelist \
        --dataset data/adversarial_training/whitelist_module/dataset.json \
        --output results/whitelist_cv_results.json \
        --folds 5 \
        --epochs 3 \
        --batch-size 16
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple
import random
import numpy as np
from sklearn.model_selection import StratifiedKFold
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm
from sklearn.metrics import accuracy_score, precision_recall_fscore_support

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.infrastructure.training.models.whitelist_classifier import (
    create_whitelist_classifier
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WhitelistDataset(Dataset):
    """Dataset für Whitelist Classifier."""
    
    def __init__(self, samples: List[Dict]):
        """Initialize with samples."""
        self.samples = samples
    
    def __len__(self):
        return len(self.samples)
    
    def __getitem__(self, idx):
        return self.samples[idx]


def train_fold(
    train_samples: List[Dict],
    val_samples: List[Dict],
    fold: int,
    epochs: int,
    batch_size: int,
    device: str,
    base_model: str = "distilbert-base-uncased"
) -> Dict[str, Any]:
    """Train one fold."""
    logger.info(f"\n{'='*60}")
    logger.info(f"Fold {fold+1}")
    logger.info(f"{'='*60}")
    
    # Create model
    model = create_whitelist_classifier(
        base_model_name=base_model,
        dropout=0.1,
        freeze_encoder=False,
        device=device
    )
    
    # Create datasets
    train_dataset = WhitelistDataset(train_samples)
    val_dataset = WhitelistDataset(val_samples)
    
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        collate_fn=lambda x: x
    )
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=lambda x: x
    )
    
    # Setup optimizer
    optimizer = optim.AdamW(
        model.parameters(),
        lr=2e-5,
        weight_decay=0.01
    )
    
    criterion = nn.BCEWithLogitsLoss(reduction='none')
    
    # Training loop
    best_val_accuracy = 0.0
    best_val_recall = 0.0
    fold_history = []
    
    for epoch in range(epochs):
        # Train
        model.train()
        train_loss = 0.0
        num_batches = 0
        
        for batch in train_loader:
            texts = [item['text'] for item in batch]
            labels = torch.tensor(
                [item['label'] for item in batch],
                dtype=torch.float32
            ).to(device).unsqueeze(1)
            
            logits = model.forward(texts=texts)
            loss = criterion(logits, labels)
            
            # Apply positive weight
            pos_mask = (labels == 1.0).float()
            loss = loss * (1.0 + 1.0 * pos_mask)  # pos_weight = 2.0
            loss = loss.mean()
            
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            
            train_loss += loss.item()
            num_batches += 1
        
        # Validate
        model.eval()
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch in val_loader:
                texts = [item['text'] for item in batch]
                labels = [item['label'] for item in batch]
                
                logits = model.forward(texts=texts)
                probs = torch.sigmoid(logits).squeeze(-1)
                preds = (probs >= 0.5).long().cpu().numpy()
                
                all_preds.extend(preds)
                all_labels.extend(labels)
        
        # Calculate metrics
        accuracy = accuracy_score(all_labels, all_preds)
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_preds, average='binary', zero_division=0
        )
        
        precision_pos, recall_pos, f1_pos, _ = precision_recall_fscore_support(
            all_labels, all_preds, average=None, zero_division=0, labels=[0, 1]
        )
        
        val_metrics = {
            'epoch': epoch + 1,
            'train_loss': train_loss / num_batches if num_batches > 0 else 0.0,
            'val_accuracy': accuracy,
            'val_precision': precision,
            'val_recall': recall,
            'val_f1': f1,
            'val_precision_whitelist': precision_pos[1] if len(precision_pos) > 1 else 0.0,
            'val_recall_whitelist': recall_pos[1] if len(recall_pos) > 1 else 0.0,
            'val_f1_whitelist': f1_pos[1] if len(f1_pos) > 1 else 0.0
        }
        
        fold_history.append(val_metrics)
        
        if accuracy > best_val_accuracy:
            best_val_accuracy = accuracy
        if recall_pos[1] if len(recall_pos) > 1 else 0.0 > best_val_recall:
            best_val_recall = recall_pos[1] if len(recall_pos) > 1 else 0.0
        
        logger.info(
            f"  Epoch {epoch+1}/{epochs}: "
            f"Loss={val_metrics['train_loss']:.4f}, "
            f"Acc={accuracy:.4f}, "
            f"Recall={recall_pos[1] if len(recall_pos) > 1 else 0.0:.4f}"
        )
    
    return {
        'fold': fold + 1,
        'best_val_accuracy': best_val_accuracy,
        'best_val_recall': best_val_recall,
        'final_metrics': fold_history[-1] if fold_history else {},
        'history': fold_history
    }


def main():
    parser = argparse.ArgumentParser(description="Cross-Validate Whitelist Classifier")
    parser.add_argument(
        "--dataset",
        type=str,
        required=True,
        help="Path to dataset JSON (with train/validation splits)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/whitelist_cv_results.json",
        help="Output JSON path"
    )
    parser.add_argument(
        "--folds",
        type=int,
        default=5,
        help="Number of folds"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Epochs per fold"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
        help="Batch size"
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default="distilbert-base-uncased",
        help="Base model name"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device"
    )
    
    args = parser.parse_args()
    
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    
    logger.info("="*80)
    logger.info("5-FOLD CROSS-VALIDATION - WHITELIST CLASSIFIER")
    logger.info("="*80)
    logger.info(f"Dataset: {args.dataset}")
    logger.info(f"Folds: {args.folds}")
    logger.info(f"Epochs per fold: {args.epochs}")
    logger.info(f"Batch Size: {args.batch_size}")
    logger.info(f"Device: {args.device}")
    logger.info("="*80)
    
    # Load dataset
    logger.info("\n📂 Loading dataset...")
    with open(args.dataset, 'r', encoding='utf-8') as f:
        dataset = json.load(f)
    
    # Combine train and validation for CV
    all_samples = dataset.get('train', []) + dataset.get('validation', [])
    logger.info(f"Total samples: {len(all_samples)}")
    
    # Extract labels for stratified split
    labels = [sample['label'] for sample in all_samples]
    texts = [sample['text'] for sample in all_samples]
    
    positive_count = sum(labels)
    negative_count = len(labels) - positive_count
    logger.info(f"  Positive (Whitelist): {positive_count} ({positive_count/len(labels)*100:.1f}%)")
    logger.info(f"  Negative: {negative_count} ({negative_count/len(labels)*100:.1f}%)")
    
    # Create stratified folds
    skf = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=args.seed)
    
    fold_results = []
    
    for fold, (train_idx, val_idx) in enumerate(skf.split(texts, labels)):
        train_samples = [all_samples[i] for i in train_idx]
        val_samples = [all_samples[i] for i in val_idx]
        
        logger.info(f"\nFold {fold+1}: Train={len(train_samples)}, Val={len(val_samples)}")
        
        fold_result = train_fold(
            train_samples=train_samples,
            val_samples=val_samples,
            fold=fold,
            epochs=args.epochs,
            batch_size=args.batch_size,
            device=args.device,
            base_model=args.base_model
        )
        
        fold_results.append(fold_result)
    
    # Aggregate results
    accuracies = [r['best_val_accuracy'] for r in fold_results]
    recalls = [r['best_val_recall'] for r in fold_results]
    
    results = {
        'folds': args.folds,
        'epochs_per_fold': args.epochs,
        'fold_results': fold_results,
        'aggregated': {
            'accuracy': {
                'mean': np.mean(accuracies),
                'std': np.std(accuracies),
                'min': np.min(accuracies),
                'max': np.max(accuracies),
                'values': accuracies
            },
            'recall_whitelist': {
                'mean': np.mean(recalls),
                'std': np.std(recalls),
                'min': np.min(recalls),
                'max': np.max(recalls),
                'values': recalls
            }
        }
    }
    
    # Print summary
    logger.info("\n" + "="*80)
    logger.info("📊 CROSS-VALIDATION RESULTS")
    logger.info("="*80)
    
    logger.info(f"\nAccuracy:")
    logger.info(f"  Mean: {results['aggregated']['accuracy']['mean']:.4f}")
    logger.info(f"  Std:  {results['aggregated']['accuracy']['std']:.4f}")
    logger.info(f"  Min:  {results['aggregated']['accuracy']['min']:.4f}")
    logger.info(f"  Max:  {results['aggregated']['accuracy']['max']:.4f}")
    
    logger.info(f"\nWhitelist Recall:")
    logger.info(f"  Mean: {results['aggregated']['recall_whitelist']['mean']:.4f}")
    logger.info(f"  Std:  {results['aggregated']['recall_whitelist']['std']:.4f}")
    logger.info(f"  Min:  {results['aggregated']['recall_whitelist']['min']:.4f}")
    logger.info(f"  Max:  {results['aggregated']['recall_whitelist']['max']:.4f}")
    
    # Analysis
    logger.info("\n" + "="*80)
    logger.info("🔍 ANALYSIS")
    logger.info("="*80)
    
    mean_acc = results['aggregated']['accuracy']['mean']
    std_acc = results['aggregated']['accuracy']['std']
    
    if mean_acc > 0.99 and std_acc < 0.01:
        logger.error("❌ KRITISCH: Mean Accuracy > 99% mit sehr niedriger Std (< 1%)")
        logger.error("   → Verdacht auf Overfitting oder Data Leakage!")
    elif mean_acc > 0.95:
        logger.warning("⚠️  WARNUNG: Mean Accuracy > 95%")
        logger.warning("   → Mögliches Overfitting, OOD Test empfohlen")
    else:
        logger.info("✅ Accuracy im erwarteten Bereich")
    
    if std_acc > 0.05:
        logger.warning("⚠️  WARNUNG: Hohe Standardabweichung (> 5%)")
        logger.warning("   → Model ist instabil, mehr Daten oder Regularisierung nötig")
    else:
        logger.info("✅ Standardabweichung akzeptabel")
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    logger.info(f"\n💾 Results saved to: {output_path}")
    
    logger.info("\n" + "="*80)
    logger.info("✅ Cross-Validation complete!")
    logger.info("="*80)


if __name__ == "__main__":
    main()

