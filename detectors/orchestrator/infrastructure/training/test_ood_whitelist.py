"""
Out-of-Distribution Test für Whitelist Classifier

Testet den Whitelist Classifier mit komplett neuen, ungesehenen Daten.

Usage:
    python -m detectors.orchestrator.infrastructure.training.test_ood_whitelist \
        --model models/whitelist_classifier/best_model_epoch_3.pt \
        --new-data data/adversarial_training/ood_test_samples.jsonl \
        --output results/whitelist_ood_results.json
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any
import torch
from torch.utils.data import Dataset, DataLoader
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.infrastructure.training.models.whitelist_classifier import (
    WhitelistClassifier,
    create_whitelist_classifier
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class OODDataset(Dataset):
    """Dataset für OOD Test."""
    
    def __init__(self, samples: List[Dict]):
        self.samples = samples
    
    def __len__(self):
        return len(self.samples)
    
    def __getitem__(self, idx):
        return self.samples[idx]


def load_model(model_path: Path, device: str) -> WhitelistClassifier:
    """Load trained model."""
    logger.info(f"Loading model from: {model_path}")
    
    model = create_whitelist_classifier(
        base_model_name="distilbert-base-uncased",
        dropout=0.1,
        freeze_encoder=False,
        device=device
    )
    
    checkpoint = torch.load(model_path, map_location=device)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    
    logger.info(f"Model loaded. Epoch: {checkpoint.get('epoch', 'unknown')}")
    if 'val_metrics' in checkpoint:
        logger.info(f"Training metrics: {checkpoint['val_metrics']}")
    
    return model


def evaluate_ood(
    model: WhitelistClassifier,
    samples: List[Dict],
    device: str,
    threshold: float = 0.5,
    batch_size: int = 16
) -> Dict[str, Any]:
    """Evaluate on OOD data."""
    logger.info(f"\nEvaluating on {len(samples)} OOD samples...")
    
    dataset = OODDataset(samples)
    dataloader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=False,
        collate_fn=lambda x: x
    )
    
    all_predictions = []
    all_labels = []
    all_probs = []
    all_texts = []
    
    with torch.no_grad():
        for batch in dataloader:
            texts = [item['text'] for item in batch]
            labels = [item['label'] for item in batch]
            
            logits = model.forward(texts=texts)
            probs = torch.sigmoid(logits).squeeze(-1).cpu().numpy()
            preds = (probs >= threshold).astype(int)
            
            all_predictions.extend(preds)
            all_labels.extend(labels)
            all_probs.extend(probs.tolist())
            all_texts.extend(texts)
    
    # Calculate metrics
    accuracy = accuracy_score(all_labels, all_predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(
        all_labels, all_predictions, average='binary', zero_division=0
    )
    
    precision_pos, recall_pos, f1_pos, _ = precision_recall_fscore_support(
        all_labels, all_predictions, average=None, zero_division=0, labels=[0, 1]
    )
    
    cm = confusion_matrix(all_labels, all_predictions)
    
    # Per-class breakdown
    positive_samples = [s for s in samples if s['label'] == 1]
    negative_samples = [s for s in samples if s['label'] == 0]
    
    positive_correct = sum(1 for i, label in enumerate(all_labels) 
                          if label == 1 and all_predictions[i] == 1)
    negative_correct = sum(1 for i, label in enumerate(all_labels) 
                          if label == 0 and all_predictions[i] == 0)
    
    results = {
        'total_samples': len(samples),
        'positive_samples': len(positive_samples),
        'negative_samples': len(negative_samples),
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'precision_whitelist': float(precision_pos[1]) if len(precision_pos) > 1 else 0.0,
        'recall_whitelist': float(recall_pos[1]) if len(recall_pos) > 1 else 0.0,
        'f1_whitelist': float(f1_pos[1]) if len(f1_pos) > 1 else 0.0,
        'confusion_matrix': cm.tolist(),
        'positive_accuracy': positive_correct / len(positive_samples) if positive_samples else 0.0,
        'negative_accuracy': negative_correct / len(negative_samples) if negative_samples else 0.0,
        'false_positives': int(cm[0][1]) if len(cm) > 1 else 0,
        'false_negatives': int(cm[1][0]) if len(cm) > 1 and len(cm[1]) > 0 else 0,
        'detailed_predictions': [
            {
                'text': text[:100] + '...' if len(text) > 100 else text,
                'true_label': int(label),
                'predicted_label': int(pred),
                'probability': float(prob)
            }
            for text, label, pred, prob in zip(all_texts, all_labels, all_predictions, all_probs)
        ][:50]  # First 50 for review
    }
    
    return results


def main():
    parser = argparse.ArgumentParser(description="OOD Test für Whitelist Classifier")
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to trained model checkpoint"
    )
    parser.add_argument(
        "--new-data",
        type=str,
        required=True,
        help="Path to OOD test data (JSONL)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/whitelist_ood_results.json",
        help="Output JSON path"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Classification threshold"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=16,
        help="Batch size"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("OUT-OF-DISTRIBUTION TEST - WHITELIST CLASSIFIER")
    logger.info("="*80)
    logger.info(f"Model: {args.model}")
    logger.info(f"OOD Data: {args.new_data}")
    logger.info(f"Threshold: {args.threshold}")
    logger.info(f"Device: {args.device}")
    logger.info("="*80)
    
    # Load model
    logger.info("\n📂 Loading model...")
    model = load_model(Path(args.model), args.device)
    
    # Load OOD data
    logger.info("\n📂 Loading OOD test data...")
    ood_samples = []
    with open(args.new_data, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                sample = json.loads(line)
                ood_samples.append({
                    'text': sample.get('text', sample.get('input', '')),
                    'label': sample.get('label', 0)  # 1=Whitelist, 0=Not Whitelist
                })
    
    logger.info(f"Loaded {len(ood_samples)} OOD samples")
    positive_count = sum(1 for s in ood_samples if s['label'] == 1)
    negative_count = len(ood_samples) - positive_count
    logger.info(f"  Positive (Whitelist): {positive_count}")
    logger.info(f"  Negative: {negative_count}")
    
    # Evaluate
    results = evaluate_ood(
        model=model,
        samples=ood_samples,
        device=args.device,
        threshold=args.threshold,
        batch_size=args.batch_size
    )
    
    # Print results
    logger.info("\n" + "="*80)
    logger.info("📊 OOD TEST RESULTS")
    logger.info("="*80)
    
    logger.info(f"\nOverall Metrics:")
    logger.info(f"  Accuracy: {results['accuracy']:.4f}")
    logger.info(f"  Precision: {results['precision']:.4f}")
    logger.info(f"  Recall: {results['recall']:.4f}")
    logger.info(f"  F1: {results['f1']:.4f}")
    
    logger.info(f"\nWhitelist-Specific Metrics:")
    logger.info(f"  Precision: {results['precision_whitelist']:.4f}")
    logger.info(f"  Recall: {results['recall_whitelist']:.4f} ⭐")
    logger.info(f"  F1: {results['f1_whitelist']:.4f}")
    
    logger.info(f"\nPer-Class Accuracy:")
    logger.info(f"  Positive (Whitelist): {results['positive_accuracy']:.4f}")
    logger.info(f"  Negative: {results['negative_accuracy']:.4f}")
    
    logger.info(f"\nError Analysis:")
    logger.info(f"  False Positives: {results['false_positives']}")
    logger.info(f"  False Negatives: {results['false_negatives']}")
    
    # Analysis
    logger.info("\n" + "="*80)
    logger.info("🔍 ANALYSIS")
    logger.info("="*80)
    
    if results['accuracy'] > 0.99:
        logger.error("❌ KRITISCH: OOD Accuracy > 99%")
        logger.error("   → Verdacht auf Data Leakage oder zu ähnliche OOD Daten!")
    elif results['accuracy'] > 0.95:
        logger.warning("⚠️  WARNUNG: OOD Accuracy > 95%")
        logger.warning("   → Sehr gut, aber ungewöhnlich hoch")
    elif results['accuracy'] > 0.90:
        logger.info("✅ OOD Accuracy im erwarteten Bereich (90-95%)")
    elif results['accuracy'] > 0.85:
        logger.warning("⚠️  WARNUNG: OOD Accuracy < 90%")
        logger.warning("   → Model generalisiert nicht gut genug")
    else:
        logger.error("❌ KRITISCH: OOD Accuracy < 85%")
        logger.error("   → Model generalisiert schlecht!")
    
    if results['recall_whitelist'] < 0.90:
        logger.error("❌ KRITISCH: Whitelist Recall < 90%")
        logger.error("   → Model verpasst zu viele Whitelist-Cases!")
    elif results['recall_whitelist'] < 0.95:
        logger.warning("⚠️  WARNUNG: Whitelist Recall < 95%")
        logger.warning("   → Unter Zielwert, aber akzeptabel")
    else:
        logger.info("✅ Whitelist Recall ≥ 95% (Ziel erreicht)")
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    logger.info(f"\n💾 Results saved to: {output_path}")
    
    logger.info("\n" + "="*80)
    logger.info("✅ OOD Test complete!")
    logger.info("="*80)
    
    # Final verdict
    if results['accuracy'] < 0.85 or results['recall_whitelist'] < 0.90:
        logger.error("\n❌ DEPLOYMENT NICHT EMPFOHLEN - Model generalisiert nicht gut genug")
        return 1
    elif results['accuracy'] > 0.99:
        logger.error("\n❌ DEPLOYMENT NICHT EMPFOHLEN - Verdacht auf Data Leakage")
        return 1
    else:
        logger.info("\n✅ OOD Test bestanden - Model kann deployed werden (mit Monitoring)")
        return 0


if __name__ == "__main__":
    exit(main())

