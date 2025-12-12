"""Check Whitelist Classifier Training Results"""

import glob
import torch
from pathlib import Path

checkpoints = sorted(glob.glob('models/whitelist_classifier/best_model_epoch_*.pt'))

print("="*80)
print("WHITELIST CLASSIFIER TRAINING RESULTS")
print("="*80)

if not checkpoints:
    print("\n⚠️ No checkpoints found!")
    exit(1)

print(f"\nFound {len(checkpoints)} checkpoint(s):")
for ckpt in checkpoints:
    print(f"  - {ckpt}")

latest = checkpoints[-1]
print(f"\nLatest checkpoint: {latest}")

ckpt = torch.load(latest, map_location='cpu', weights_only=False)
metrics = ckpt.get('val_metrics', {})

print(f"\nValidation Metrics (Epoch {ckpt.get('epoch', 'unknown')}):")
print(f"  Accuracy: {metrics.get('accuracy', 0):.4f}")
print(f"  Precision: {metrics.get('precision', 0):.4f}")
print(f"  Recall: {metrics.get('recall', 0):.4f}")
print(f"  F1: {metrics.get('f1', 0):.4f}")
print(f"\nWhitelist-Specific:")
print(f"  Precision: {metrics.get('precision_whitelist', 0):.4f}")
print(f"  Recall: {metrics.get('recall_whitelist', 0):.4f} ⭐ (Target: ≥ 0.95)")
print(f"  F1: {metrics.get('f1_whitelist', 0):.4f}")

print(f"\nTraining Loss: {ckpt.get('train_loss', 0):.4f}")
print(f"Best Recall: {ckpt.get('best_recall', 0):.4f}")
print(f"Best F1: {ckpt.get('best_f1', 0):.4f}")

print("\n" + "="*80)
if metrics.get('recall_whitelist', 0) >= 0.95:
    print("✅ TARGET ACHIEVED - Whitelist Recall ≥ 95%")
else:
    print("⚠️ Target not achieved - Whitelist Recall < 95%")
print("="*80)

