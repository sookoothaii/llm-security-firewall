"""
Monitor V3 Training Progress

Zeigt den aktuellen Training-Status an.
"""

import sys
from pathlib import Path
import json
import time

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

def monitor_training():
    """Monitor training progress."""
    output_dir = Path("models/v3_whitelist_learner")
    
    print("="*80)
    print("V3 TRAINING MONITOR")
    print("="*80)
    
    # Check for checkpoints
    checkpoints = sorted(output_dir.glob("best_model_epoch_*.pt"))
    
    if checkpoints:
        print(f"\n✓ Found {len(checkpoints)} checkpoint(s):")
        for ckpt in checkpoints:
            print(f"  - {ckpt.name}")
        
        # Load latest checkpoint info
        latest = checkpoints[-1]
        print(f"\nLatest checkpoint: {latest.name}")
        
        try:
            import torch
            checkpoint = torch.load(latest, map_location='cpu', weights_only=False)
            
            print(f"  Epoch: {checkpoint.get('epoch', 'unknown')}")
            print(f"  Validation Accuracy: {checkpoint.get('val_accuracy', 0):.4f}")
            print(f"  Benign Accuracy: {checkpoint.get('val_benign_accuracy', 0):.4f}")
            print(f"  Malicious Accuracy: {checkpoint.get('val_malicious_accuracy', 0):.4f}")
            
            if 'train_losses' in checkpoint:
                losses = checkpoint['train_losses']
                print(f"\n  Training Losses:")
                print(f"    Classification: {losses.get('class_loss', 0):.4f}")
                print(f"    Pattern: {losses.get('pattern_loss', 0):.4f}")
                print(f"    Imitation: {losses.get('imitation_loss', 0):.4f}")
        except Exception as e:
            print(f"  Could not load checkpoint info: {e}")
    else:
        print("\n⚠️ No checkpoints found yet. Training may still be starting...")
    
    # Check for pattern embeddings
    pattern_embeddings = output_dir / "pattern_embeddings.pt"
    if pattern_embeddings.exists():
        print(f"\n✓ Pattern embeddings found: {pattern_embeddings.name}")
        try:
            import torch
            checkpoint = torch.load(pattern_embeddings, map_location='cpu', weights_only=False)
            print(f"  Epoch: {checkpoint.get('epoch', 'unknown')}")
            print(f"  Loss: {checkpoint.get('loss', 0):.4f}")
        except:
            pass
    
    # Check dataset stats
    stats_path = Path("data/adversarial_training/v3_whitelist_learner/statistics.json")
    if stats_path.exists():
        print(f"\n✓ Dataset statistics:")
        with open(stats_path, 'r') as f:
            stats = json.load(f)
            print(f"  Train: {stats['train']['malicious']} malicious, {stats['train']['benign_total']} benign")
            print(f"  Validation: {stats['validation']['malicious']} malicious, {stats['validation']['benign_total']} benign")
    
    print("\n" + "="*80)
    print("Training Status:")
    print("  - Check for new checkpoints: models/v3_whitelist_learner/best_model_epoch_*.pt")
    print("  - Training runs in background")
    print("  - Run this script again to see latest progress")
    print("="*80)

if __name__ == "__main__":
    monitor_training()

