"""
Save Champion Model (Epoch 2) - Best Performing Model
=====================================================

Loads the best model checkpoint (Epoch 2) and saves it as the champion model
for production use.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import torch
import json
import sys
from pathlib import Path
import argparse

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))
sys.path.insert(0, str(project_root))

from llm_firewall.ml.quantum_inspired_architectures import QuantumInspiredCNN
from detectors.code_intent_service.quantum_model_loader import SimpleTokenizer


def load_champion_model(
    checkpoint_path: str,
    output_path: str = "models/quantum_cnn_champion.pt",
    vocab_size: int = 10000,
    embedding_dim: int = 128,
    hidden_dims: list = [256, 128, 64],
    kernel_sizes: list = [3, 5, 7],
    dropout: float = 0.2
):
    """
    Load best model checkpoint and save as champion model.
    
    Args:
        checkpoint_path: Path to best_model.pt checkpoint
        output_path: Path to save champion model
        vocab_size: Vocabulary size (must match training)
        embedding_dim: Embedding dimension (must match training)
        hidden_dims: Hidden dimensions (must match training)
        kernel_sizes: Kernel sizes (must match training)
        dropout: Dropout rate (must match training)
    """
    print("=" * 80)
    print("CHAMPION MODEL EXTRACTION")
    print("=" * 80)
    print()
    
    # Load checkpoint
    print(f"Loading checkpoint: {checkpoint_path}")
    checkpoint = torch.load(checkpoint_path, map_location='cpu')
    
    # Extract hyperparameters from checkpoint if available
    if 'hyperparameters' in checkpoint:
        hparams = checkpoint['hyperparameters']
        vocab_size = hparams.get('vocab_size', vocab_size)
        embedding_dim = hparams.get('embedding_dim', embedding_dim)
        hidden_dims = hparams.get('hidden_dims', hidden_dims)
        kernel_sizes = hparams.get('kernel_sizes', kernel_sizes)
        dropout = hparams.get('dropout', dropout)
        print(f"  Using hyperparameters from checkpoint:")
        print(f"    vocab_size: {vocab_size}")
        print(f"    embedding_dim: {embedding_dim}")
        print(f"    hidden_dims: {hidden_dims}")
        print(f"    kernel_sizes: {kernel_sizes}")
        print(f"    dropout: {dropout}")
    else:
        print(f"  Using default hyperparameters")
    
    # Extract metrics
    epoch = checkpoint.get('epoch', 'unknown')
    val_loss = checkpoint.get('val_loss', 'unknown')
    val_fnr = checkpoint.get('val_fnr', 'unknown')
    
    print(f"  Epoch: {epoch}")
    print(f"  Validation Loss: {val_loss}")
    print(f"  Validation FNR: {val_fnr}")
    print()
    
    # Create model with same architecture
    print("Creating model architecture...")
    model = QuantumInspiredCNN(
        vocab_size=vocab_size,
        embedding_dim=embedding_dim,
        num_classes=2,
        hidden_dims=hidden_dims,
        kernel_sizes=kernel_sizes,
        dropout=dropout
    )
    
    # Load state dict
    print("Loading model weights...")
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    
    # Save champion model
    print(f"Saving champion model: {output_path}")
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    torch.save(model.state_dict(), output_path)
    print(f"  ✓ Champion model saved")
    print()
    
    # Save metadata
    metadata_path = output_path.replace('.pt', '_metadata.json')
    metadata = {
        'epoch': epoch,
        'val_loss': float(val_loss) if val_loss != 'unknown' else None,
        'val_fnr': float(val_fnr) if val_fnr != 'unknown' else None,
        'hyperparameters': {
            'vocab_size': vocab_size,
            'embedding_dim': embedding_dim,
            'hidden_dims': hidden_dims,
            'kernel_sizes': kernel_sizes,
            'dropout': dropout
        },
        'model_parameters': sum(p.numel() for p in model.parameters()),
        'source_checkpoint': checkpoint_path
    }
    
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"  ✓ Metadata saved: {metadata_path}")
    print()
    
    # Verify model can be loaded
    print("Verifying model can be loaded...")
    test_model = QuantumInspiredCNN(
        vocab_size=vocab_size,
        embedding_dim=embedding_dim,
        num_classes=2,
        hidden_dims=hidden_dims,
        kernel_sizes=kernel_sizes,
        dropout=dropout
    )
    test_model.load_state_dict(torch.load(output_path, map_location='cpu'))
    print("  ✓ Model verification successful")
    print()
    
    print("=" * 80)
    print("CHAMPION MODEL SAVED SUCCESSFULLY")
    print("=" * 80)
    print()
    print(f"Champion Model: {output_path}")
    print(f"Metadata: {metadata_path}")
    print()
    print("To use in service, update quantum_model_loader.py:")
    print(f"  model_path = '{output_path}'")
    
    return output_path, metadata


def main():
    parser = argparse.ArgumentParser(description="Extract and save champion model from checkpoint")
    parser.add_argument(
        "--checkpoint",
        type=str,
        default="models/quantum_cnn_trained/best_model.pt",
        help="Path to best_model.pt checkpoint"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="models/quantum_cnn_champion.pt",
        help="Output path for champion model"
    )
    parser.add_argument(
        "--vocab_size",
        type=int,
        default=10000,
        help="Vocabulary size (overridden by checkpoint if available)"
    )
    parser.add_argument(
        "--embedding_dim",
        type=int,
        default=128,
        help="Embedding dimension (overridden by checkpoint if available)"
    )
    parser.add_argument(
        "--hidden_dims",
        type=int,
        nargs='+',
        default=[256, 128, 64],
        help="Hidden dimensions (overridden by checkpoint if available)"
    )
    parser.add_argument(
        "--kernel_sizes",
        type=int,
        nargs='+',
        default=[3, 5, 7],
        help="Kernel sizes (overridden by checkpoint if available)"
    )
    parser.add_argument(
        "--dropout",
        type=float,
        default=0.2,
        help="Dropout rate (overridden by checkpoint if available)"
    )
    
    args = parser.parse_args()
    
    # Check if checkpoint exists
    if not Path(args.checkpoint).exists():
        print(f"ERROR: Checkpoint not found: {args.checkpoint}")
        print("Please train the model first or specify correct checkpoint path.")
        sys.exit(1)
    
    # Load and save champion model
    load_champion_model(
        checkpoint_path=args.checkpoint,
        output_path=args.output,
        vocab_size=args.vocab_size,
        embedding_dim=args.embedding_dim,
        hidden_dims=args.hidden_dims,
        kernel_sizes=args.kernel_sizes,
        dropout=args.dropout
    )


if __name__ == "__main__":
    main()
