"""
Quick Test für V3 WhitelistAwareCodeIntentModel

Testet die Model-Architektur ohne Training.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

import torch
from detectors.orchestrator.infrastructure.training.models import create_model

def test_model():
    """Test V3 Model Architecture."""
    print("="*80)
    print("V3 WHITELIST-AWARE MODEL TEST")
    print("="*80)
    
    # Create model
    print("\nCreating model...")
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = create_model(
        base_model_name="microsoft/codebert-base",
        num_patterns=4,
        pattern_dim=768,
        hidden_dim=256,
        dropout=0.2,
        freeze_encoder=False,
        device=device
    )
    
    print(f"✓ Model created on {device}")
    
    # Test texts
    test_texts = [
        "What is SQL?",
        "How do I use Docker?",
        "rm -rf /",
        "Show me best practices for REST API"
    ]
    
    print(f"\nTesting with {len(test_texts)} samples...")
    
    # Forward pass
    model.eval()
    with torch.no_grad():
        output = model.forward(
            texts=test_texts,
            return_patterns=True,
            return_similarities=True
        )
    
    print("\n✓ Forward pass successful")
    print(f"  Standard logits shape: {output['logits'].shape}")
    print(f"  Whitelist logits shape: {output['whitelist_logits'].shape}")
    print(f"  Pattern logits shape: {output['pattern_logits'].shape}")
    print(f"  Similarities shape: {output['similarities'].shape}")
    
    # Predictions
    print("\nPredictions:")
    predictions = model.predict(test_texts, use_whitelist=True)
    
    for i, (text, pred) in enumerate(zip(test_texts, predictions)):
        print(f"\n[{i+1}] {text[:50]}...")
        print(f"     Malicious: {pred['is_malicious']} (prob: {pred['malicious_probability']:.3f})")
        print(f"     Best Pattern: {pred['best_pattern']} (conf: {pred['pattern_confidence']:.3f})")
    
    # Pattern embeddings
    print("\n✓ Pattern Embeddings:")
    pattern_embeddings = model.get_pattern_embeddings()
    for name, embedding in pattern_embeddings.items():
        print(f"  {name}: shape {embedding.shape}, norm {embedding.norm().item():.3f}")
    
    print("\n" + "="*80)
    print("✅ ALL TESTS PASSED!")
    print("="*80)
    print("\nModel is ready for training!")

if __name__ == "__main__":
    test_model()

