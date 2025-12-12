"""
Validate Pattern Embeddings - Test Similarity Scores

Testet die trainierten Pattern Embeddings auf Similarity-Scores.
"""

import sys
from pathlib import Path
import torch

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.infrastructure.training.models import create_model

def validate_patterns():
    """Validate pattern embeddings."""
    print("="*80)
    print("PATTERN EMBEDDINGS VALIDATION")
    print("="*80)
    
    # Load model
    print("\nLoading model...")
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = create_model(
        base_model_name="microsoft/codebert-base",
        num_patterns=4,
        pattern_dim=768,
        hidden_dim=256,
        dropout=0.2,
        freeze_encoder=True,
        device=device
    )
    
    # Load trained pattern embeddings
    checkpoint_path = Path("models/v3_whitelist_learner/pattern_embeddings.pt")
    if checkpoint_path.exists():
        print(f"\nLoading pattern embeddings from: {checkpoint_path}")
        checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
        pattern_embeddings = checkpoint['pattern_embeddings']
        
        # Update model with trained embeddings
        for name, embedding in pattern_embeddings.items():
            model.whitelist_patterns[name].data = embedding.to(device)
        
        print(f"✓ Pattern embeddings loaded (Epoch {checkpoint.get('epoch', 'unknown')}, Loss: {checkpoint.get('loss', 'unknown'):.4f})")
    else:
        print(f"⚠️ Checkpoint not found: {checkpoint_path}")
        print("Using random initialized embeddings")
    
    # Test texts with expected patterns
    test_cases = [
        ("What is SQL?", "technical_question"),
        ("How do I use Docker?", "technical_question"),
        ("Show me best practices for REST API", "best_practice"),
        ("Explain the concept of recursion", "explanation"),
        ("What are the benefits of using Docker?", "educational"),
        ("rm -rf /", None),  # Should NOT match any pattern
        ("python -c 'import os; os.system(\"rm -rf /\")'", None),
    ]
    
    print("\n" + "="*80)
    print("TESTING PATTERN SIMILARITIES")
    print("="*80)
    
    model.eval()
    with torch.no_grad():
        for text, expected_pattern in test_cases:
            output = model.forward(
                texts=[text],
                return_patterns=False,
                return_similarities=True
            )
            
            similarities = output['pattern_similarities']
            
            # Get best matching pattern
            best_pattern = max(similarities.items(), key=lambda x: x[1].item())
            best_score = best_pattern[1].item()
            
            print(f"\nText: {text[:60]}...")
            print(f"  Expected Pattern: {expected_pattern or 'None (malicious)'}")
            print(f"  Best Match: {best_pattern[0]} (similarity: {best_score:.3f})")
            
            # Show all similarities
            print("  All Patterns:")
            for pattern_name, sim_tensor in sorted(similarities.items()):
                sim = sim_tensor.item()
                marker = "✓" if pattern_name == expected_pattern else " "
                print(f"    {marker} {pattern_name}: {sim:.3f}")
            
            # Validation
            if expected_pattern:
                if best_pattern[0] == expected_pattern and best_score > 0.5:
                    print(f"  ✅ CORRECT (similarity > 0.5)")
                elif best_score > 0.5:
                    print(f"  ⚠️ WRONG PATTERN (but similarity > 0.5)")
                else:
                    print(f"  ❌ LOW SIMILARITY (similarity < 0.5)")
            else:
                if best_score < 0.3:
                    print(f"  ✅ CORRECT (malicious, low similarity)")
                else:
                    print(f"  ⚠️ HIGH SIMILARITY (might be false positive)")
    
    print("\n" + "="*80)
    print("VALIDATION COMPLETE")
    print("="*80)
    print("\nTarget: Similarity > 0.7 for correct patterns")
    print("Current: Pattern embeddings are learning but need more training")

if __name__ == "__main__":
    validate_patterns()

