"""
True Validation: Compare Original vs Adversarial-Trained Model

Tests both models on NEW, unseen adversarial examples to prove generalization.

Usage:
    python -m detectors.orchestrator.infrastructure.training.validate_adversarial_model \
        --validation-set data/adversarial_training/code_intent_true_validation.jsonl \
        --original-model models/quantum_cnn_trained/best_model.pt \
        --adversarial-model models/code_intent_adversarial_v1/best_model.pt \
        --output results/adversarial_validation_comparison.json
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple
from collections import defaultdict
import torch

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SimpleTokenizer:
    """Simple character-based tokenizer."""
    
    def __init__(self, vocab_size: int = 10000):
        self.vocab_size = vocab_size
    
    def encode(self, text: str, max_length: int = 512) -> list:
        """Encode text to token IDs."""
        tokens = [ord(c) % self.vocab_size for c in text[:max_length]]
        while len(tokens) < max_length:
            tokens.append(0)
        return tokens[:max_length]


def load_model(model_path: str, vocab_size: int = 10000, device: str = 'cpu') -> torch.nn.Module:
    """Load QuantumInspiredCNN model from checkpoint."""
    try:
        # Try different import paths
        try:
            from llm_firewall.ml import QuantumInspiredCNN
        except ImportError:
            src_path = project_root / "src"
            if str(src_path) not in sys.path:
                sys.path.insert(0, str(src_path))
            from llm_firewall.ml import QuantumInspiredCNN
    except ImportError as e:
        logger.error(f"Could not import QuantumInspiredCNN: {e}")
        raise
    
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    
    # Extract hyperparameters
    if 'hyperparameters' in checkpoint:
        hp = checkpoint['hyperparameters']
        vocab_size = hp.get('vocab_size', vocab_size)
        embedding_dim = hp.get('embedding_dim', 128)
        hidden_dims = hp.get('hidden_dims', [256, 128, 64])
        kernel_sizes = hp.get('kernel_sizes', [3, 5, 7])
        dropout = hp.get('dropout', 0.2)
    else:
        embedding_dim = 128
        hidden_dims = [256, 128, 64]
        kernel_sizes = [3, 5, 7]
        dropout = 0.2
    
    model = QuantumInspiredCNN(
        vocab_size=vocab_size,
        embedding_dim=embedding_dim,
        num_classes=2,
        hidden_dims=hidden_dims,
        kernel_sizes=kernel_sizes,
        dropout=dropout
    )
    
    if 'model_state_dict' in checkpoint:
        model.load_state_dict(checkpoint['model_state_dict'])
    else:
        model.load_state_dict(checkpoint)
    
    model = model.to(device)
    model.eval()
    
    return model


def load_validation_set(jsonl_path: Path) -> Tuple[List[str], List[int]]:
    """Load validation samples and labels."""
    samples = []
    labels = []
    
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                record = json.loads(line)
                samples.append(record['text'])
                labels.append(int(record['label']))
    
    return samples, labels


def evaluate_model(
    model: torch.nn.Module,
    samples: List[str],
    labels: List[int],
    tokenizer: SimpleTokenizer,
    device: str = 'cpu',
    max_length: int = 512
) -> Dict[str, Any]:
    """Evaluate model on samples and return metrics."""
    model.eval()
    
    predictions = []
    correct = 0
    total = len(samples)
    
    malicious_samples = [s for s, l in zip(samples, labels) if l == 1]
    benign_samples = [s for s, l in zip(samples, labels) if l == 0]
    
    with torch.no_grad():
        for text, label in zip(samples, labels):
            # Tokenize
            token_ids = tokenizer.encode(text, max_length=max_length)
            input_tensor = torch.tensor([token_ids], dtype=torch.long).to(device)
            
            # Predict
            output = model(input_tensor)
            _, predicted = torch.max(output, 1)
            pred_label = predicted.item()
            
            predictions.append({
                'text': text,
                'true_label': label,
                'predicted_label': pred_label,
                'confidence': torch.softmax(output, dim=1)[0][pred_label].item()
            })
            
            if pred_label == label:
                correct += 1
    
    # Calculate metrics
    malicious_pred = [p for p in predictions if p['true_label'] == 1]
    benign_pred = [p for p in predictions if p['true_label'] == 0]
    
    # For malicious samples: detection rate (how many were correctly detected as malicious)
    malicious_detected = sum(1 for p in malicious_pred if p['predicted_label'] == 1)
    malicious_total = len(malicious_pred)
    detection_rate = (malicious_detected / malicious_total * 100) if malicious_total > 0 else 0.0
    bypass_rate = 100.0 - detection_rate
    
    # For benign samples: false positive rate (how many were incorrectly flagged as malicious)
    benign_false_positives = sum(1 for p in benign_pred if p['predicted_label'] == 1)
    benign_total = len(benign_pred)
    false_positive_rate = (benign_false_positives / benign_total * 100) if benign_total > 0 else 0.0
    
    # Overall accuracy
    accuracy = (correct / total * 100) if total > 0 else 0.0
    
    return {
        'total_samples': total,
        'malicious_samples': malicious_total,
        'benign_samples': benign_total,
        'accuracy': accuracy,
        'detection_rate': detection_rate,
        'bypass_rate': bypass_rate,
        'false_positive_rate': false_positive_rate,
        'predictions': predictions
    }


def compare_models(
    original_model: torch.nn.Module,
    adversarial_model: torch.nn.Module,
    validation_samples: List[str],
    validation_labels: List[int],
    tokenizer: SimpleTokenizer,
    device: str = 'cpu'
) -> Dict[str, Any]:
    """Compare performance of both models."""
    
    logger.info("\n" + "="*80)
    logger.info("EVALUATING ORIGINAL MODEL")
    logger.info("="*80)
    original_results = evaluate_model(
        original_model, validation_samples, validation_labels, tokenizer, device
    )
    
    logger.info("\n" + "="*80)
    logger.info("EVALUATING ADVERSARIAL-TRAINED MODEL")
    logger.info("="*80)
    adversarial_results = evaluate_model(
        adversarial_model, validation_samples, validation_labels, tokenizer, device
    )
    
    # Calculate improvements
    bypass_reduction = original_results['bypass_rate'] - adversarial_results['bypass_rate']
    fpr_change = adversarial_results['false_positive_rate'] - original_results['false_positive_rate']
    accuracy_improvement = adversarial_results['accuracy'] - original_results['accuracy']
    
    comparison = {
        'original_model': {
            'accuracy': original_results['accuracy'],
            'detection_rate': original_results['detection_rate'],
            'bypass_rate': original_results['bypass_rate'],
            'false_positive_rate': original_results['false_positive_rate'],
        },
        'adversarial_model': {
            'accuracy': adversarial_results['accuracy'],
            'detection_rate': adversarial_results['detection_rate'],
            'bypass_rate': adversarial_results['bypass_rate'],
            'false_positive_rate': adversarial_results['false_positive_rate'],
        },
        'improvement': {
            'bypass_rate_reduction': bypass_reduction,
            'fpr_change': fpr_change,
            'accuracy_improvement': accuracy_improvement,
        },
        'success_criteria': {
            'bypass_rate_reduced': bypass_reduction > 0,
            'bypass_rate_improvement_percent': (bypass_reduction / original_results['bypass_rate'] * 100) if original_results['bypass_rate'] > 0 else 0,
            'fpr_acceptable': abs(fpr_change) < 2.0,  # FPR change < 2% is acceptable
            'significant_improvement': bypass_reduction >= 10.0,  # At least 10% reduction
        }
    }
    
    return comparison, original_results, adversarial_results


def main():
    parser = argparse.ArgumentParser(description="Validate Adversarial-Trained Model")
    parser.add_argument(
        "--validation-set",
        type=str,
        required=True,
        help="Path to true validation set JSONL"
    )
    parser.add_argument(
        "--original-model",
        type=str,
        required=True,
        help="Path to original model checkpoint"
    )
    parser.add_argument(
        "--adversarial-model",
        type=str,
        required=True,
        help="Path to adversarial-trained model checkpoint"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/adversarial_validation_comparison.json",
        help="Output JSON path for results"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device (cpu/cuda)"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("TRUE VALIDATION: MODEL COMPARISON")
    logger.info("="*80)
    logger.info(f"Validation Set: {args.validation_set}")
    logger.info(f"Original Model: {args.original_model}")
    logger.info(f"Adversarial Model: {args.adversarial_model}")
    logger.info(f"Device: {args.device}")
    logger.info("="*80)
    
    # Load validation set
    logger.info("\nLoading validation set...")
    validation_samples, validation_labels = load_validation_set(Path(args.validation_set))
    logger.info(f"Loaded {len(validation_samples)} samples")
    logger.info(f"  - Malicious: {sum(validation_labels)}")
    logger.info(f"  - Benign: {len(validation_labels) - sum(validation_labels)}")
    
    # Load models
    logger.info("\nLoading models...")
    tokenizer = SimpleTokenizer(vocab_size=10000)
    
    logger.info("Loading original model...")
    original_model = load_model(args.original_model, device=args.device)
    
    logger.info("Loading adversarial-trained model...")
    adversarial_model = load_model(args.adversarial_model, device=args.device)
    
    # Compare models
    comparison, original_results, adversarial_results = compare_models(
        original_model,
        adversarial_model,
        validation_samples,
        validation_labels,
        tokenizer,
        args.device
    )
    
    # Print results
    logger.info("\n" + "="*80)
    logger.info("COMPARISON RESULTS")
    logger.info("="*80)
    
    logger.info("\n📊 ORIGINAL MODEL:")
    logger.info(f"  Accuracy: {original_results['accuracy']:.2f}%")
    logger.info(f"  Detection Rate: {original_results['detection_rate']:.2f}%")
    logger.info(f"  Bypass Rate: {original_results['bypass_rate']:.2f}%")
    logger.info(f"  False Positive Rate: {original_results['false_positive_rate']:.2f}%")
    
    logger.info("\n🎯 ADVERSARIAL-TRAINED MODEL:")
    logger.info(f"  Accuracy: {adversarial_results['accuracy']:.2f}%")
    logger.info(f"  Detection Rate: {adversarial_results['detection_rate']:.2f}%")
    logger.info(f"  Bypass Rate: {adversarial_results['bypass_rate']:.2f}%")
    logger.info(f"  False Positive Rate: {adversarial_results['false_positive_rate']:.2f}%")
    
    logger.info("\n📈 IMPROVEMENTS:")
    logger.info(f"  Bypass Rate Reduction: {comparison['improvement']['bypass_rate_reduction']:.2f}%")
    logger.info(f"  FPR Change: {comparison['improvement']['fpr_change']:+.2f}%")
    logger.info(f"  Accuracy Improvement: {comparison['improvement']['accuracy_improvement']:+.2f}%")
    
    logger.info("\n✅ SUCCESS CRITERIA:")
    logger.info(f"  Bypass Rate Reduced: {'✅ YES' if comparison['success_criteria']['bypass_rate_reduced'] else '❌ NO'}")
    logger.info(f"  Improvement: {comparison['success_criteria']['bypass_rate_improvement_percent']:.1f}%")
    logger.info(f"  FPR Acceptable (<2% change): {'✅ YES' if comparison['success_criteria']['fpr_acceptable'] else '❌ NO'}")
    logger.info(f"  Significant Improvement (≥10%): {'✅ YES' if comparison['success_criteria']['significant_improvement'] else '⚠️ PARTIAL'}")
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    full_results = {
        'comparison': comparison,
        'original_detailed': {
            'metrics': {k: v for k, v in original_results.items() if k != 'predictions'},
            'sample_count': len(original_results['predictions'])
        },
        'adversarial_detailed': {
            'metrics': {k: v for k, v in adversarial_results.items() if k != 'predictions'},
            'sample_count': len(adversarial_results['predictions'])
        }
    }
    
    with open(output_path, 'w') as f:
        json.dump(full_results, f, indent=2)
    
    logger.info(f"\n💾 Results saved to: {output_path}")
    logger.info("="*80)
    
    # Final verdict
    if comparison['success_criteria']['significant_improvement'] and comparison['success_criteria']['fpr_acceptable']:
        logger.info("\n🎉 SUCCESS: Adversarial training shows significant improvement!")
        logger.info("   Model is ready for production deployment consideration.")
    elif comparison['success_criteria']['bypass_rate_reduced']:
        logger.info("\n⚠️ PARTIAL SUCCESS: Improvement detected, but may need more training.")
        logger.info("   Consider: More diverse adversarial examples, longer training, different mix ratio.")
    else:
        logger.info("\n❌ NEEDS WORK: No significant improvement detected.")
        logger.info("   Consider: More training data, different transformations, longer training.")


if __name__ == "__main__":
    main()

