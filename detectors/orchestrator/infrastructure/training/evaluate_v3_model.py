"""
Evaluate V3 Whitelist-Learner Model

Vergleicht V3 mit V2.1 Hotfix auf dem Validation Set.
"""

import sys
import json
import logging
from pathlib import Path
from typing import List, Dict, Any
import torch
import numpy as np

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.infrastructure.training.models import create_model

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_validation_set(jsonl_path: Path) -> List[Dict[str, Any]]:
    """Load validation samples."""
    samples = []
    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                samples.append(json.loads(line))
    return samples


def evaluate_v3_model(
    model_path: Path,
    validation_path: Path,
    device: str = 'cuda'
) -> Dict[str, Any]:
    """Evaluate V3 model."""
    logger.info("Loading V3 model...")
    
    # Load model
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    model = create_model(
        base_model_name="microsoft/codebert-base",
        num_patterns=4,
        pattern_dim=768,
        hidden_dim=256,
        dropout=0.2,
        freeze_encoder=False,
        device=device
    )
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    
    # Load validation set
    logger.info("Loading validation set...")
    validation_samples = load_validation_set(validation_path)
    
    # Evaluate
    logger.info("Evaluating...")
    predictions = []
    correct = 0
    total = 0
    benign_correct = 0
    benign_total = 0
    malicious_correct = 0
    malicious_total = 0
    whitelist_correct = 0
    whitelist_total = 0
    
    with torch.no_grad():
        for sample in validation_samples:
            text = sample['text']
            true_label = sample['label']
            is_whitelist = sample.get('pattern') is not None
            
            # Predict
            pred = model.predict([text], use_whitelist=True, threshold=0.5)[0]
            pred_label = 1 if pred['is_malicious'] else 0
            
            # Statistics
            total += 1
            if pred_label == true_label:
                correct += 1
            
            if true_label == 0:  # benign
                benign_total += 1
                if pred_label == 0:
                    benign_correct += 1
                if is_whitelist:
                    whitelist_total += 1
                    if pred_label == 0:
                        whitelist_correct += 1
            else:  # malicious
                malicious_total += 1
                if pred_label == 1:
                    malicious_correct += 1
            
            predictions.append({
                'text': text,
                'true_label': true_label,
                'pred_label': pred_label,
                'malicious_probability': pred['malicious_probability'],
                'best_pattern': pred['best_pattern'],
                'pattern_confidence': pred['pattern_confidence'],
                'is_whitelist': is_whitelist
            })
    
    # Calculate metrics
    accuracy = correct / total if total > 0 else 0.0
    benign_accuracy = benign_correct / benign_total if benign_total > 0 else 0.0
    malicious_accuracy = malicious_correct / malicious_total if malicious_total > 0 else 0.0
    whitelist_recall = whitelist_correct / whitelist_total if whitelist_total > 0 else 0.0
    
    # FPR = False Positives / Total Benign
    false_positives = benign_total - benign_correct
    fpr = false_positives / benign_total if benign_total > 0 else 0.0
    
    # Bypass Rate = False Negatives / Total Malicious
    false_negatives = malicious_total - malicious_correct
    bypass_rate = false_negatives / malicious_total if malicious_total > 0 else 0.0
    
    return {
        'accuracy': accuracy,
        'benign_accuracy': benign_accuracy,
        'malicious_accuracy': malicious_accuracy,
        'whitelist_recall': whitelist_recall,
        'fpr': fpr,
        'bypass_rate': bypass_rate,
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'total_samples': total,
        'benign_samples': benign_total,
        'malicious_samples': malicious_total,
        'whitelist_samples': whitelist_total,
        'predictions': predictions,
        'checkpoint_info': {
            'epoch': checkpoint.get('epoch', 'unknown'),
            'val_accuracy': checkpoint.get('val_accuracy', 0)
        }
    }


def print_evaluation_report(results: Dict[str, Any]):
    """Print evaluation report."""
    print("="*80)
    print("V3 WHITELIST-LEARNER EVALUATION")
    print("="*80)
    
    print(f"\nModel Info:")
    print(f"  Epoch: {results['checkpoint_info']['epoch']}")
    print(f"  Validation Accuracy (during training): {results['checkpoint_info']['val_accuracy']:.4f}")
    
    print(f"\nOverall Metrics:")
    print(f"  Accuracy: {results['accuracy']:.4f} ({results['accuracy']*100:.2f}%)")
    print(f"  Benign Accuracy: {results['benign_accuracy']:.4f} ({results['benign_accuracy']*100:.2f}%)")
    print(f"  Malicious Accuracy: {results['malicious_accuracy']:.4f} ({results['malicious_accuracy']*100:.2f}%)")
    
    print(f"\nWhitelist Metrics:")
    print(f"  Whitelist Recall: {results['whitelist_recall']:.4f} ({results['whitelist_recall']*100:.2f}%)")
    print(f"  Whitelist Samples: {results['whitelist_samples']}")
    
    print(f"\nSecurity Metrics:")
    print(f"  False Positive Rate (FPR): {results['fpr']:.4f} ({results['fpr']*100:.2f}%)")
    print(f"  Bypass Rate: {results['bypass_rate']:.4f} ({results['bypass_rate']*100:.2f}%)")
    print(f"  False Positives: {results['false_positives']}")
    print(f"  False Negatives: {results['false_negatives']}")
    
    print(f"\nDataset:")
    print(f"  Total Samples: {results['total_samples']}")
    print(f"  Benign: {results['benign_samples']}")
    print(f"  Malicious: {results['malicious_samples']}")
    
    # Acceptance Criteria
    print(f"\n" + "="*80)
    print("ACCEPTANCE CRITERIA")
    print("="*80)
    
    criteria = {
        'Whitelist Recall ≥ 95%': results['whitelist_recall'] >= 0.95,
        'FPR ≤ 5%': results['fpr'] <= 0.05,
        'Bypass Rate = 0%': results['bypass_rate'] == 0.0
    }
    
    for criterion, passed in criteria.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}: {criterion}")
    
    all_passed = all(criteria.values())
    print(f"\n{'='*80}")
    if all_passed:
        print("✅ ALL CRITERIA MET - V3 IS PRODUCTION READY!")
    else:
        print("⚠️ SOME CRITERIA NOT MET - NEEDS IMPROVEMENT")
    print("="*80)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Evaluate V3 Model")
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to V3 model checkpoint"
    )
    parser.add_argument(
        "--validation",
        type=str,
        required=True,
        help="Path to validation set (JSONL)"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output JSON path for detailed results"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device"
    )
    
    args = parser.parse_args()
    
    # Evaluate
    results = evaluate_v3_model(
        model_path=Path(args.model),
        validation_path=Path(args.validation),
        device=args.device
    )
    
    # Print report
    print_evaluation_report(results)
    
    # Save results
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Remove predictions for smaller file
        results_to_save = {k: v for k, v in results.items() if k != 'predictions'}
        results_to_save['num_predictions'] = len(results['predictions'])
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results_to_save, f, indent=2, ensure_ascii=False)
        
        logger.info(f"\n💾 Detailed results saved to: {output_path}")


if __name__ == "__main__":
    main()

