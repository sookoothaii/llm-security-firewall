"""
V2.1 Hotfix Validation

Validiert den V2.1 Hotfix gegen V1 und V2 auf dem True Validation Set.

Usage:
    python -m detectors.orchestrator.infrastructure.training.validate_v21_hotfix \
        --validation-set data/adversarial_training/code_intent_true_validation.jsonl \
        --v1-model models/code_intent_adversarial_v1/best_model.pt \
        --v2-model models/code_intent_adversarial_v2/best_model.pt \
        --output results/v21_hotfix_validation.json
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def load_validation_set(jsonl_path: Path) -> tuple[List[str], List[int]]:
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


def evaluate_detector(
    detector,
    samples: List[str],
    labels: List[int]
) -> Dict[str, Any]:
    """
    Evaluiere Detector auf Samples.
    
    Returns:
        Dictionary mit Metriken
    """
    predictions = []
    correct = 0
    total = len(samples)
    
    for text, label in zip(samples, labels):
        result = detector.predict(text)
        pred = result['prediction']
        predictions.append({
            'text': text,
            'true_label': label,
            'predicted_label': pred,
            'score': result['score'],
            'confidence': result['confidence'],
            'method': result['method'],
            'v1_score': result.get('v1_score'),
            'v2_score': result.get('v2_score'),
        })
        
        if pred == label:
            correct += 1
    
    # Calculate metrics
    malicious_pred = [p for p in predictions if p['true_label'] == 1]
    benign_pred = [p for p in predictions if p['true_label'] == 0]
    
    # Detection Rate (TPR)
    malicious_detected = sum(1 for p in malicious_pred if p['predicted_label'] == 1)
    malicious_total = len(malicious_pred)
    detection_rate = (malicious_detected / malicious_total * 100) if malicious_total > 0 else 0.0
    bypass_rate = 100.0 - detection_rate
    
    # False Positive Rate (FPR)
    benign_false_positives = sum(1 for p in benign_pred if p['predicted_label'] == 1)
    benign_total = len(benign_pred)
    false_positive_rate = (benign_false_positives / benign_total * 100) if benign_total > 0 else 0.0
    
    # Overall accuracy
    accuracy = (correct / total * 100) if total > 0 else 0.0
    
    # Method statistics
    method_stats = defaultdict(int)
    for p in predictions:
        method_stats[p['method']] += 1
    
    return {
        'total_samples': total,
        'malicious_samples': malicious_total,
        'benign_samples': benign_total,
        'accuracy': accuracy,
        'detection_rate': detection_rate,
        'bypass_rate': bypass_rate,
        'false_positive_rate': false_positive_rate,
        'method_statistics': dict(method_stats),
        'predictions': predictions
    }


def main():
    parser = argparse.ArgumentParser(description="Validate V2.1 Hotfix")
    parser.add_argument(
        "--validation-set",
        type=str,
        required=True,
        help="Path to true validation set JSONL"
    )
    parser.add_argument(
        "--v1-model",
        type=str,
        required=True,
        help="Path to V1 model checkpoint"
    )
    parser.add_argument(
        "--v2-model",
        type=str,
        required=True,
        help="Path to V2 model checkpoint"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/v21_hotfix_validation.json",
        help="Output JSON path for results"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if __import__('torch').cuda.is_available() else 'cpu',
        help="Device (cpu/cuda)"
    )
    parser.add_argument(
        "--v2-threshold",
        type=float,
        default=0.95,
        help="V2 threshold (default: 0.95)"
    )
    parser.add_argument(
        "--v1-fallback-threshold",
        type=float,
        default=0.7,
        help="V1 fallback threshold (default: 0.7)"
    )
    parser.add_argument(
        "--disable-whitelist",
        action="store_true",
        help="Disable technical questions whitelist"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("V2.1 HOTFIX VALIDATION")
    logger.info("="*80)
    logger.info(f"Validation Set: {args.validation_set}")
    logger.info(f"V1 Model: {args.v1_model}")
    logger.info(f"V2 Model: {args.v2_model}")
    logger.info(f"Device: {args.device}")
    logger.info(f"V2 Threshold: {args.v2_threshold}")
    logger.info(f"V1 Fallback Threshold: {args.v1_fallback_threshold}")
    logger.info(f"Whitelist enabled: {not args.disable_whitelist}")
    logger.info("="*80)
    
    # Load validation set
    logger.info("\nLoading validation set...")
    validation_samples, validation_labels = load_validation_set(Path(args.validation_set))
    logger.info(f"Loaded {len(validation_samples)} samples")
    logger.info(f"  - Malicious: {sum(validation_labels)}")
    logger.info(f"  - Benign: {len(validation_labels) - sum(validation_labels)}")
    
    # Load V2.1 Hotfix Detector
    logger.info("\nLoading V2.1 Hotfix Detector...")
    from detectors.orchestrator.domain.hotfix.v2_1_hotfix_detector import load_v21_hotfix_detector
    
    detector = load_v21_hotfix_detector(
        v1_model_path=args.v1_model,
        v2_model_path=args.v2_model,
        device=args.device,
        v2_threshold=args.v2_threshold,
        v1_fallback_threshold=args.v1_fallback_threshold,
        enable_whitelist=not args.disable_whitelist
    )
    
    # Evaluate
    logger.info("\nEvaluating V2.1 Hotfix...")
    results = evaluate_detector(detector, validation_samples, validation_labels)
    
    # Print results
    logger.info("\n" + "="*80)
    logger.info("V2.1 HOTFIX RESULTS")
    logger.info("="*80)
    logger.info(f"Accuracy: {results['accuracy']:.2f}%")
    logger.info(f"Detection Rate: {results['detection_rate']:.2f}%")
    logger.info(f"Bypass Rate: {results['bypass_rate']:.2f}%")
    logger.info(f"False Positive Rate: {results['false_positive_rate']:.2f}%")
    
    logger.info(f"\n[Method Statistics]")
    for method, count in results['method_statistics'].items():
        percentage = (count / results['total_samples'] * 100)
        logger.info(f"  {method}: {count} ({percentage:.1f}%)")
    
    # Comparison with expected V1/V2 baselines
    logger.info("\n[Expected Baselines]")
    logger.info("  V1: FPR 53.40%, Bypass 5.49%")
    logger.info("  V2: FPR 95.81%, Bypass 0.00%")
    logger.info(f"\n[V2.1 Hotfix]")
    logger.info(f"  FPR: {results['false_positive_rate']:.2f}% (Ziel: < 60%)")
    logger.info(f"  Bypass: {results['bypass_rate']:.2f}% (Ziel: < 5%)")
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Remove predictions from saved results (too large)
    results_to_save = {
        'configuration': {
            'v2_threshold': args.v2_threshold,
            'v1_fallback_threshold': args.v1_fallback_threshold,
            'whitelist_enabled': not args.disable_whitelist,
        },
        'metrics': {
            k: v for k, v in results.items() if k != 'predictions'
        },
        'sample_count': len(results['predictions'])
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results_to_save, f, indent=2, ensure_ascii=False)
    
    logger.info(f"\n💾 Results saved to: {output_path}")
    logger.info("="*80)
    
    # Final verdict
    fpr_improvement = results['false_positive_rate'] < 60.0
    bypass_acceptable = results['bypass_rate'] < 5.0
    
    if fpr_improvement and bypass_acceptable:
        logger.info("\n✅ SUCCESS: V2.1 Hotfix meets targets!")
        logger.info("   Ready for production deployment consideration.")
    elif fpr_improvement:
        logger.info("\n⚠️ PARTIAL SUCCESS: FPR improved, but bypass rate needs attention.")
        logger.info("   Consider adjusting thresholds or whitelist.")
    else:
        logger.info("\n❌ NEEDS WORK: FPR still too high.")
        logger.info("   Consider: Higher V2 threshold, more whitelist patterns, or V3 training.")


if __name__ == "__main__":
    main()

