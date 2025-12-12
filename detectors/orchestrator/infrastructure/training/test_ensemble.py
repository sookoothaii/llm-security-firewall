"""
Test Ensemble Detector

Validates the ensemble approach on true validation set.

Usage:
    python -m detectors.orchestrator.infrastructure.training.test_ensemble \
        --v1-model models/code_intent_adversarial_v1/best_model.pt \
        --v2-model models/code_intent_adversarial_v2/best_model.pt \
        --validation-set data/adversarial_training/code_intent_true_validation.jsonl \
        --v2-weights 0.5 0.6 0.7 0.8 0.9 \
        --output results/ensemble_validation.json
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

logging.basicConfig(level=logging.INFO)
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


def evaluate_ensemble(
    ensemble,
    samples: List[str],
    labels: List[int],
    decision_threshold: float = 0.5
) -> Dict[str, Any]:
    """Evaluate ensemble on samples."""
    correct = 0
    total = len(samples)
    
    malicious_samples = [s for s, l in zip(samples, labels) if l == 1]
    benign_samples = [s for s, l in zip(samples, labels) if l == 0]
    
    malicious_pred = []
    benign_pred = []
    
    for text, label in zip(samples, labels):
        score, conf, metadata = ensemble.predict(text)
        is_malicious = score >= decision_threshold
        
        if is_malicious == bool(label):
            correct += 1
        
        if label == 1:
            malicious_pred.append({
                'text': text,
                'score': score,
                'confidence': conf,
                'predicted': is_malicious,
                'metadata': metadata
            })
        else:
            benign_pred.append({
                'text': text,
                'score': score,
                'confidence': conf,
                'predicted': is_malicious,
                'metadata': metadata
            })
    
    # Calculate metrics
    malicious_detected = sum(1 for p in malicious_pred if p['predicted'])
    malicious_total = len(malicious_pred)
    detection_rate = (malicious_detected / malicious_total * 100) if malicious_total > 0 else 0.0
    bypass_rate = 100.0 - detection_rate
    
    benign_false_positives = sum(1 for p in benign_pred if p['predicted'])
    benign_total = len(benign_pred)
    false_positive_rate = (benign_false_positives / benign_total * 100) if benign_total > 0 else 0.0
    
    accuracy = (correct / total * 100) if total > 0 else 0.0
    
    # Calculate average disagreement
    disagreements = [abs(p['metadata']['v1_score'] - p['metadata']['v2_score']) 
                     for p in malicious_pred + benign_pred]
    avg_disagreement = sum(disagreements) / len(disagreements) if disagreements else 0.0
    
    return {
        'total_samples': total,
        'malicious_samples': malicious_total,
        'benign_samples': benign_total,
        'accuracy': accuracy,
        'detection_rate': detection_rate,
        'bypass_rate': bypass_rate,
        'false_positive_rate': false_positive_rate,
        'avg_disagreement': avg_disagreement,
        'decision_threshold': decision_threshold
    }


def main():
    parser = argparse.ArgumentParser(description="Test Ensemble Detector")
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
        "--validation-set",
        type=str,
        required=True,
        help="Path to validation set JSONL"
    )
    parser.add_argument(
        "--v2-weights",
        type=float,
        nargs='+',
        default=[0.5, 0.6, 0.7, 0.8, 0.9],
        help="V2 weights to test"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/ensemble_validation.json",
        help="Output JSON path"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if __import__('torch').cuda.is_available() else 'cpu',
        help="Device (cpu/cuda)"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("ENSEMBLE DETECTOR VALIDATION")
    logger.info("="*80)
    
    # Load models
    from detectors.orchestrator.domain.ensemble import (
        load_ensemble_models,
        WeightedEnsembleDetector,
        AdaptiveEnsembleDetector
    )
    
    logger.info("\nLoading models...")
    v1_wrapper, v2_wrapper = load_ensemble_models(
        args.v1_model,
        args.v2_model,
        args.device
    )
    
    # Load validation set
    logger.info("\nLoading validation set...")
    samples, labels = load_validation_set(Path(args.validation_set))
    logger.info(f"Loaded {len(samples)} samples ({sum(labels)} malicious, {len(labels)-sum(labels)} benign)")
    
    # Test different weights
    logger.info("\n" + "="*80)
    logger.info("TESTING DIFFERENT V2 WEIGHTS")
    logger.info("="*80)
    
    results = {}
    
    for v2_weight in args.v2_weights:
        logger.info(f"\nTesting V2 weight: {v2_weight}")
        logger.info("-" * 80)
        
        ensemble = WeightedEnsembleDetector(
            v1_wrapper,
            v2_wrapper,
            v2_weight=v2_weight
        )
        
        metrics = evaluate_ensemble(ensemble, samples, labels)
        results[f"v2_weight_{v2_weight}"] = {
            'v2_weight': v2_weight,
            'metrics': metrics
        }
        
        logger.info(f"  Accuracy: {metrics['accuracy']:.2f}%")
        logger.info(f"  Detection Rate: {metrics['detection_rate']:.2f}%")
        logger.info(f"  Bypass Rate: {metrics['bypass_rate']:.2f}%")
        logger.info(f"  False Positive Rate: {metrics['false_positive_rate']:.2f}%")
        logger.info(f"  Avg Disagreement: {metrics['avg_disagreement']:.4f}")
    
    # Find best weight
    best_weight = None
    best_score = -1
    best_metrics = None
    
    for weight_str, data in results.items():
        metrics = data['metrics']
        # Score: low bypass rate + low FPR (weighted)
        score = (100 - metrics['bypass_rate']) * 0.6 + (100 - metrics['false_positive_rate']) * 0.4
        if score > best_score:
            best_score = score
            best_weight = data['v2_weight']
            best_metrics = metrics
    
    logger.info("\n" + "="*80)
    logger.info("RESULTS SUMMARY")
    logger.info("="*80)
    logger.info(f"\n📊 Best V2 Weight: {best_weight}")
    logger.info(f"   Accuracy: {best_metrics['accuracy']:.2f}%")
    logger.info(f"   Detection Rate: {best_metrics['detection_rate']:.2f}%")
    logger.info(f"   Bypass Rate: {best_metrics['bypass_rate']:.2f}%")
    logger.info(f"   False Positive Rate: {best_metrics['false_positive_rate']:.2f}%")
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    full_results = {
        'best_weight': best_weight,
        'best_metrics': best_metrics,
        'all_results': results
    }
    
    with open(output_path, 'w') as f:
        json.dump(full_results, f, indent=2)
    
    # Test Adaptive Ensemble
    logger.info("\n" + "="*80)
    logger.info("TESTING ADAPTIVE ENSEMBLE")
    logger.info("="*80)
    
    adaptive_ensemble = AdaptiveEnsembleDetector(
        v1_wrapper,
        v2_wrapper,
        v2_confidence_threshold=0.8,
        v2_malicious_threshold=0.8,
        v2_benign_threshold=0.2
    )
    
    adaptive_metrics = evaluate_ensemble(adaptive_ensemble, samples, labels)
    
    logger.info(f"\n📊 Adaptive Ensemble Results:")
    logger.info(f"  Accuracy: {adaptive_metrics['accuracy']:.2f}%")
    logger.info(f"  Detection Rate: {adaptive_metrics['detection_rate']:.2f}%")
    logger.info(f"  Bypass Rate: {adaptive_metrics['bypass_rate']:.2f}%")
    logger.info(f"  False Positive Rate: {adaptive_metrics['false_positive_rate']:.2f}%")
    logger.info(f"  Avg Disagreement: {adaptive_metrics['avg_disagreement']:.4f}")
    
    # Add to results
    full_results['adaptive_ensemble'] = {
        'metrics': adaptive_metrics,
        'strategy': 'adaptive_fallback'
    }
    
    # Save updated results
    with open(output_path, 'w') as f:
        json.dump(full_results, f, indent=2)
    
    logger.info(f"\n💾 Results saved to: {output_path}")
    logger.info("="*80)


if __name__ == "__main__":
    main()

