"""
Test Calibrated V2 Ensemble

Tests the ensemble with calibrated V2 model to measure FPR improvement.

Usage:
    python -m detectors.orchestrator.infrastructure.training.test_calibrated_ensemble \
        --v1-model models/code_intent_adversarial_v1/best_model.pt \
        --v2-model models/code_intent_adversarial_v2/best_model.pt \
        --v2-calibration models/code_intent_adversarial_v2_calibration.json \
        --validation-set data/adversarial_training/code_intent_true_validation.jsonl \
        --output results/calibrated_ensemble_validation.json
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

import torch

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


def evaluate_model(wrapper, samples: List[str], labels: List[int]) -> Dict[str, Any]:
    """Evaluate model wrapper on samples."""
    correct = 0
    total = len(samples)
    
    malicious_samples = [s for s, l in zip(samples, labels) if l == 1]
    benign_samples = [s for s, l in zip(samples, labels) if l == 0]
    
    malicious_pred = []
    benign_pred = []
    
    for text, label in zip(samples, labels):
        score, conf = wrapper.predict_with_confidence(text)
        is_malicious = score >= 0.5
        
        if is_malicious == bool(label):
            correct += 1
        
        if label == 1:
            malicious_pred.append({
                'text': text,
                'score': score,
                'confidence': conf,
                'predicted': is_malicious
            })
        else:
            benign_pred.append({
                'text': text,
                'score': score,
                'confidence': conf,
                'predicted': is_malicious
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
    
    return {
        'total_samples': total,
        'malicious_samples': malicious_total,
        'benign_samples': benign_total,
        'accuracy': accuracy,
        'detection_rate': detection_rate,
        'bypass_rate': bypass_rate,
        'false_positive_rate': false_positive_rate
    }


def evaluate_ensemble(ensemble, samples: List[str], labels: List[int]) -> Dict[str, Any]:
    """Evaluate ensemble on samples."""
    correct = 0
    total = len(samples)
    
    malicious_samples = [s for s, l in zip(samples, labels) if l == 1]
    benign_samples = [s for s, l in zip(samples, labels) if l == 0]
    
    malicious_pred = []
    benign_pred = []
    decision_modes = {'v2_high_confidence_malicious': 0, 'v2_high_confidence_benign': 0, 'v1_fallback': 0}
    
    for text, label in zip(samples, labels):
        score, conf, metadata = ensemble.predict(text)
        is_malicious = score >= 0.5
        
        if is_malicious == bool(label):
            correct += 1
        
        decision_mode = metadata.get('decision_mode', 'unknown')
        if decision_mode in decision_modes:
            decision_modes[decision_mode] += 1
        
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
        'decision_modes': decision_modes
    }


def main():
    parser = argparse.ArgumentParser(description="Test Calibrated V2 Ensemble")
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
        "--v2-calibration",
        type=str,
        required=True,
        help="Path to V2 calibration JSON"
    )
    parser.add_argument(
        "--validation-set",
        type=str,
        required=True,
        help="Path to validation set JSONL"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/calibrated_ensemble_validation.json",
        help="Output JSON path"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device (cpu/cuda)"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("CALIBRATED ENSEMBLE VALIDATION")
    logger.info("="*80)
    
    # Load models
    from detectors.orchestrator.domain.ensemble import load_ensemble_models, AdaptiveEnsembleDetector
    from detectors.orchestrator.infrastructure.training.calibrate_model import (
        CalibratedModelWrapper, load_model, SimpleTokenizer
    )
    
    logger.info("\nLoading models...")
    
    # Load V1 (normal wrapper)
    v1_wrapper, _ = load_ensemble_models(args.v1_model, args.v2_model, args.device)
    
    # Load V2 calibration parameters
    logger.info(f"Loading V2 calibration from {args.v2_calibration}...")
    with open(args.v2_calibration, 'r') as f:
        calib_data = json.load(f)
    
    # Load V2 model and wrap with calibration
    logger.info("Loading V2 model...")
    v2_model = load_model(calib_data['model_path'], args.device)
    v2_tokenizer = SimpleTokenizer(vocab_size=10000)
    
    v2_calibrated_wrapper = CalibratedModelWrapper(
        v2_model,
        v2_tokenizer,
        calib_data['calibration_method'],
        calib_data['calibration_params'],
        args.device
    )
    
    logger.info("✓ Models loaded")
    
    # Load validation set
    logger.info("\nLoading validation set...")
    samples, labels = load_validation_set(Path(args.validation_set))
    logger.info(f"Loaded {len(samples)} samples ({sum(labels)} malicious, {len(labels)-sum(labels)} benign)")
    
    # Evaluate individual models
    logger.info("\n" + "="*80)
    logger.info("EVALUATING INDIVIDUAL MODELS")
    logger.info("="*80)
    
    logger.info("\nV1 Model:")
    v1_metrics = evaluate_model(v1_wrapper, samples, labels)
    logger.info(f"  Accuracy: {v1_metrics['accuracy']:.2f}%")
    logger.info(f"  Detection Rate: {v1_metrics['detection_rate']:.2f}%")
    logger.info(f"  Bypass Rate: {v1_metrics['bypass_rate']:.2f}%")
    logger.info(f"  False Positive Rate: {v1_metrics['false_positive_rate']:.2f}%")
    
    logger.info("\nV2 Model (Calibrated):")
    v2_metrics = evaluate_model(v2_calibrated_wrapper, samples, labels)
    logger.info(f"  Accuracy: {v2_metrics['accuracy']:.2f}%")
    logger.info(f"  Detection Rate: {v2_metrics['detection_rate']:.2f}%")
    logger.info(f"  Bypass Rate: {v2_metrics['bypass_rate']:.2f}%")
    logger.info(f"  False Positive Rate: {v2_metrics['false_positive_rate']:.2f}%")
    
    # Evaluate calibrated ensemble
    logger.info("\n" + "="*80)
    logger.info("EVALUATING CALIBRATED ENSEMBLE")
    logger.info("="*80)
    
    # Create ensemble with calibrated V2
    ensemble = AdaptiveEnsembleDetector(
        v1_wrapper,
        v2_calibrated_wrapper,
        v2_confidence_threshold=0.8,
        v2_malicious_threshold=0.8,
        v2_benign_threshold=0.2
    )
    
    ensemble_metrics = evaluate_ensemble(ensemble, samples, labels)
    
    logger.info("\n📊 Calibrated Ensemble Results:")
    logger.info(f"  Accuracy: {ensemble_metrics['accuracy']:.2f}%")
    logger.info(f"  Detection Rate: {ensemble_metrics['detection_rate']:.2f}%")
    logger.info(f"  Bypass Rate: {ensemble_metrics['bypass_rate']:.2f}%")
    logger.info(f"  False Positive Rate: {ensemble_metrics['false_positive_rate']:.2f}%")
    logger.info(f"  Avg Disagreement: {ensemble_metrics['avg_disagreement']:.4f}")
    
    logger.info(f"\nDecision Mode Distribution:")
    for mode, count in ensemble_metrics['decision_modes'].items():
        logger.info(f"  {mode}: {count} ({count/len(samples)*100:.1f}%)")
    
    # Comparison
    logger.info("\n" + "="*80)
    logger.info("COMPARISON")
    logger.info("="*80)
    
    fpr_improvement_vs_v1 = v1_metrics['false_positive_rate'] - ensemble_metrics['false_positive_rate']
    fpr_improvement_vs_v2 = v2_metrics['false_positive_rate'] - ensemble_metrics['false_positive_rate']
    bypass_improvement = v1_metrics['bypass_rate'] - ensemble_metrics['bypass_rate']
    
    logger.info(f"\n📈 Improvements:")
    logger.info(f"  FPR vs V1: {fpr_improvement_vs_v1:+.2f}%")
    logger.info(f"  FPR vs V2: {fpr_improvement_vs_v2:+.2f}%")
    logger.info(f"  Bypass Rate vs V1: {bypass_improvement:+.2f}%")
    
    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    results = {
        'v1_metrics': v1_metrics,
        'v2_calibrated_metrics': v2_metrics,
        'ensemble_metrics': ensemble_metrics,
        'improvements': {
            'fpr_vs_v1': float(fpr_improvement_vs_v1),
            'fpr_vs_v2': float(fpr_improvement_vs_v2),
            'bypass_vs_v1': float(bypass_improvement)
        }
    }
    
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"\n💾 Results saved to: {output_path}")
    logger.info("="*80)
    
    # Final verdict
    logger.info("\n✅ VERDICT:")
    if ensemble_metrics['false_positive_rate'] < 70 and ensemble_metrics['bypass_rate'] < 2:
        logger.info("   🎉 SUCCESS: Calibrated ensemble shows good balance!")
        logger.info("   Ready for production consideration.")
    elif ensemble_metrics['false_positive_rate'] < v1_metrics['false_positive_rate']:
        logger.info("   ✅ IMPROVEMENT: FPR improved vs V1!")
        logger.info("   Consider for production with monitoring.")
    else:
        logger.info("   ⚠️ NEEDS WORK: FPR still too high.")
        logger.info("   Consider optimizing thresholds or V3 training.")


if __name__ == "__main__":
    main()

