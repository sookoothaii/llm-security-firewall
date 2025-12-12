"""
Validate V2.1 Enhanced

Vergleicht V2.1 Hotfix vs V2.1 Enhanced auf Validation Set.
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any
import torch

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from detectors.orchestrator.domain.hotfix.v2_1_hotfix_detector import load_v21_hotfix_detector
from detectors.orchestrator.domain.hotfix.v2_1_enhanced import load_v21_enhanced

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


def evaluate_model(
    model,
    validation_samples: List[Dict],
    model_name: str
) -> Dict[str, Any]:
    """Evaluate model."""
    logger.info(f"\nEvaluating {model_name}...")
    
    correct = 0
    total = 0
    benign_correct = 0
    benign_total = 0
    malicious_correct = 0
    malicious_total = 0
    whitelist_correct = 0
    whitelist_total = 0
    false_positives = 0
    false_negatives = 0
    whitelist_overrides = 0
    
    for sample in validation_samples:
        text = sample['text']
        true_label = sample['label']  # 0=benign, 1=malicious
        is_whitelist = sample.get('pattern') is not None
        
        # Predict
        result = model.predict(text)
        
        # Handle both dict and tuple returns
        if isinstance(result, dict):
            score = result.get('score', 0.0)
            conf = result.get('confidence', 0.0)
            metadata = result
            pred_label = 1 if result.get('prediction', 0) == 1 or result.get('is_malicious', False) else 0
        else:
            # Tuple return (for V21Enhanced)
            score, conf, metadata = result
            pred_label = 1 if metadata.get('is_malicious', score >= 0.5) else 0
        
        # Statistics
        total += 1
        if pred_label == true_label:
            correct += 1
        else:
            if pred_label == 1 and true_label == 0:
                false_positives += 1
            else:
                false_negatives += 1
        
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
        
        # Whitelist overrides
        if metadata.get('whitelist_override', False):
            whitelist_overrides += 1
    
    # Calculate metrics
    accuracy = correct / total if total > 0 else 0.0
    benign_accuracy = benign_correct / benign_total if benign_total > 0 else 0.0
    malicious_accuracy = malicious_correct / malicious_total if malicious_total > 0 else 0.0
    whitelist_recall = whitelist_correct / whitelist_total if whitelist_total > 0 else 0.0
    fpr = false_positives / benign_total if benign_total > 0 else 0.0
    bypass_rate = false_negatives / malicious_total if malicious_total > 0 else 0.0
    
    return {
        'model_name': model_name,
        'accuracy': accuracy,
        'benign_accuracy': benign_accuracy,
        'malicious_accuracy': malicious_accuracy,
        'whitelist_recall': whitelist_recall,
        'fpr': fpr,
        'bypass_rate': bypass_rate,
        'false_positives': false_positives,
        'false_negatives': false_negatives,
        'whitelist_overrides': whitelist_overrides,
        'total_samples': total,
        'benign_samples': benign_total,
        'malicious_samples': malicious_total,
        'whitelist_samples': whitelist_total
    }


def print_comparison(v2_1_results: Dict, v21_enhanced_results: Dict):
    """Print comparison."""
    print("="*80)
    print("V2.1 HOTFIX vs V2.1 ENHANCED COMPARISON")
    print("="*80)
    
    print(f"\n{'Metric':<30} {'V2.1 Hotfix':<20} {'V2.1 Enhanced':<20} {'Difference':<15}")
    print("-" * 80)
    
    metrics = [
        ('Accuracy', 'accuracy'),
        ('Benign Accuracy', 'benign_accuracy'),
        ('Malicious Accuracy', 'malicious_accuracy'),
        ('Whitelist Recall', 'whitelist_recall'),
        ('FPR', 'fpr'),
        ('Bypass Rate', 'bypass_rate')
    ]
    
    for metric_name, metric_key in metrics:
        v2_1_val = v2_1_results[metric_key]
        enhanced_val = v21_enhanced_results[metric_key]
        diff = enhanced_val - v2_1_val
        diff_str = f"{diff:+.4f}" if abs(diff) > 0.0001 else "0.0000"
        
        print(f"{metric_name:<30} {v2_1_val:<20.4f} {enhanced_val:<20.4f} {diff_str:<15}")
    
    print("\n" + "="*80)
    print("IMPROVEMENT ANALYSIS")
    print("="*80)
    
    fpr_improvement = v2_1_results['fpr'] - v21_enhanced_results['fpr']
    whitelist_improvement = v21_enhanced_results['whitelist_recall'] - v2_1_results['whitelist_recall']
    
    if v2_1_results['fpr'] > 0:
        print(f"\nFPR Improvement: {fpr_improvement:.4f} ({fpr_improvement/v2_1_results['fpr']*100:.1f}% reduction)")
    else:
        print(f"\nFPR Improvement: {fpr_improvement:.4f} (both have 0% FPR)")
    print(f"Whitelist Recall Improvement: {whitelist_improvement:.4f} ({whitelist_improvement*100:.1f}% increase)")
    print(f"Whitelist Overrides: {v21_enhanced_results['whitelist_overrides']}")
    
    if fpr_improvement > 0 and v21_enhanced_results['bypass_rate'] == 0:
        print("\n✅ V2.1 Enhanced ist besser als V2.1 Hotfix!")
        print("   - Niedrigere FPR")
        print("   - Gleiche Bypass Rate (0%)")
    else:
        print("\n⚠️ V2.1 Enhanced zeigt keine Verbesserung")
        if fpr_improvement <= 0:
            print("   - FPR nicht reduziert")
        if v21_enhanced_results['bypass_rate'] > 0:
            print("   - Bypass Rate > 0% (KRITISCH!)")


def main():
    parser = argparse.ArgumentParser(description="Validate V2.1 Enhanced")
    parser.add_argument(
        "--validation-set",
        type=str,
        required=True,
        help="Path to validation set (JSONL)"
    )
    parser.add_argument(
        "--v1-model",
        type=str,
        required=True,
        help="Path to V1 model"
    )
    parser.add_argument(
        "--v2-model",
        type=str,
        required=True,
        help="Path to V2 model"
    )
    parser.add_argument(
        "--whitelist-model",
        type=str,
        help="Path to Whitelist Classifier model"
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output JSON path for results"
    )
    parser.add_argument(
        "--device",
        type=str,
        default='cuda' if torch.cuda.is_available() else 'cpu',
        help="Device"
    )
    
    args = parser.parse_args()
    
    logger.info("="*80)
    logger.info("V2.1 ENHANCED VALIDATION")
    logger.info("="*80)
    
    # Load validation set
    logger.info("\nLoading validation set...")
    validation_samples = load_validation_set(Path(args.validation_set))
    logger.info(f"Loaded {len(validation_samples)} samples")
    
    # Load models
    logger.info("\nLoading models...")
    v2_1 = load_v21_hotfix_detector(
        v1_model_path=args.v1_model,
        v2_model_path=args.v2_model,
        device=args.device
    )
    
    v21_enhanced = load_v21_enhanced(
        v1_model_path=args.v1_model,
        v2_model_path=args.v2_model,
        whitelist_model_path=args.whitelist_model,
        device=args.device,
        whitelist_enabled=args.whitelist_model is not None
    )
    
    # Evaluate
    v2_1_results = evaluate_model(v2_1, validation_samples, "V2.1 Hotfix")
    v21_enhanced_results = evaluate_model(v21_enhanced, validation_samples, "V2.1 Enhanced")
    
    # Print comparison
    print_comparison(v2_1_results, v21_enhanced_results)
    
    # Save results
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        results = {
            'v2_1_hotfix': v2_1_results,
            'v2_1_enhanced': v21_enhanced_results,
            'comparison': {
                'fpr_improvement': v2_1_results['fpr'] - v21_enhanced_results['fpr'],
                'whitelist_recall_improvement': v21_enhanced_results['whitelist_recall'] - v2_1_results['whitelist_recall'],
                'whitelist_overrides': v21_enhanced_results['whitelist_overrides']
            }
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"\n💾 Results saved to: {output_path}")

if __name__ == "__main__":
    main()

