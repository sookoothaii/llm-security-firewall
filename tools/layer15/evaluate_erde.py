"""Evaluate crisis detection with ERDE metric (Early Risk Detection Error).

ERDE is delay-aware: penalizes late detection of positive cases.

Paper: Losada & Crestani (2016) - "A Test Collection for Research on Depression and Language Use"

Usage:
  python evaluate_erde.py --predictions preds.jsonl --ground_truth truth.jsonl --o 50
"""

import argparse
import json
import numpy as np
from pathlib import Path
from typing import List, Tuple, Dict
from sklearn.metrics import precision_recall_fscore_support, classification_report


def latency_cost(k: int, o: int = 50) -> float:
    """Latency cost function.
    
    Args:
        k: Delay (number of documents seen before decision)
        o: Latency parameter (default 50)
    
    Returns:
        Cost in [0, 1]
    """
    return 1 - 1 / (1 + np.exp((k - o)))


def erde_score(predictions: List[Tuple[int, int]], ground_truth: List[int], 
               o: int = 50, cfp: float = None, cfn: float = 1.0, ctp: float = 1.0) -> Dict:
    """Calculate ERDE (Early Risk Detection Error).
    
    Args:
        predictions: List of (decision, delay) tuples
        ground_truth: List of true labels (0/1)
        o: Latency parameter
        cfp: False positive cost (auto-set based on prevalence if None)
        cfn: False negative cost
        ctp: True positive cost (late detection penalty)
    
    Returns:
        Dict with ERDE score and breakdown
    """
    if cfp is None:
        # Set FP cost based on class imbalance
        prevalence = sum(ground_truth) / len(ground_truth)
        cfp = prevalence  # If 1% positive, FP cost = 0.01
    
    errors = []
    tp_delays = []
    fp_count = 0
    fn_count = 0
    tn_count = 0
    tp_count = 0
    
    for (pred, delay), truth in zip(predictions, ground_truth):
        if pred == 1 and truth == 0:  # False Positive
            errors.append(cfp)
            fp_count += 1
        elif pred == 0 and truth == 1:  # False Negative
            errors.append(cfn)
            fn_count += 1
        elif pred == 1 and truth == 1:  # True Positive (with delay penalty)
            lc = latency_cost(delay, o)
            errors.append(lc * ctp)
            tp_delays.append(delay)
            tp_count += 1
        else:  # True Negative
            errors.append(0.0)
            tn_count += 1
    
    erde = np.mean(errors)
    
    return {
        "erde": erde,
        "o": o,
        "cfp": cfp,
        "cfn": cfn,
        "ctp": ctp,
        "tp": tp_count,
        "fp": fp_count,
        "tn": tn_count,
        "fn": fn_count,
        "tp_avg_delay": np.mean(tp_delays) if tp_delays else 0.0,
        "tp_median_delay": np.median(tp_delays) if tp_delays else 0.0
    }


def main():
    """Evaluate crisis detection predictions with ERDE."""
    ap = argparse.ArgumentParser()
    ap.add_argument('--predictions', required=True, help='Predictions JSONL (decision, delay, truth)')
    ap.add_argument('--ground_truth', help='Ground truth JSONL (optional if included in predictions)')
    ap.add_argument('--o', type=int, default=50, help='ERDE latency parameter (default: 50)')
    ap.add_argument('--cfp', type=float, help='False positive cost (auto if not set)')
    ap.add_argument('--cfn', type=float, default=1.0, help='False negative cost (default: 1.0)')
    ap.add_argument('--ctp', type=float, default=1.0, help='True positive late cost (default: 1.0)')
    args = ap.parse_args()
    
    # Load predictions
    print(f"[INFO] Loading predictions from {args.predictions}...")
    with open(args.predictions, 'r', encoding='utf-8') as f:
        preds_data = [json.loads(line) for line in f if line.strip()]
    
    predictions = []
    ground_truth = []
    
    for entry in preds_data:
        pred = entry.get('prediction', entry.get('pred', 0))
        delay = entry.get('delay', entry.get('k', 1))
        truth = entry.get('truth', entry.get('label', entry.get('ground_truth', None)))
        
        if truth is None and args.ground_truth:
            # Load from separate file
            continue
        
        predictions.append((pred, delay))
        ground_truth.append(truth)
    
    # Load ground truth from separate file if provided
    if args.ground_truth:
        print(f"[INFO] Loading ground truth from {args.ground_truth}...")
        with open(args.ground_truth, 'r', encoding='utf-8') as f:
            truth_data = [json.loads(line) for line in f if line.strip()]
        ground_truth = [entry['label'] for entry in truth_data]
    
    if not predictions or not ground_truth:
        print("[ERROR] No valid predictions or ground truth found!")
        return
    
    if len(predictions) != len(ground_truth):
        print(f"[ERROR] Prediction count ({len(predictions)}) != ground truth count ({len(ground_truth)})")
        return
    
    print(f"[INFO] Evaluating {len(predictions)} predictions...")
    
    # Calculate ERDE
    result = erde_score(predictions, ground_truth, o=args.o, cfp=args.cfp, cfn=args.cfn, ctp=args.ctp)
    
    # Standard metrics (delay-agnostic)
    preds_only = [p[0] for p in predictions]
    precision, recall, f1, _ = precision_recall_fscore_support(ground_truth, preds_only, average='binary', zero_division=0)
    
    # Print results
    print("\n" + "="*80)
    print("ERDE EVALUATION RESULTS")
    print("="*80)
    
    print("\n[ERDE Metric]")
    print(f"  ERDE_{result['o']}: {result['erde']:.4f}")
    print(f"  Parameters: cfp={result['cfp']:.4f}, cfn={result['cfn']:.2f}, ctp={result['ctp']:.2f}")
    
    print("\n[Confusion Matrix]")
    print(f"  TP: {result['tp']:4d}  FP: {result['fp']:4d}")
    print(f"  FN: {result['fn']:4d}  TN: {result['tn']:4d}")
    
    print("\n[Standard Metrics (delay-agnostic)]")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall:    {recall:.3f}")
    print(f"  F1:        {f1:.3f}")
    
    print("\n[Delay Statistics (True Positives)]")
    print(f"  Average Delay:  {result['tp_avg_delay']:.1f} documents")
    print(f"  Median Delay:   {result['tp_median_delay']:.1f} documents")
    
    # Detailed classification report
    print("\n[Classification Report]")
    print(classification_report(ground_truth, preds_only, target_names=['negative', 'positive'], zero_division=0))
    
    # Interpretation
    print("\n[Interpretation]")
    if result['erde'] < 0.05:
        print("  Excellent early detection (ERDE < 0.05)")
    elif result['erde'] < 0.10:
        print("  Good early detection (ERDE < 0.10)")
    elif result['erde'] < 0.15:
        print("  Fair early detection (ERDE < 0.15)")
    else:
        print("  Poor early detection (ERDE >= 0.15)")
    
    print("\n  Lower ERDE is better (0 = perfect, 1 = worst)")
    print("  ERDE balances accuracy and delay (late TP = high cost)")
    
    # Save results
    output_path = Path(args.predictions).parent / f"erde_{args.o}_results.json"
    with open(output_path, 'w') as f:
        json.dump({
            "erde": result,
            "standard_metrics": {
                "precision": float(precision),
                "recall": float(recall),
                "f1": float(f1)
            },
            "parameters": {
                "o": args.o,
                "cfp": result['cfp'],
                "cfn": result['cfn'],
                "ctp": result['ctp']
            }
        }, f, indent=2)
    
    print(f"\n[OK] Results saved to {output_path}")


if __name__ == '__main__':
    main()










