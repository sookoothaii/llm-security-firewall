"""
Threshold-Optimierung für Quantum-CNN Modell
=============================================

Findet optimalen Threshold, um FPR zu reduzieren ohne FNR zu erhöhen.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple
import torch
import torch.nn as nn
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import logging

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))
sys.path.insert(0, str(project_root))

from llm_firewall.ml.quantum_inspired_architectures import QuantumInspiredCNN
from detectors.code_intent_service.quantum_model_loader import SimpleTokenizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_model(model_path: str, vocab_size: int = 10000, device: str = 'cpu'):
    """Lade Modell für Threshold-Optimierung."""
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    
    if 'hyperparameters' in checkpoint:
        hp = checkpoint['hyperparameters']
        vocab_size = hp.get('vocab_size', vocab_size)
        embedding_dim = hp.get('embedding_dim', 128)
        hidden_dims = hp.get('hidden_dims', [256, 128, 64])
        kernel_sizes = hp.get('kernel_sizes', [3, 5, 7])
        dropout = hp.get('dropout', 0.5)
    else:
        embedding_dim = 128
        hidden_dims = [256, 128, 64]
        kernel_sizes = [3, 5, 7]
        dropout = 0.5
    
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
    
    model.eval()
    model = model.to(device)
    return model


def evaluate_with_threshold(
    model: nn.Module,
    tokenizer,
    test_data_path: str,
    threshold: float,
    device: str = 'cpu'
) -> Dict:
    """Evaluiere Modell mit spezifischem Threshold."""
    
    # Lade Test-Daten
    all_texts = []
    all_labels = []
    all_probs = []
    
    with open(test_data_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                all_texts.append(item['text'])
                all_labels.append(int(item['label']))
            except json.JSONDecodeError:
                continue
    
    # Mache Vorhersagen
    model.eval()
    with torch.no_grad():
        for text in all_texts:
            if hasattr(tokenizer, 'encode'):
                token_ids = tokenizer.encode(text, max_length=512)
                input_ids = torch.tensor([token_ids], dtype=torch.long).to(device)
            else:
                encoded = tokenizer(text, return_tensors="pt", max_length=512)
                input_ids = encoded['input_ids'].to(device)
            
            logits = model(input_ids)
            probabilities = torch.softmax(logits, dim=-1)
            prob_malicious = probabilities[0][1].item()
            all_probs.append(prob_malicious)
    
    # Wende Threshold an
    predictions = [1 if prob >= threshold else 0 for prob in all_probs]
    
    # Berechne Metriken
    accuracy = accuracy_score(all_labels, predictions)
    precision = precision_score(all_labels, predictions, pos_label=1, zero_division=0)
    recall = recall_score(all_labels, predictions, pos_label=1, zero_division=0)
    f1 = f1_score(all_labels, predictions, pos_label=1, zero_division=0)
    
    # Confusion Matrix
    cm = confusion_matrix(all_labels, predictions)
    tn, fp, fn, tp = cm.ravel()
    
    # Security-Metriken
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    return {
        'threshold': threshold,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'false_negative_rate': fnr,
        'false_positive_rate': fpr,
        'true_positives': int(tp),
        'true_negatives': int(tn),
        'false_positives': int(fp),
        'false_negatives': int(fn)
    }


def optimize_threshold(
    model_path: str,
    test_data_path: str,
    vocab_size: int = 10000,
    device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
    threshold_range: Tuple[float, float] = (0.3, 0.9),
    step: float = 0.05
):
    """Finde optimalen Threshold durch Sweep."""
    
    logger.info("=" * 80)
    logger.info("THRESHOLD OPTIMIZATION")
    logger.info("=" * 80)
    logger.info(f"Model: {model_path}")
    logger.info(f"Test Set: {test_data_path}")
    logger.info(f"Threshold Range: {threshold_range[0]} - {threshold_range[1]} (step: {step})")
    logger.info("")
    
    device = torch.device(device)
    
    # Lade Modell
    model = load_model(model_path, vocab_size=vocab_size, device=device)
    tokenizer = SimpleTokenizer(vocab_size=vocab_size)
    
    # Threshold Sweep
    thresholds = np.arange(threshold_range[0], threshold_range[1] + step, step)
    results = []
    
    logger.info("Running threshold sweep...")
    for threshold in thresholds:
        metrics = evaluate_with_threshold(model, tokenizer, test_data_path, threshold, device=device)
        results.append(metrics)
        logger.info(f"Threshold {threshold:.2f}: FNR={metrics['false_negative_rate']:.4f}, FPR={metrics['false_positive_rate']:.4f}, Accuracy={metrics['accuracy']:.4f}")
    
    # Finde optimalen Threshold
    # Kriterium: Minimale FPR bei FNR <= 0.01 (1%)
    optimal_threshold = None
    optimal_metrics = None
    
    for result in results:
        if result['false_negative_rate'] <= 0.01:  # FNR <= 1%
            if optimal_threshold is None or result['false_positive_rate'] < optimal_metrics['false_positive_rate']:
                optimal_threshold = result['threshold']
                optimal_metrics = result
    
    # Falls kein Threshold mit FNR <= 1% gefunden, nimm den mit niedrigster FPR
    if optimal_threshold is None:
        optimal_threshold = min(results, key=lambda x: x['false_positive_rate'])['threshold']
        optimal_metrics = min(results, key=lambda x: x['false_positive_rate'])
    
    # Ausgabe
    print("\n" + "=" * 80)
    print("📊 THRESHOLD OPTIMIZATION RESULTS")
    print("=" * 80)
    print(f"\nOptimal Threshold: {optimal_threshold:.2f}")
    print(f"\nMetrics at Optimal Threshold:")
    print(f"  Accuracy:  {optimal_metrics['accuracy']:.4f}")
    print(f"  Precision: {optimal_metrics['precision']:.4f}")
    print(f"  Recall:    {optimal_metrics['recall']:.4f}")
    print(f"  F1-Score:  {optimal_metrics['f1_score']:.4f}")
    print(f"  FNR:       {optimal_metrics['false_negative_rate']:.4f} ({optimal_metrics['false_negative_rate']*100:.2f}%)")
    print(f"  FPR:       {optimal_metrics['false_positive_rate']:.4f} ({optimal_metrics['false_positive_rate']*100:.2f}%)")
    print(f"  TP: {optimal_metrics['true_positives']}, TN: {optimal_metrics['true_negatives']}")
    print(f"  FP: {optimal_metrics['false_positives']}, FN: {optimal_metrics['false_negatives']}")
    
    # Vergleich mit Standard-Threshold (0.5)
    standard_result = next((r for r in results if abs(r['threshold'] - 0.5) < 0.01), None)
    if standard_result:
        print(f"\nComparison with Standard Threshold (0.5):")
        print(f"  FNR: {standard_result['false_negative_rate']:.4f} -> {optimal_metrics['false_negative_rate']:.4f} (Δ: {optimal_metrics['false_negative_rate'] - standard_result['false_negative_rate']:+.4f})")
        print(f"  FPR: {standard_result['false_positive_rate']:.4f} -> {optimal_metrics['false_positive_rate']:.4f} (Δ: {optimal_metrics['false_positive_rate'] - standard_result['false_positive_rate']:+.4f})")
    
    # Speichere Ergebnisse
    output_path = Path(model_path).parent / 'threshold_optimization_results.json'
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump({
            'optimal_threshold': optimal_threshold,
            'optimal_metrics': optimal_metrics,
            'all_results': results,
            'standard_threshold_metrics': standard_result
        }, f, indent=2, ensure_ascii=False)
    
    logger.info(f"\n✓ Results saved to: {output_path}")
    
    return optimal_threshold, optimal_metrics


def main():
    parser = argparse.ArgumentParser(
        description="Optimize threshold for Quantum-CNN model to reduce FPR"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="./models/quantum_cnn_trained/best_model.pt",
        help="Path to model checkpoint"
    )
    parser.add_argument(
        "--test",
        type=str,
        default="./data/train/quantum_cnn_training_test.jsonl",
        help="Path to test set JSONL"
    )
    parser.add_argument(
        "--vocab_size",
        type=int,
        default=10000,
        help="Vocabulary size"
    )
    parser.add_argument(
        "--device",
        type=str,
        default=None,
        help="Device (cuda/cpu, default: auto)"
    )
    parser.add_argument(
        "--threshold_min",
        type=float,
        default=0.3,
        help="Minimum threshold for sweep"
    )
    parser.add_argument(
        "--threshold_max",
        type=float,
        default=0.9,
        help="Maximum threshold for sweep"
    )
    parser.add_argument(
        "--step",
        type=float,
        default=0.05,
        help="Step size for threshold sweep"
    )
    
    args = parser.parse_args()
    
    if args.device is None:
        args.device = 'cuda' if torch.cuda.is_available() else 'cpu'
    
    optimize_threshold(
        model_path=args.model,
        test_data_path=args.test,
        vocab_size=args.vocab_size,
        device=args.device,
        threshold_range=(args.threshold_min, args.threshold_max),
        step=args.step
    )


if __name__ == "__main__":
    main()
