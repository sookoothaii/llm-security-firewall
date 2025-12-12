"""
Security-Focused Evaluation für Quantum-Inspired CNN
====================================================

Implementiert Security-spezifische Metriken:
- False Negative Rate (FNR) - kritisch für Security
- Cost Matrix (FN kostet 100x mehr als FP)
- Threshold-Tuning für optimale Security-Performance

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import numpy as np
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_curve,
    auc,
    precision_recall_curve
)
import matplotlib.pyplot as plt
import argparse
import sys


def calculate_security_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray] = None
) -> Dict[str, float]:
    """
    Berechne Security-spezifische Metriken.
    
    Args:
        y_true: True Labels (0=benign, 1=malicious)
        y_pred: Predicted Labels
        y_proba: Predicted Probabilities (optional)
    
    Returns:
        Dictionary mit Metriken
    """
    # Standard Metriken
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, pos_label=1, zero_division=0)
    recall = recall_score(y_true, y_pred, pos_label=1, zero_division=0)
    f1 = f1_score(y_true, y_pred, pos_label=1, zero_division=0)
    
    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    # Security-spezifische Metriken
    # False Negative Rate (FNR) - KRITISCH für Security
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    # False Positive Rate (FPR) - weniger kritisch, aber störend
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    # True Positive Rate (TPR) = Recall = Sensitivity
    tpr = recall
    
    # True Negative Rate (TNR) = Specificity
    tnr = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    
    # Cost Matrix (Security-spezifisch)
    # Annahme: False Negative (übersehener Angriff) kostet 100x mehr als False Positive
    cost_fn = 100.0  # Kosten eines False Negative (Sicherheitsvorfall)
    cost_fp = 1.0    # Kosten eines False Positive (Unterbrechung)
    
    total_cost = (fn * cost_fn) + (fp * cost_fp)
    normalized_cost = total_cost / len(y_true)  # Durchschnittliche Kosten pro Sample
    
    # ROC-AUC (wenn Probabilities verfügbar)
    roc_auc = None
    if y_proba is not None:
        try:
            fpr_curve, tpr_curve, _ = roc_curve(y_true, y_proba)
            roc_auc = auc(fpr_curve, tpr_curve)
        except:
            pass
    
    # Precision-Recall AUC
    pr_auc = None
    if y_proba is not None:
        try:
            precision_curve, recall_curve, _ = precision_recall_curve(y_true, y_proba)
            pr_auc = auc(recall_curve, precision_curve)
        except:
            pass
    
    return {
        # Standard Metriken
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        
        # Security-spezifisch
        'false_negative_rate': fnr,
        'false_positive_rate': fpr,
        'true_positive_rate': tpr,
        'true_negative_rate': tnr,
        
        # Confusion Matrix
        'true_positives': int(tp),
        'true_negatives': int(tn),
        'false_positives': int(fp),
        'false_negatives': int(fn),
        
        # Cost Analysis
        'total_cost': total_cost,
        'normalized_cost': normalized_cost,
        'cost_fn': cost_fn,
        'cost_fp': cost_fp,
        
        # AUC (wenn verfügbar)
        'roc_auc': roc_auc,
        'pr_auc': pr_auc,
    }


def threshold_sweep(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    thresholds: Optional[List[float]] = None,
    cost_fn: float = 100.0,
    cost_fp: float = 1.0
) -> Tuple[Dict, float]:
    """
    Teste verschiedene Thresholds und finde optimalen für Security.
    
    Args:
        y_true: True Labels
        y_proba: Predicted Probabilities
        thresholds: Liste von Thresholds zum Testen (default: 0.0 bis 1.0 in 0.05 Schritten)
        cost_fn: Kosten eines False Negative
        cost_fp: Kosten eines False Positive
    
    Returns:
        (best_metrics, best_threshold)
    """
    if thresholds is None:
        thresholds = np.arange(0.0, 1.01, 0.05)
    
    best_cost = float('inf')
    best_threshold = 0.5
    best_metrics = None
    all_results = []
    
    for threshold in thresholds:
        # Wende Threshold an
        y_pred = (y_proba >= threshold).astype(int)
        
        # Berechne Metriken
        metrics = calculate_security_metrics(y_true, y_pred, y_proba)
        metrics['threshold'] = threshold
        
        # Verwende normalized_cost als Hauptkriterium
        if metrics['normalized_cost'] < best_cost:
            best_cost = metrics['normalized_cost']
            best_threshold = threshold
            best_metrics = metrics
        
        all_results.append(metrics)
    
    return best_metrics, best_threshold, all_results


def security_analysis_report(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray] = None,
    threshold: float = 0.5
) -> str:
    """
    Generiere Security-Focused Analysis Report.
    
    Returns:
        Formatierten Report als String
    """
    metrics = calculate_security_metrics(y_true, y_pred, y_proba)
    
    report = []
    report.append("=" * 80)
    report.append("SECURITY-FOCUSED EVALUATION REPORT")
    report.append("=" * 80)
    report.append("")
    
    # Standard Metriken
    report.append("📊 STANDARD METRIKEN:")
    report.append(f"   Accuracy:  {metrics['accuracy']:.4f}")
    report.append(f"   Precision: {metrics['precision']:.4f}")
    report.append(f"   Recall:    {metrics['recall']:.4f}")
    report.append(f"   F1-Score:  {metrics['f1_score']:.4f}")
    report.append("")
    
    # Security-spezifisch
    report.append("🔒 SECURITY-SPEZIFISCHE METRIKEN:")
    report.append(f"   False Negative Rate (FNR): {metrics['false_negative_rate']:.4f} ⚠️ KRITISCH")
    report.append(f"   False Positive Rate (FPR):  {metrics['false_positive_rate']:.4f}")
    report.append(f"   True Positive Rate (TPR):   {metrics['true_positive_rate']:.4f}")
    report.append(f"   True Negative Rate (TNR):   {metrics['true_negative_rate']:.4f}")
    report.append("")
    
    # Confusion Matrix
    report.append("📋 CONFUSION MATRIX:")
    report.append(f"   True Positives (TP):  {metrics['true_positives']}")
    report.append(f"   True Negatives (TN):  {metrics['true_negatives']}")
    report.append(f"   False Positives (FP): {metrics['false_positives']}")
    report.append(f"   False Negatives (FN): {metrics['false_negatives']} ⚠️ KRITISCH")
    report.append("")
    
    # Cost Analysis
    report.append("💰 COST ANALYSIS:")
    report.append(f"   Cost per False Negative: {metrics['cost_fn']:.1f}")
    report.append(f"   Cost per False Positive:  {metrics['cost_fp']:.1f}")
    report.append(f"   Total Cost:               {metrics['total_cost']:.2f}")
    report.append(f"   Normalized Cost:          {metrics['normalized_cost']:.4f} (pro Sample)")
    report.append("")
    
    # Security Assessment
    report.append("⚠️  SECURITY ASSESSMENT:")
    if metrics['false_negative_rate'] < 0.05:
        report.append("   ✅ EXCELLENT: FNR < 5% - Sehr sicher")
    elif metrics['false_negative_rate'] < 0.10:
        report.append("   ✅ GOOD: FNR < 10% - Akzeptabel")
    elif metrics['false_negative_rate'] < 0.20:
        report.append("   ⚠️  WARNING: FNR < 20% - Verbesserung nötig")
    else:
        report.append("   ❌ CRITICAL: FNR >= 20% - NICHT PRODUCTION-READY!")
    report.append("")
    
    # AUC (wenn verfügbar)
    if metrics['roc_auc'] is not None:
        report.append("📈 AUC METRIKEN:")
        report.append(f"   ROC-AUC: {metrics['roc_auc']:.4f}")
        if metrics['pr_auc'] is not None:
            report.append(f"   PR-AUC:  {metrics['pr_auc']:.4f}")
        report.append("")
    
    report.append("=" * 80)
    
    return "\n".join(report)


def plot_security_curves(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    output_path: str = "results/security_curves.png"
):
    """Plotte ROC und Precision-Recall Curves."""
    try:
        fpr, tpr, _ = roc_curve(y_true, y_proba)
        roc_auc = auc(fpr, tpr)
        
        precision, recall, _ = precision_recall_curve(y_true, y_proba)
        pr_auc = auc(recall, precision)
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # ROC Curve
        ax1.plot(fpr, tpr, label=f'ROC (AUC = {roc_auc:.3f})')
        ax1.plot([0, 1], [0, 1], 'k--', label='Random')
        ax1.set_xlabel('False Positive Rate')
        ax1.set_ylabel('True Positive Rate')
        ax1.set_title('ROC Curve')
        ax1.legend()
        ax1.grid(True)
        
        # Precision-Recall Curve
        ax2.plot(recall, precision, label=f'PR (AUC = {pr_auc:.3f})')
        ax2.set_xlabel('Recall')
        ax2.set_ylabel('Precision')
        ax2.set_title('Precision-Recall Curve')
        ax2.legend()
        ax2.grid(True)
        
        plt.tight_layout()
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(output_path, dpi=150)
        print(f"📊 Curves gespeichert: {output_path}")
    except Exception as e:
        print(f"⚠️  Plot-Fehler: {e}")


def main():
    parser = argparse.ArgumentParser(description="Security-Focused Evaluation")
    parser.add_argument(
        "--predictions",
        type=str,
        required=True,
        help="Path to predictions file (JSONL: text, label, prediction, probability)"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Classification threshold (default: 0.5)"
    )
    parser.add_argument(
        "--threshold-sweep",
        action="store_true",
        help="Perform threshold sweep to find optimal threshold"
    )
    parser.add_argument(
        "--plot",
        action="store_true",
        help="Generate ROC/PR curves plot"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="results/security_evaluation.txt",
        help="Output path for report"
    )
    
    args = parser.parse_args()
    
    # Lade Predictions
    print("📂 Lade Predictions...")
    y_true = []
    y_pred = []
    y_proba = []
    
    with open(args.predictions, 'r', encoding='utf-8') as f:
        for line in f:
            data = json.loads(line)
            y_true.append(data['label'])
            y_pred.append(1 if data.get('probability', 0) >= args.threshold else 0)
            y_proba.append(data.get('probability', 0))
    
    y_true = np.array(y_true)
    y_pred = np.array(y_pred)
    y_proba = np.array(y_proba)
    
    print(f"   Geladen: {len(y_true)} Samples")
    print()
    
    # Threshold Sweep (optional)
    if args.threshold_sweep:
        print("🔍 Führe Threshold-Sweep durch...")
        best_metrics, best_threshold, all_results = threshold_sweep(y_true, y_proba)
        print(f"   Optimaler Threshold: {best_threshold:.3f}")
        print(f"   Beste Normalized Cost: {best_metrics['normalized_cost']:.4f}")
        print(f"   Beste FNR: {best_metrics['false_negative_rate']:.4f}")
        print()
        
        # Verwende besten Threshold
        y_pred = (y_proba >= best_threshold).astype(int)
        args.threshold = best_threshold
    
    # Generiere Report
    report = security_analysis_report(y_true, y_pred, y_proba, args.threshold)
    print(report)
    
    # Speichere Report
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"💾 Report gespeichert: {output_path}")
    
    # Plot (optional)
    if args.plot:
        plot_path = args.output.replace('.txt', '_curves.png')
        plot_security_curves(y_true, y_proba, plot_path)


if __name__ == "__main__":
    main()
