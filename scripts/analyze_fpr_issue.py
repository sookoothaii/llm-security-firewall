#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyse FPR-Problem und generiere Empfehlungen
===============================================

Analysiert False Positive Ergebnisse und schlägt Threshold-Anpassungen vor.
"""

import json
import sys
import argparse
from pathlib import Path
from collections import Counter
from typing import Dict, List, Any

def analyze_fpr_results(result_file: str) -> Dict[str, Any]:
    """Analysiert FPR-Ergebnisse und generiert Empfehlungen."""
    
    with open(result_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    false_positives = data.get('false_positives', [])
    summary = data.get('summary', {})
    
    print("=" * 80)
    print("FPR ANALYSIS - False Positive Rate Problem")
    print("=" * 80)
    print(f"\nTotal Samples: {summary.get('total', 0)}")
    print(f"False Positives: {summary.get('blocked', 0)} ({summary.get('fpr', 0):.2f}%)")
    print(f"True Negatives: {summary.get('allowed', 0)} ({summary.get('tpr', 0):.2f}%)")
    print()
    
    # Analysiere ML-Score-Verteilung bei False Positives
    ml_scores = [fp.get('ml_score', 0) for fp in false_positives if fp.get('ml_score') is not None]
    rule_scores = [fp.get('rule_score', 0) for fp in false_positives]
    
    if ml_scores:
        print("ML Score Distribution (False Positives):")
        print(f"  Min: {min(ml_scores):.4f}")
        print(f"  Max: {max(ml_scores):.4f}")
        print(f"  Avg: {sum(ml_scores)/len(ml_scores):.4f}")
        print(f"  Median: {sorted(ml_scores)[len(ml_scores)//2]:.4f}")
        print()
        
        # Score-Buckets
        buckets = {
            "0.60-0.65": sum(1 for s in ml_scores if 0.60 <= s < 0.65),
            "0.65-0.70": sum(1 for s in ml_scores if 0.65 <= s < 0.70),
            "0.70-0.75": sum(1 for s in ml_scores if 0.70 <= s < 0.75),
            "0.75+": sum(1 for s in ml_scores if s >= 0.75),
        }
        
        print("ML Score Buckets (False Positives):")
        for bucket, count in buckets.items():
            pct = (count / len(ml_scores) * 100) if ml_scores else 0
            print(f"  {bucket}: {count} ({pct:.1f}%)")
        print()
    
    # Rule Score Analyse
    rule_zero_count = sum(1 for s in rule_scores if s == 0.0)
    print(f"Rule Engine Analysis:")
    print(f"  Rule Score = 0.0: {rule_zero_count}/{len(false_positives)} ({rule_zero_count/len(false_positives)*100:.1f}%)")
    print(f"  → Rule Engine erkennt diese korrekt als BENIGN!")
    print()
    
    # Kategorie-Analyse
    categories = Counter([fp.get('category', 'unknown') for fp in false_positives])
    print("False Positives by Category:")
    for cat, count in categories.most_common():
        pct = (count / len(false_positives) * 100) if false_positives else 0
        print(f"  {cat:20s}: {count:3d} ({pct:5.1f}%)")
    print()
    
    # Empfehlungen
    print("=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)
    print()
    
    if ml_scores:
        avg_ml_score = sum(ml_scores) / len(ml_scores)
        max_ml_score = max(ml_scores)
        
        print("1. THRESHOLD ANPASSUNG:")
        print(f"   Current Threshold: 0.60")
        print(f"   Average ML Score (FP): {avg_ml_score:.4f}")
        print(f"   Max ML Score (FP): {max_ml_score:.4f}")
        print()
        
        # Empfohlene Thresholds
        if max_ml_score < 0.70:
            recommended_threshold = 0.70
            print(f"   [RECOMMENDED] Set QUANTUM_THRESHOLD = 0.70")
            print(f"   → Würde {sum(1 for s in ml_scores if s < 0.70)}/{len(ml_scores)} False Positives eliminieren")
        elif max_ml_score < 0.75:
            recommended_threshold = 0.75
            print(f"   [RECOMMENDED] Set QUANTUM_THRESHOLD = 0.75")
            print(f"   → Würde {sum(1 for s in ml_scores if s < 0.75)}/{len(ml_scores)} False Positives eliminieren")
        else:
            recommended_threshold = 0.80
            print(f"   [RECOMMENDED] Set QUANTUM_THRESHOLD = 0.80")
            print(f"   → Würde {sum(1 for s in ml_scores if s < 0.80)}/{len(ml_scores)} False Positives eliminieren")
        print()
        
        print("2. HYBRID LOGIC VERBESSERUNG:")
        print("   Problem: ML-Modell überschreibt Rule Engine bei benign content")
        print("   Lösung: Rule Engine hat Vorrang wenn Rule Score = 0.0")
        print()
        print("   Code-Änderung in main.py:")
        print("   ```python")
        print("   if rule_score == 0.0:")
        print("       # Rule Engine sagt 'benign' → nur blockieren wenn ML sehr sicher")
        print("       if quantum_confidence > 0.75:  # Höherer Threshold für benign")
        print("           final_score = quantum_score")
        print("       else:")
        print("           final_score = 0.0  # Rule Engine hat Vorrang")
        print("   ```")
        print()
        
        print("3. ADAPTIVE THRESHOLD für BENIGN CONTENT:")
        print("   Wenn Rule Score = 0.0 → höherer ML-Threshold (0.75 statt 0.60)")
        print("   Wenn Rule Score > 0.0 → normaler ML-Threshold (0.60)")
        print()
    
    # Simuliere verschiedene Thresholds
    print("=" * 80)
    print("THRESHOLD SIMULATION")
    print("=" * 80)
    print()
    
    test_thresholds = [0.60, 0.65, 0.70, 0.75, 0.80]
    for threshold in test_thresholds:
        would_block = sum(1 for s in ml_scores if s > threshold)
        would_allow = len(ml_scores) - would_block
        fpr_reduction = (would_allow / len(ml_scores) * 100) if ml_scores else 0
        new_fpr = (would_block / summary.get('total', 1)) * 100
        
        print(f"Threshold {threshold:.2f}:")
        print(f"  Would block: {would_block}/{len(ml_scores)} FP")
        print(f"  Would allow: {would_allow}/{len(ml_scores)} FP")
        print(f"  New FPR: {new_fpr:.2f}% (reduction: {fpr_reduction:.1f}%)")
        print()
    
    return {
        "analysis": {
            "avg_ml_score": sum(ml_scores)/len(ml_scores) if ml_scores else 0,
            "max_ml_score": max(ml_scores) if ml_scores else 0,
            "rule_zero_percentage": (rule_zero_count / len(false_positives) * 100) if false_positives else 0
        },
        "recommendations": {
            "threshold": recommended_threshold if ml_scores else 0.70,
            "hybrid_logic_fix": True
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze FPR results and generate recommendations")
    parser.add_argument("--input", type=str, required=True, help="Input JSON result file from extreme_benign_test.py")
    parser.add_argument("--output", type=str, default=None, help="Output analysis JSON file")
    
    args = parser.parse_args()
    
    if not Path(args.input).exists():
        print(f"[FAIL] File not found: {args.input}")
        sys.exit(1)
    
    analysis = analyze_fpr_results(args.input)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        print(f"\n[OK] Analysis saved to: {args.output}")


if __name__ == "__main__":
    main()
