"""
Diagnose Training Data - Analysiere False Positives und Datenqualität
======================================================================

Identifiziert Probleme in Trainingsdaten:
- False Positives (benigne als malicious klassifiziert)
- Daten-Ungleichgewicht
- Ähnlichkeit zwischen benign/malicious Samples

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple
from collections import Counter
import argparse

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))
sys.path.insert(0, str(project_root / "detectors" / "code_intent_service"))


def load_dataset(data_path: str) -> List[Dict]:
    """Lade Dataset."""
    data = []
    with open(data_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return data


def analyze_data_distribution(data: List[Dict]) -> Dict:
    """Analysiere Daten-Verteilung."""
    labels = [item['label'] for item in data]
    label_counts = Counter(labels)
    
    categories = Counter([item.get('category', 'unknown') for item in data])
    
    return {
        'total': len(data),
        'malicious': label_counts.get(1, 0),
        'benign': label_counts.get(0, 0),
        'balance_ratio': label_counts.get(1, 0) / len(data) if len(data) > 0 else 0,
        'categories': dict(categories)
    }


def find_suspicious_benign_samples(data: List[Dict], top_n: int = 50) -> List[Dict]:
    """
    Finde benigne Samples, die verdächtige Patterns enthalten.
    Diese könnten False Positives verursachen.
    """
    suspicious = []
    
    # Verdächtige Keywords, die in benignen Samples problematisch sein könnten
    suspicious_keywords = [
        'rm', 'delete', 'drop', 'exec', 'eval', 'system', 'shell',
        'curl', 'wget', 'nc ', 'bash', 'python -c', 'import os',
        'chmod', 'sudo', 'su ', 'passwd', 'shadow', '../', '..\\'
    ]
    
    for item in data:
        if item['label'] == 0:  # Benign
            text_lower = item['text'].lower()
            matches = [kw for kw in suspicious_keywords if kw in text_lower]
            
            if matches:
                suspicious.append({
                    'text': item['text'],
                    'category': item.get('category', 'unknown'),
                    'matched_keywords': matches,
                    'match_count': len(matches)
                })
    
    # Sortiere nach Anzahl Matches
    suspicious.sort(key=lambda x: x['match_count'], reverse=True)
    
    return suspicious[:top_n]


def analyze_pattern_overlap(train_data: List[Dict], val_data: List[Dict]) -> Dict:
    """Analysiere Überlappung zwischen Train und Val."""
    train_texts = set(item['text'] for item in train_data)
    val_texts = set(item['text'] for item in val_data)
    
    overlap = train_texts.intersection(val_texts)
    
    return {
        'train_unique': len(train_texts),
        'val_unique': len(val_texts),
        'overlap_count': len(overlap),
        'overlap_ratio': len(overlap) / len(val_texts) if len(val_texts) > 0 else 0
    }


def diagnose_model_predictions(
    model_path: str,
    val_data_path: str,
    top_n: int = 50
) -> Tuple[List[Dict], List[Dict]]:
    """
    Analysiere Model-Predictions auf False Positives/Negatives.
    
    Benötigt: Trainiertes Model und Predictions-Datei
    """
    # Lade Predictions (falls vorhanden)
    predictions_path = Path(model_path) / 'predictions.jsonl'
    
    if not predictions_path.exists():
        print(f"⚠️  Predictions-Datei nicht gefunden: {predictions_path}")
        print("   Führe zuerst Training durch oder verwende --analyze-data-only")
        return [], []
    
    false_positives = []
    false_negatives = []
    
    with open(predictions_path, 'r', encoding='utf-8') as f:
        for line in f:
            item = json.loads(line)
            label = item['label']
            prediction = item['prediction']
            probability = item.get('probability', 0.5)
            
            if label == 0 and prediction == 1:  # False Positive
                false_positives.append({
                    'text': item['text'],
                    'probability': probability,
                    'label': label,
                    'prediction': prediction
                })
            
            if label == 1 and prediction == 0:  # False Negative
                false_negatives.append({
                    'text': item['text'],
                    'probability': probability,
                    'label': label,
                    'prediction': prediction
                })
    
    # Sortiere nach Probability (höchste zuerst für FP, niedrigste zuerst für FN)
    false_positives.sort(key=lambda x: x['probability'], reverse=True)
    false_negatives.sort(key=lambda x: x['probability'])
    
    return false_positives[:top_n], false_negatives[:top_n]


def print_report(
    train_stats: Dict,
    val_stats: Dict,
    suspicious_benign: List[Dict],
    false_positives: List[Dict],
    false_negatives: List[Dict],
    overlap: Dict
):
    """Drucke Diagnose-Report."""
    print("=" * 80)
    print("TRAINING DATA DIAGNOSE")
    print("=" * 80)
    print()
    
    # Daten-Verteilung
    print("📊 DATEN-VERTEILUNG:")
    print(f"   Train: {train_stats['total']} Samples")
    print(f"     - Malicious: {train_stats['malicious']} ({train_stats['malicious']/train_stats['total']*100:.1f}%)")
    print(f"     - Benign:    {train_stats['benign']} ({train_stats['benign']/train_stats['total']*100:.1f}%)")
    print(f"     - Balance Ratio: {train_stats['balance_ratio']:.3f} (ideal: 0.5)")
    print()
    
    print(f"   Val: {val_stats['total']} Samples")
    print(f"     - Malicious: {val_stats['malicious']} ({val_stats['malicious']/val_stats['total']*100:.1f}%)")
    print(f"     - Benign:    {val_stats['benign']} ({val_stats['benign']/val_stats['total']*100:.1f}%)")
    print()
    
    # Balance Assessment
    if abs(train_stats['balance_ratio'] - 0.5) > 0.1:
        print("⚠️  WARNUNG: Daten sind unausgewogen!")
        print(f"   Balance Ratio: {train_stats['balance_ratio']:.3f} (sollte ~0.5 sein)")
        print("   → Verwende --weighted_sampler beim Training")
    else:
        print("✅ Daten sind ausgewogen")
    print()
    
    # Overlap
    print("🔄 TRAIN/VAL OVERLAP:")
    print(f"   Overlap: {overlap['overlap_count']} Samples ({overlap['overlap_ratio']*100:.1f}%)")
    if overlap['overlap_ratio'] > 0.1:
        print("   ⚠️  WARNUNG: Hohe Überlappung zwischen Train und Val!")
        print("   → Val-Set sollte komplett unabhängig sein")
    else:
        print("   ✅ Gute Trennung zwischen Train und Val")
    print()
    
    # Suspicious Benign Samples
    print(f"🔍 VERDÄCHTIGE BENIGNE SAMPLES (Top {len(suspicious_benign)}):")
    if suspicious_benign:
        print("   Diese benignen Samples enthalten verdächtige Keywords:")
        print("   → Könnten False Positives verursachen")
        print()
        for i, item in enumerate(suspicious_benign[:20], 1):
            print(f"   {i}. [{item['match_count']} Matches] {item['text'][:80]}...")
            print(f"      Keywords: {', '.join(item['matched_keywords'][:5])}")
    else:
        print("   ✅ Keine verdächtigen benignen Samples gefunden")
    print()
    
    # False Positives (wenn Model vorhanden)
    if false_positives:
        print(f"❌ FALSE POSITIVES (Top {len(false_positives)}):")
        print("   Benigne Samples, die als malicious klassifiziert wurden:")
        print()
        for i, item in enumerate(false_positives[:20], 1):
            print(f"   {i}. [Prob: {item['probability']:.3f}] {item['text'][:80]}...")
        print()
        print(f"   ⚠️  Total False Positives: {len(false_positives)}")
        print("   → Diese Samples müssen überarbeitet werden")
    else:
        print("✅ Keine False Positives gefunden (oder Model nicht analysiert)")
    print()
    
    # False Negatives
    if false_negatives:
        print(f"❌ FALSE NEGATIVES (Top {len(false_negatives)}):")
        print("   Malicious Samples, die als benign klassifiziert wurden:")
        print()
        for i, item in enumerate(false_negatives[:20], 1):
            print(f"   {i}. [Prob: {item['probability']:.3f}] {item['text'][:80]}...")
        print()
        print(f"   ⚠️  Total False Negatives: {len(false_negatives)}")
        print("   → KRITISCH für Security! Diese müssen behoben werden")
    else:
        print("✅ Keine False Negatives gefunden (oder Model nicht analysiert)")
    print()
    
    # Empfehlungen
    print("=" * 80)
    print("💡 EMPFEHLUNGEN:")
    print("=" * 80)
    
    recommendations = []
    
    if abs(train_stats['balance_ratio'] - 0.5) > 0.1:
        recommendations.append("1. Daten ausgleichen (500/500 oder 600/400)")
    
    if suspicious_benign:
        recommendations.append("2. Verdächtige benigne Samples überarbeiten oder entfernen")
    
    if false_positives:
        recommendations.append("3. False Positive Samples analysieren und Labels korrigieren")
    
    if false_negatives:
        recommendations.append("4. False Negative Samples analysieren - KRITISCH für Security!")
    
    if overlap['overlap_ratio'] > 0.1:
        recommendations.append("5. Train/Val Split überarbeiten (keine Überlappung)")
    
    if not recommendations:
        recommendations.append("✅ Daten sehen gut aus! Training kann starten.")
    
    for rec in recommendations:
        print(f"   {rec}")
    
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Diagnose training data quality")
    parser.add_argument(
        "--train",
        type=str,
        default="data/train/quantum_cnn_training.jsonl",
        help="Path to training data"
    )
    parser.add_argument(
        "--val",
        type=str,
        default="data/train/quantum_cnn_training_val.jsonl",
        help="Path to validation data"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Path to trained model directory (for predictions analysis)"
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=50,
        help="Number of top samples to show"
    )
    parser.add_argument(
        "--analyze-data-only",
        action="store_true",
        help="Only analyze data, skip model predictions"
    )
    
    args = parser.parse_args()
    
    # Lade Daten
    print("📂 Lade Daten...")
    train_data = load_dataset(args.train)
    val_data = load_dataset(args.val)
    print(f"   Train: {len(train_data)} Samples")
    print(f"   Val:   {len(val_data)} Samples")
    print()
    
    # Analysiere Daten
    print("🔍 Analysiere Daten...")
    train_stats = analyze_data_distribution(train_data)
    val_stats = analyze_data_distribution(val_data)
    suspicious_benign = find_suspicious_benign_samples(train_data + val_data, top_n=args.top_n)
    overlap = analyze_pattern_overlap(train_data, val_data)
    
    # Analysiere Model-Predictions (wenn verfügbar)
    false_positives = []
    false_negatives = []
    
    if not args.analyze_data_only and args.model:
        print("🤖 Analysiere Model-Predictions...")
        false_positives, false_negatives = diagnose_model_predictions(
            args.model,
            args.val,
            top_n=args.top_n
        )
    
    # Drucke Report
    print_report(
        train_stats,
        val_stats,
        suspicious_benign,
        false_positives,
        false_negatives,
        overlap
    )


if __name__ == "__main__":
    main()
