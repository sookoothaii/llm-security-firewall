"""
Erweiterte Final Model Evaluation mit Explainability
===================================================

Evaluiert das beste Modell auf einem separaten Test-Set und analysiert
False Positives/Negatives detailliert.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Any
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
import logging
from tqdm import tqdm

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))
sys.path.insert(0, str(project_root))

from llm_firewall.ml.quantum_inspired_architectures import QuantumInspiredCNN
from detectors.code_intent_service.quantum_model_loader import SimpleTokenizer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CodeIntentDataset(Dataset):
    """Dataset für Code-Intent-Klassifikation."""
    
    def __init__(self, data_path: str, tokenizer, max_length: int = 512):
        self.data = []
        self.tokenizer = tokenizer
        self.max_length = max_length
        
        with open(data_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    self.data.append(item)
                except json.JSONDecodeError as e:
                    logger.warning(f"Skipping invalid JSON line: {e}")
        
        logger.info(f"Loaded {len(self.data)} examples from {data_path}")
    
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        item = self.data[idx]
        text = item['text']
        label = int(item['label'])
        
        if hasattr(self.tokenizer, 'encode'):
            token_ids = self.tokenizer.encode(text, max_length=self.max_length)
            token_ids = torch.tensor(token_ids, dtype=torch.long)
        else:
            encoded = self.tokenizer(
                text,
                max_length=self.max_length,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )
            token_ids = encoded['input_ids'].squeeze(0)
        
        return token_ids, label, text


def load_champion_model(model_path: str, vocab_size: int = 10000, device: str = 'cpu'):
    """Lade das Champion-Modell aus Checkpoint."""
    logger.info(f"Loading champion model from {model_path}")
    
    # Lade Checkpoint
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    
    # Extrahiere Hyperparameter aus Checkpoint
    if 'hyperparameters' in checkpoint:
        hp = checkpoint['hyperparameters']
        vocab_size = hp.get('vocab_size', vocab_size)
        embedding_dim = hp.get('embedding_dim', 128)
        hidden_dims = hp.get('hidden_dims', [256, 128, 64])
        kernel_sizes = hp.get('kernel_sizes', [3, 5, 7])
        dropout = hp.get('dropout', 0.5)
    else:
        # Fallback zu Standardwerten
        embedding_dim = 128
        hidden_dims = [256, 128, 64]
        kernel_sizes = [3, 5, 7]
        dropout = 0.5
    
    # Erstelle Modell mit korrekter Architektur
    model = QuantumInspiredCNN(
        vocab_size=vocab_size,
        embedding_dim=embedding_dim,
        num_classes=2,
        hidden_dims=hidden_dims,
        kernel_sizes=kernel_sizes,
        dropout=dropout
    )
    
    # Lade State Dict
    if 'model_state_dict' in checkpoint:
        model.load_state_dict(checkpoint['model_state_dict'])
    else:
        # Direktes State Dict
        model.load_state_dict(checkpoint)
    
    model.eval()
    model = model.to(device)
    
    logger.info(f"✓ Model loaded successfully")
    logger.info(f"  Epoch: {checkpoint.get('epoch', 'N/A')}")
    logger.info(f"  Val Loss: {checkpoint.get('val_loss', 'N/A'):.4f}")
    logger.info(f"  Val FNR: {checkpoint.get('val_fnr', 'N/A'):.4f}")
    
    return model


def analyze_failures(
    model: nn.Module,
    test_loader: DataLoader,
    device: str,
    top_k: int = 10
) -> Tuple[List[Dict], List[Dict]]:
    """
    Analysiere detailliert, WO das Modell scheitert.
    
    Returns:
        (false_negatives, false_positives) - Listen von Dictionaries mit Details
    """
    model.eval()
    false_positives = []  # Benign, aber als malicious erkannt
    false_negatives = []  # Malicious, aber als benign erkannt (KRITISCH!)
    
    all_predictions = []
    all_labels = []
    all_probs = []
    all_texts = []
    
    with torch.no_grad():
        for input_ids, labels, texts in tqdm(test_loader, desc="Evaluating"):
            input_ids = input_ids.to(device)
            labels = labels.to(device)
            
            logits = model(input_ids)
            probabilities = torch.softmax(logits, dim=-1)
            predictions = logits.argmax(dim=1)
            
            all_predictions.extend(predictions.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probabilities[:, 1].cpu().numpy())  # Probability für "malicious"
            all_texts.extend(texts)
    
    # Analysiere Fehler
    for text, label, pred, prob in zip(all_texts, all_labels, all_predictions, all_probs):
        if label == 0 and pred == 1:  # False Positive
            false_positives.append({
                'text': text,
                'label': int(label),
                'prediction': int(pred),
                'malicious_probability': float(prob),
                'error_type': 'false_positive'
            })
        elif label == 1 and pred == 0:  # False Negative (KRITISCH!)
            false_negatives.append({
                'text': text,
                'label': int(label),
                'prediction': int(pred),
                'malicious_probability': float(prob),
                'error_type': 'false_negative'
            })
    
    # Sortiere nach Confidence (höchste zuerst für FPs, niedrigste zuerst für FNs)
    false_positives.sort(key=lambda x: x['malicious_probability'], reverse=True)
    false_negatives.sort(key=lambda x: x['malicious_probability'])
    
    return false_negatives[:top_k], false_positives[:top_k]


def print_failure_analysis(false_negatives: List[Dict], false_positives: List[Dict]):
    """Drucke detaillierte Fehleranalyse."""
    print("\n" + "=" * 80)
    print("🔍 KRITISCHE FEHLERANALYSE")
    print("=" * 80)
    
    print(f"\n❌ FALSE NEGATIVES ({len(false_negatives)} - ÜBERSEHENE ANGRIFFE):")
    print("-" * 80)
    if false_negatives:
        for i, fn in enumerate(false_negatives, 1):
            print(f"\n  {i}. False Negative (Confidence: {fn['malicious_probability']:.4f})")
            print(f"     Text: '{fn['text'][:200]}...'")
            print(f"     Label: malicious (1) → Prediction: benign (0)")
            print(f"     ⚠️  KRITISCH: Malicious Code wurde als benign klassifiziert!")
    else:
        print("  ✓ Keine False Negatives - Alle Angriffe wurden erkannt!")
    
    print(f"\n⚠️  FALSE POSITIVES ({len(false_positives)} - FÄLSCHLICHE BLOCKIERUNGEN):")
    print("-" * 80)
    if false_positives:
        for i, fp in enumerate(false_positives, 1):
            print(f"\n  {i}. False Positive (Confidence: {fp['malicious_probability']:.4f})")
            print(f"     Text: '{fp['text'][:200]}...'")
            print(f"     Label: benign (0) → Prediction: malicious (1)")
            print(f"     ℹ️  Benign Code wurde fälschlich blockiert")
    else:
        print("  ✓ Keine False Positives - Keine fälschlichen Blockierungen!")
    
    print("\n" + "=" * 80)


def evaluate_model(
    model_path: str,
    test_data_path: str,
    vocab_size: int = 10000,
    max_length: int = 512,
    batch_size: int = 32,
    device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
    top_k_failures: int = 10
):
    """Haupt-Evaluations-Funktion."""
    
    logger.info("=" * 80)
    logger.info("FINAL MODEL EVALUATION")
    logger.info("=" * 80)
    logger.info(f"Model: {model_path}")
    logger.info(f"Test Set: {test_data_path}")
    logger.info(f"Device: {device}")
    logger.info("")
    
    device = torch.device(device)
    
    # Lade Modell
    model = load_champion_model(model_path, vocab_size=vocab_size, device=device)
    
    # Erstelle Tokenizer
    tokenizer = SimpleTokenizer(vocab_size=vocab_size)
    
    # Lade Test-Dataset
    test_dataset = CodeIntentDataset(test_data_path, tokenizer, max_length)
    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=2
    )
    
    logger.info(f"Test Set: {len(test_dataset)} samples")
    logger.info("")
    
    # Evaluation
    logger.info("Running evaluation...")
    model.eval()
    all_predictions = []
    all_labels = []
    all_probs = []
    all_texts = []
    
    with torch.no_grad():
        for input_ids, labels, texts in tqdm(test_loader, desc="Evaluating"):
            input_ids = input_ids.to(device)
            labels = labels.to(device)
            
            logits = model(input_ids)
            probabilities = torch.softmax(logits, dim=-1)
            predictions = logits.argmax(dim=1)
            
            all_predictions.extend(predictions.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probabilities[:, 1].cpu().numpy())
            all_texts.extend(texts)
    
    # Metriken
    accuracy = accuracy_score(all_labels, all_predictions)
    precision = precision_score(all_labels, all_predictions, pos_label=1, zero_division=0)
    recall = recall_score(all_labels, all_predictions, pos_label=1, zero_division=0)
    f1 = f1_score(all_labels, all_predictions, pos_label=1, zero_division=0)
    
    # Confusion Matrix
    cm = confusion_matrix(all_labels, all_predictions)
    tn, fp, fn, tp = cm.ravel()
    
    # Security-spezifische Metriken
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    # Ausgabe
    print("\n" + "=" * 80)
    print("📊 TEST SET EVALUATION RESULTS")
    print("=" * 80)
    print(f"\nAccuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"\nSecurity Metrics:")
    print(f"  False Negative Rate (FNR): {fnr:.4f} ({fnr*100:.2f}%) ⚠️")
    print(f"  False Positive Rate (FPR): {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"\nConfusion Matrix:")
    print(f"  True Negatives (TN):  {tn}")
    print(f"  False Positives (FP): {fp}")
    print(f"  False Negatives (FN): {fn} ⚠️")
    print(f"  True Positives (TP):  {tp}")
    print("")
    
    # Classification Report
    print("Classification Report:")
    print(classification_report(all_labels, all_predictions, target_names=['benign', 'malicious']))
    
    # Fehleranalyse
    false_negatives, false_positives = analyze_failures(
        model, test_loader, device, top_k=top_k_failures
    )
    print_failure_analysis(false_negatives, false_positives)
    
    # Speichere detaillierte Ergebnisse
    results = {
        'metrics': {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'false_negative_rate': float(fnr),
            'false_positive_rate': float(fpr),
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn)
        },
        'false_negatives': false_negatives,
        'false_positives': false_positives,
        'confusion_matrix': {
            'tn': int(tn),
            'fp': int(fp),
            'fn': int(fn),
            'tp': int(tp)
        }
    }
    
    # Speichere Ergebnisse
    output_path = Path(model_path).parent / 'test_evaluation_results.json'
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    logger.info(f"\n✓ Detailed results saved to: {output_path}")
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate final model on test set with detailed failure analysis"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="./models/quantum_cnn_trained/best_model.pt",
        help="Path to champion model checkpoint"
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
        "--batch_size",
        type=int,
        default=32,
        help="Batch size"
    )
    parser.add_argument(
        "--device",
        type=str,
        default=None,
        help="Device (cuda/cpu, default: auto)"
    )
    parser.add_argument(
        "--top_k",
        type=int,
        default=10,
        help="Number of top failures to show"
    )
    
    args = parser.parse_args()
    
    if args.device is None:
        args.device = 'cuda' if torch.cuda.is_available() else 'cpu'
    
    evaluate_model(
        model_path=args.model,
        test_data_path=args.test,
        vocab_size=args.vocab_size,
        batch_size=args.batch_size,
        device=args.device,
        top_k_failures=args.top_k
    )


if __name__ == "__main__":
    main()
