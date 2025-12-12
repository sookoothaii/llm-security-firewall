"""
Train Quantum-Inspired CNN for Code Intent Detection
====================================================

Training script für QuantumInspiredCNN basierend auf Spezifikation.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Tuple
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from torch.optim.lr_scheduler import ReduceLROnPlateau
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
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


def convert_to_json_serializable(obj):
    """Konvertiert numpy-Typen und andere nicht-JSON-serialisierbare Objekte."""
    if isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_to_json_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_json_serializable(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_to_json_serializable(item) for item in obj)
    else:
        return obj


class CodeIntentDataset(Dataset):
    """Dataset für Code-Intent-Klassifikation."""
    
    def __init__(self, data_path: str, tokenizer, max_length: int = 512):
        """
        Args:
            data_path: Pfad zu JSONL-Datei
            tokenizer: Tokenizer-Instanz
            max_length: Maximale Sequenz-Länge
        """
        self.data = []
        self.tokenizer = tokenizer
        self.max_length = max_length
        
        # Lade Daten
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
        label = int(item['label'])  # 0 oder 1
        
        # Tokenize
        if hasattr(self.tokenizer, 'encode'):
            # SimpleTokenizer
            token_ids = self.tokenizer.encode(text, max_length=self.max_length)
            token_ids = torch.tensor(token_ids, dtype=torch.long)
        else:
            # Transformers Tokenizer
            encoded = self.tokenizer(
                text,
                max_length=self.max_length,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )
            token_ids = encoded['input_ids'].squeeze(0)
        
        return token_ids, label


def train_epoch(
    model: nn.Module,
    train_loader: DataLoader,
    optimizer: optim.Optimizer,
    criterion: nn.Module,
    device: str,
    gradient_clip: float = 0.5,
    epoch: int = 0,
    learning_rate: float = 1e-4,
    warmup_epochs: int = 3
) -> Tuple[float, float]:
    """Ein Training-Epoch mit Gradient Clipping und LR Warmup."""
    model.train()
    total_loss = 0.0
    correct = 0
    total = 0
    
    # Learning Rate Warmup (erste 3 Epochs langsam hochfahren)
    if epoch < warmup_epochs:
        warmup_lr = learning_rate * (epoch + 1) / warmup_epochs
        for param_group in optimizer.param_groups:
            param_group['lr'] = warmup_lr
    
    progress_bar = tqdm(train_loader, desc="Training")
    
    for input_ids, labels in progress_bar:
        input_ids = input_ids.to(device)
        labels = labels.to(device)
        
        # Forward Pass
        optimizer.zero_grad()
        logits = model(input_ids)
        
        # Loss Calculation
        loss = criterion(logits, labels)
        
        # Backward Pass
        loss.backward()
        
        # AGGRESSIVES Gradient Clipping (Notfall-Maßnahme #1)
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=gradient_clip)
        
        # Optimizer Step
        optimizer.step()
        
        # Metrics
        total_loss += loss.item()
        predictions = logits.argmax(dim=1)
        correct += (predictions == labels).sum().item()
        total += labels.size(0)
        
        # Update progress bar
        progress_bar.set_postfix({
            'loss': f'{loss.item():.4f}',
            'acc': f'{correct/total:.4f}'
        })
    
    avg_loss = total_loss / len(train_loader)
    accuracy = correct / total
    return avg_loss, accuracy


def validate(
    model: nn.Module,
    val_loader: DataLoader,
    criterion: nn.Module,
    device: str
) -> Dict[str, float]:
    """Validation ohne Gradienten."""
    model.eval()
    total_loss = 0.0
    all_predictions = []
    all_labels = []
    all_probs = []
    
    with torch.no_grad():
        for input_ids, labels in tqdm(val_loader, desc="Validation"):
            input_ids = input_ids.to(device)
            labels = labels.to(device)
            
            logits = model(input_ids)
            loss = criterion(logits, labels)
            
            total_loss += loss.item()
            probabilities = torch.softmax(logits, dim=-1)
            predictions = logits.argmax(dim=1)
            
            all_predictions.extend(predictions.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probs.extend(probabilities[:, 1].cpu().numpy())  # Probability für "malicious"
    
    avg_loss = total_loss / len(val_loader)
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
    
    return {
        'loss': avg_loss,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'false_negative_rate': fnr,
        'false_positive_rate': fpr,
        'true_positives': int(tp),
        'true_negatives': int(tn),
        'false_positives': int(fp),
        'false_negatives': int(fn),
        'predictions': all_predictions,
        'labels': all_labels,
        'probabilities': all_probs
    }


class FocalLoss(nn.Module):
    """Focal Loss für harte Samples - reduziert Loss für gut klassifizierte Samples."""
    def __init__(self, alpha=0.25, gamma=2.0):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        
    def forward(self, inputs, targets):
        # Für Multi-Class: Convert to one-hot
        ce_loss = nn.functional.cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-ce_loss)  # p_t = confidence
        focal_loss = self.alpha * (1 - pt) ** self.gamma * ce_loss
        return focal_loss.mean()


def train_model(
    train_data_path: str,
    val_data_path: str,
    output_dir: str = "./models/quantum_cnn_trained",
    vocab_size: int = 10000,
    embedding_dim: int = 128,
    hidden_dims: List[int] = [256, 128, 64],
    kernel_sizes: List[int] = [3, 5, 7],
    dropout: float = 0.2,
    num_epochs: int = 20,
    batch_size: int = 32,
    learning_rate: float = 1e-3,
    max_length: int = 512,
    device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
    use_weighted_sampler: bool = False,
    gradient_clip: float = 0.5,
    early_stopping_patience: int = 2,
    weight_decay: float = 1e-4,
    warmup_epochs: int = 3,
    use_focal_loss: bool = False,
    class_weight_malicious: float = 3.0
):
    """Haupt-Training-Loop."""
    
    logger.info("=" * 80)
    logger.info("QUANTUM-INSPIRED CNN TRAINING")
    logger.info("=" * 80)
    logger.info(f"Device: {device}")
    logger.info(f"Output: {output_dir}")
    logger.info("")
    
    # Setup Device
    device = torch.device(device)
    
    # Create Tokenizer
    logger.info("Creating tokenizer...")
    tokenizer = SimpleTokenizer(vocab_size=vocab_size)
    logger.info(f"Tokenizer created (vocab_size={vocab_size})")
    
    # Create Model
    logger.info("Creating QuantumInspiredCNN model...")
    model = QuantumInspiredCNN(
        vocab_size=vocab_size,
        embedding_dim=embedding_dim,
        num_classes=2,
        hidden_dims=hidden_dims,
        kernel_sizes=kernel_sizes,
        dropout=dropout
    )
    model = model.to(device)
    
    # Count parameters
    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    logger.info(f"Model created: {total_params:,} total params, {trainable_params:,} trainable")
    logger.info("")
    
    # Create Datasets
    logger.info("Loading datasets...")
    train_dataset = CodeIntentDataset(train_data_path, tokenizer, max_length)
    val_dataset = CodeIntentDataset(val_data_path, tokenizer, max_length)
    logger.info(f"Train: {len(train_dataset)} samples")
    logger.info(f"Val:   {len(val_dataset)} samples")
    logger.info("")
    
    # Create DataLoaders
    if use_weighted_sampler:
        # Calculate class weights
        labels = [item['label'] for item in train_dataset.data]
        class_counts = [labels.count(0), labels.count(1)]
        class_weights = 1.0 / torch.tensor(class_counts, dtype=torch.float)
        sample_weights = [class_weights[label] for label in labels]
        sampler = WeightedRandomSampler(
            weights=sample_weights,
            num_samples=len(sample_weights),
            replacement=True
        )
        train_loader = DataLoader(
            train_dataset,
            batch_size=batch_size,
            sampler=sampler,
            num_workers=2
        )
    else:
        train_loader = DataLoader(
            train_dataset,
            batch_size=batch_size,
            shuffle=True,
            num_workers=2
        )
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=2
    )
    
    # Setup Training mit Class-Weighted Loss (bestraft False Negatives stärker)
    # Für Sicherheitsmodelle: Höheres Gewicht für malicious Klasse (1) reduziert False Negatives
    if use_focal_loss:
        criterion = FocalLoss(alpha=0.25, gamma=2.0)
        logger.info("Using Focal Loss (alpha=0.25, gamma=2.0)")
    else:
        class_weights = torch.tensor([1.0, class_weight_malicious], device=device)
        criterion = nn.CrossEntropyLoss(weight=class_weights)
        logger.info(f"Using Class-Weighted Loss (benign=1.0, malicious={class_weight_malicious})")
    
    optimizer = optim.Adam(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
    scheduler = ReduceLROnPlateau(
        optimizer,
        mode='min',
        factor=0.5,
        patience=3,
        verbose=False  # Verwende get_last_lr() statt verbose
    )
    
    # Training Loop mit Early Stopping (Notfall-Maßnahme #3)
    best_val_loss = float('inf')
    best_val_fnr = float('inf')
    best_epoch = 0
    best_model_state = None
    training_history = []
    patience_counter = 0  # Early Stopping Counter
    
    logger.info("Starting training...")
    logger.info(f"Gradient Clipping: {gradient_clip}")
    logger.info(f"Early Stopping Patience: {early_stopping_patience}")
    logger.info(f"LR Warmup Epochs: {warmup_epochs}")
    logger.info(f"Weight Decay: {weight_decay}")
    logger.info("")
    
    for epoch in range(num_epochs):
        logger.info(f"Epoch {epoch+1}/{num_epochs}")
        logger.info("-" * 80)
        
        # Training mit Warmup
        train_loss, train_acc = train_epoch(
            model, train_loader, optimizer, criterion, device,
            gradient_clip=gradient_clip,
            epoch=epoch,
            learning_rate=learning_rate,
            warmup_epochs=warmup_epochs
        )
        
        # Validation
        val_metrics = validate(model, val_loader, criterion, device)
        
        # Learning Rate Scheduling
        scheduler.step(val_metrics['loss'])
        
        # Logging
        current_lr = optimizer.param_groups[0]['lr']
        logger.info(f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.4f}")
        logger.info(f"Val Loss:   {val_metrics['loss']:.4f}, Val Acc: {val_metrics['accuracy']:.4f}")
        logger.info(f"Val Precision: {val_metrics['precision']:.4f}, Recall: {val_metrics['recall']:.4f}, F1: {val_metrics['f1_score']:.4f}")
        logger.info(f"Val FNR: {val_metrics['false_negative_rate']:.4f} ⚠️, FPR: {val_metrics['false_positive_rate']:.4f}")
        logger.info(f"Learning Rate: {current_lr:.2e}")
        logger.info("")
        
        # Save History (konvertiere numpy-Typen für JSON)
        epoch_history = {
            'epoch': epoch + 1,
            'train_loss': float(train_loss),
            'train_acc': float(train_acc),
            'learning_rate': float(current_lr),
            **{k: convert_to_json_serializable(v) for k, v in val_metrics.items() if k not in ['predictions', 'labels', 'probabilities']}
        }
        training_history.append(epoch_history)
        
        # VALIDATION-LOSS MONITORING mit Early Stopping (Notfall-Maßnahme #3)
        if val_metrics['loss'] < best_val_loss:
            best_val_loss = val_metrics['loss']
            best_val_fnr = val_metrics['false_negative_rate']
            best_epoch = epoch + 1
            best_model_state = model.state_dict().copy()
            patience_counter = 0  # Reset counter bei Verbesserung
            
            # Save checkpoint
            checkpoint_path = os.path.join(output_dir, 'best_model.pt')
            os.makedirs(output_dir, exist_ok=True)
            torch.save({
                'epoch': epoch + 1,
                'model_state_dict': best_model_state,
                'optimizer_state_dict': optimizer.state_dict(),
                'scheduler_state_dict': scheduler.state_dict(),
                'val_loss': best_val_loss,
                'val_fnr': best_val_fnr,
                'hyperparameters': {
                    'vocab_size': vocab_size,
                    'embedding_dim': embedding_dim,
                    'hidden_dims': hidden_dims,
                    'kernel_sizes': kernel_sizes,
                    'dropout': dropout,
                    'gradient_clip': gradient_clip,
                    'learning_rate': learning_rate,
                    'weight_decay': weight_decay
                }
            }, checkpoint_path)
            logger.info(f"✓ Saved best model (val_loss: {best_val_loss:.4f}, FNR: {best_val_fnr:.4f})")
            logger.info("")
        else:
            patience_counter += 1
            logger.warning(f"⚠️ Val Loss steigt! Patience: {patience_counter}/{early_stopping_patience}")
            
            # Early Stopping: Nach X schlechten Epochs stoppen
            if patience_counter >= early_stopping_patience:
                logger.warning("=" * 80)
                logger.warning("⚠️ EARLY STOPPING: Val Loss steigt - Training gestoppt")
                logger.warning(f"Best Val Loss: {best_val_loss:.4f} (Epoch {best_epoch})")
                logger.warning("=" * 80)
                logger.info("")
                break
    
    # Load Best Model aus Checkpoint (sicherer als best_model_state)
    checkpoint_path = os.path.join(output_dir, 'best_model.pt')
    if os.path.exists(checkpoint_path):
        logger.info(f"Loading best model from checkpoint: {checkpoint_path}")
        checkpoint = torch.load(checkpoint_path, map_location=device, weights_only=False)
        model.load_state_dict(checkpoint['model_state_dict'])
        model.eval()  # Wichtig: Setze Modell in eval-Modus
        logger.info("✓ Loaded best model for final evaluation")
        logger.info(f"Best model was from Epoch {checkpoint.get('epoch', best_epoch)}")
        logger.info(f"Best Val Loss: {checkpoint.get('val_loss', best_val_loss):.4f}")
        logger.info(f"Best FNR: {checkpoint.get('val_fnr', best_val_fnr):.4f}")
    elif best_model_state is not None:
        # Fallback: Verwende best_model_state falls Checkpoint nicht existiert
        model.load_state_dict(best_model_state)
        model.eval()
        logger.info("Loaded best model from memory (checkpoint file not found)")
        logger.info(f"Best model was from Epoch {best_epoch} with val_loss: {best_val_loss:.4f}, FNR: {best_val_fnr:.4f}")
    else:
        logger.warning("⚠️ No best model found! Using current model state.")
    
    # Final Evaluation mit bestem Modell
    logger.info("=" * 80)
    logger.info("FINAL EVALUATION (Best Model)")
    logger.info("=" * 80)
    
    # Debug: Prüfe Modell-Zustand
    logger.info(f"Model in eval mode: {not model.training}")
    
    final_metrics = validate(model, val_loader, criterion, device)
    
    # Debug: Zeige Verteilung der Vorhersagen
    predictions = np.array(final_metrics['predictions'])
    labels = np.array(final_metrics['labels'])
    logger.info(f"Prediction distribution: {np.bincount(predictions)}")
    logger.info(f"Label distribution: {np.bincount(labels)}")
    logger.info("")
    
    logger.info(f"Final Accuracy:  {final_metrics['accuracy']:.4f}")
    logger.info(f"Final Precision: {final_metrics['precision']:.4f}")
    logger.info(f"Final Recall:    {final_metrics['recall']:.4f}")
    logger.info(f"Final F1-Score:  {final_metrics['f1_score']:.4f}")
    logger.info(f"Final FNR:       {final_metrics['false_negative_rate']:.4f} ⚠️")
    logger.info(f"Final FPR:       {final_metrics['false_positive_rate']:.4f}")
    logger.info("")
    
    # Fallback: Wenn Final Evaluation schlecht ist, zeige Metriken aus training_history
    if final_metrics['accuracy'] < 0.7 and best_epoch > 0:
        logger.warning("⚠️ Final Evaluation zeigt schlechte Metriken!")
        logger.warning("Zeige Metriken aus training_history für bestes Epoch:")
        best_epoch_history = next((h for h in training_history if h['epoch'] == best_epoch), None)
        if best_epoch_history:
            logger.info(f"Epoch {best_epoch} Metrics from training:")
            logger.info(f"  Val Accuracy:  {best_epoch_history.get('accuracy', 'N/A'):.4f}")
            logger.info(f"  Val Precision: {best_epoch_history.get('precision', 'N/A'):.4f}")
            logger.info(f"  Val Recall:    {best_epoch_history.get('recall', 'N/A'):.4f}")
            logger.info(f"  Val F1-Score:  {best_epoch_history.get('f1_score', 'N/A'):.4f}")
            logger.info(f"  Val FNR:       {best_epoch_history.get('false_negative_rate', 'N/A'):.4f} ⚠️")
            logger.info(f"  Val FPR:       {best_epoch_history.get('false_positive_rate', 'N/A'):.4f}")
            logger.info("")
            logger.info("💡 Tipp: Verwende 'best_model.pt' für Production - diese Metriken sind korrekt!")
            logger.info("")
    
    # Save final model
    final_model_path = os.path.join(output_dir, 'quantum_cnn_final.pt')
    torch.save(model.state_dict(), final_model_path)
    logger.info(f"Saved final model: {final_model_path}")
    
    # Save training history (konvertiere alle numpy-Typen)
    history_path = os.path.join(output_dir, 'training_history.json')
    with open(history_path, 'w') as f:
        json.dump(convert_to_json_serializable(training_history), f, indent=2)
    logger.info(f"Saved training history: {history_path}")
    
    # Save predictions for security evaluation
    predictions_path = os.path.join(output_dir, 'predictions.jsonl')
    with open(predictions_path, 'w', encoding='utf-8') as f:
        for i, (text, label, pred, prob) in enumerate(zip(
            [item['text'] for item in val_dataset.data],
            final_metrics['labels'],
            final_metrics['predictions'],
            final_metrics['probabilities']
        )):
            f.write(json.dumps({
                'text': text,
                'label': int(label),
                'prediction': int(pred),
                'probability': float(prob)
            }, ensure_ascii=False) + '\n')
    logger.info(f"Saved predictions: {predictions_path}")
    logger.info("")
    
    logger.info("=" * 80)
    logger.info("✅ TRAINING COMPLETE")
    logger.info("=" * 80)
    
    return model, tokenizer, final_metrics


def main():
    parser = argparse.ArgumentParser(description="Train Quantum-Inspired CNN for code intent detection")
    parser.add_argument(
        "--train",
        type=str,
        default="data/train/quantum_cnn_training.jsonl",
        help="Path to training data JSONL"
    )
    parser.add_argument(
        "--val",
        type=str,
        default="data/train/quantum_cnn_training_val.jsonl",
        help="Path to validation data JSONL"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./models/quantum_cnn_trained",
        help="Output directory for trained model"
    )
    parser.add_argument(
        "--vocab_size",
        type=int,
        default=10000,
        help="Vocabulary size"
    )
    parser.add_argument(
        "--embedding_dim",
        type=int,
        default=128,
        help="Embedding dimension"
    )
    parser.add_argument(
        "--hidden_dims",
        type=int,
        nargs='+',
        default=[256, 128, 64],
        help="Hidden dimensions (hierarchical)"
    )
    parser.add_argument(
        "--kernel_sizes",
        type=int,
        nargs='+',
        default=[3, 5, 7],
        help="Kernel sizes"
    )
    parser.add_argument(
        "--dropout",
        type=float,
        default=0.3,
        help="Dropout rate (default: 0.3 for stability)"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=20,
        help="Number of training epochs"
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=8,
        help="Batch size (default: 8 for stability)"
    )
    parser.add_argument(
        "--learning_rate",
        type=float,
        default=5e-5,
        help="Learning rate (default: 5e-5 for stability)"
    )
    parser.add_argument(
        "--max_length",
        type=int,
        default=512,
        help="Maximum sequence length"
    )
    parser.add_argument(
        "--device",
        type=str,
        default=None,
        help="Device (cuda/cpu, default: auto)"
    )
    parser.add_argument(
        "--weighted_sampler",
        action="store_true",
        help="Use weighted sampler for imbalanced data"
    )
    parser.add_argument(
        "--gradient_clip",
        type=float,
        default=0.5,
        help="Gradient clipping max norm (default: 0.5 for stability)"
    )
    parser.add_argument(
        "--early_stopping_patience",
        type=int,
        default=2,
        help="Early stopping patience (stop after N epochs without improvement)"
    )
    parser.add_argument(
        "--weight_decay",
        type=float,
        default=1e-4,
        help="Weight decay for L2 regularization (default: 1e-4)"
    )
    parser.add_argument(
        "--warmup_epochs",
        type=int,
        default=3,
        help="Number of epochs for learning rate warmup (default: 3)"
    )
    parser.add_argument(
        "--use_focal_loss",
        action="store_true",
        help="Use Focal Loss instead of Class-Weighted Loss (for hard samples)"
    )
    parser.add_argument(
        "--class_weight_malicious",
        type=float,
        default=3.0,
        help="Weight for malicious class in Class-Weighted Loss (default: 3.0, range: 2.0-5.0)"
    )
    
    args = parser.parse_args()
    
    # Auto-detect device
    if args.device is None:
        args.device = 'cuda' if torch.cuda.is_available() else 'cpu'
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Train
    train_model(
        train_data_path=args.train,
        val_data_path=args.val,
        output_dir=args.output,
        vocab_size=args.vocab_size,
        embedding_dim=args.embedding_dim,
        hidden_dims=args.hidden_dims,
        kernel_sizes=args.kernel_sizes,
        dropout=args.dropout,
        num_epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        max_length=args.max_length,
        device=args.device,
        use_weighted_sampler=args.weighted_sampler,
        gradient_clip=args.gradient_clip,
        early_stopping_patience=args.early_stopping_patience,
        weight_decay=args.weight_decay,
        warmup_epochs=args.warmup_epochs,
        use_focal_loss=args.use_focal_loss,
        class_weight_malicious=args.class_weight_malicious
    )


if __name__ == "__main__":
    main()
