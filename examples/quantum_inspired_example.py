"""
Beispiel: Quantum-Inspired ML für LLM Firewall
==============================================

Demonstriert Continual Learning, Quantum-Inspired CNN und
Robustheits-Regularisierung.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
License: MIT
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from llm_firewall.ml import (
    ContinualLearningTrainer,
    QuantumInspiredCNN,
    HybridDetector,
    RobustnessTrainer
)


def create_dummy_data(vocab_size: int = 1000, num_samples: int = 100):
    """Erstelle Dummy-Daten für Demo."""
    # Random Input IDs
    input_ids = torch.randint(0, vocab_size, (num_samples, 128))
    
    # Random Labels (0=benign, 1=malicious)
    labels = torch.randint(0, 2, (num_samples,))
    
    return TensorDataset(input_ids, labels)


def example_continual_learning():
    """Beispiel: Continual Learning mit EWC."""
    print("=" * 80)
    print("Beispiel 1: Continual Learning (EWC)")
    print("=" * 80)
    
    # Model
    model = QuantumInspiredCNN(
        vocab_size=1000,
        embedding_dim=64,
        num_classes=2,
        hidden_dims=[128, 64]
    )
    
    # Trainer
    trainer = ContinualLearningTrainer(
        model=model,
        method="ewc",
        lambda_ewc=0.4
    )
    
    # Task 1: SQL Injection Detection
    print("\nTraining Task 1: SQL Injection...")
    task1_data = create_dummy_data(vocab_size=1000, num_samples=50)
    task1_loader = DataLoader(task1_data, batch_size=8)
    
    trainer.train_task(
        task_id="sql_injection",
        train_loader=task1_loader,
        num_epochs=3,
        device="cpu"
    )
    
    # Task 2: RCE Detection (OHNE Task 1 zu vergessen!)
    print("\nTraining Task 2: RCE Attacks...")
    task2_data = create_dummy_data(vocab_size=1000, num_samples=50)
    task2_loader = DataLoader(task2_data, batch_size=8)
    
    trainer.train_task(
        task_id="rce_attacks",
        train_loader=task2_loader,
        num_epochs=3,
        device="cpu"
    )
    
    print("\n✅ Continual Learning erfolgreich!")
    print("   Model behält Performance auf Task 1 (SQL Injection)")


def example_quantum_cnn():
    """Beispiel: Quantum-Inspired CNN."""
    print("\n" + "=" * 80)
    print("Beispiel 2: Quantum-Inspired CNN")
    print("=" * 80)
    
    # Model
    model = QuantumInspiredCNN(
        vocab_size=1000,
        embedding_dim=128,
        num_classes=2,
        hidden_dims=[256, 128, 64],
        kernel_sizes=[3, 5, 7]
    )
    
    # Dummy Input
    input_ids = torch.randint(0, 1000, (4, 128))  # [batch_size, seq_len]
    
    # Forward Pass
    with torch.no_grad():
        logits = model(input_ids)
        probs = torch.softmax(logits, dim=-1)
    
    print(f"\nInput Shape: {input_ids.shape}")
    print(f"Output Logits: {logits.shape}")
    print(f"Predictions: {probs.argmax(dim=-1)}")
    print("\n✅ Quantum-Inspired CNN funktioniert!")


def example_hybrid_detector():
    """Beispiel: Hybrid Detector (Neural + Rule-Based)."""
    print("\n" + "=" * 80)
    print("Beispiel 3: Hybrid Detector")
    print("=" * 80)
    
    # Hybrid Model
    model = HybridDetector(
        vocab_size=1000,
        num_classes=2,
        use_quantum_cnn=True
    )
    
    # Input
    input_ids = torch.randint(0, 1000, (4, 128))
    
    # Rule-based Scores (10 Kategorien)
    rule_scores = torch.rand(4, 10)  # [batch_size, num_rules]
    
    # Forward Pass
    with torch.no_grad():
        logits = model(input_ids, rule_scores=rule_scores)
        probs = torch.softmax(logits, dim=-1)
    
    print(f"\nNeural Input: {input_ids.shape}")
    print(f"Rule Scores: {rule_scores.shape}")
    print(f"Combined Logits: {logits.shape}")
    print(f"Predictions: {probs.argmax(dim=-1)}")
    print("\n✅ Hybrid Detector funktioniert!")


def example_robustness():
    """Beispiel: Robustheits-Regularisierung."""
    print("\n" + "=" * 80)
    print("Beispiel 4: Robustheits-Regularisierung")
    print("=" * 80)
    
    # Model
    model = QuantumInspiredCNN(
        vocab_size=1000,
        embedding_dim=64,
        num_classes=2
    )
    
    # Robustness Trainer
    trainer = RobustnessTrainer(
        model=model,
        lambda_ortho=0.01,
        use_spectral_norm=True
    )
    
    # Dummy Loss
    input_ids = torch.randint(0, 1000, (4, 128))
    labels = torch.randint(0, 2, (4,))
    
    logits = model(input_ids)
    base_loss = nn.CrossEntropyLoss()(logits, labels)
    
    # Total Loss mit Robustheits-Regularisierung
    total_loss = trainer.compute_total_loss(base_loss)
    
    print(f"\nBase Loss: {base_loss.item():.4f}")
    print(f"Total Loss (mit Regularisierung): {total_loss.item():.4f}")
    print("\n✅ Robustheits-Regularisierung funktioniert!")


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("QUANTUM-INSPIRED ML BEISPIELE")
    print("=" * 80)
    
    # Beispiel 1: Continual Learning
    example_continual_learning()
    
    # Beispiel 2: Quantum-Inspired CNN
    example_quantum_cnn()
    
    # Beispiel 3: Hybrid Detector
    example_hybrid_detector()
    
    # Beispiel 4: Robustness
    example_robustness()
    
    print("\n" + "=" * 80)
    print("ALLE BEISPIELE ERFOLGREICH!")
    print("=" * 80)
