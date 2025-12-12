"""
Continual Learning Feedback Loop
=================================

Integriert Continual Learning in produktiven Detector-Lebenszyklus.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import torch
import torch.nn as nn
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

from llm_firewall.ml.continual_learning import ContinualLearningTrainer

logger = logging.getLogger(__name__)


@dataclass
class FeedbackEntry:
    """Einzelnes Feedback-Eintrag."""
    text: str
    correct_label: int  # 0=benign, 1=malicious
    original_prediction: float  # Original risk score
    timestamp: str
    feedback_type: str  # "false_positive", "false_negative", "correction"
    user_id: Optional[str] = None


class ContinualLearningFeedbackLoop:
    """
    Continual Learning Feedback Loop für produktive Nutzung.
    
    Lässt Detektoren aus Blocked-Requests und False-Positives lernen.
    """
    
    def __init__(
        self,
        model: nn.Module,
        trainer: ContinualLearningTrainer,
        feedback_buffer_size: int = 100,
        min_feedback_for_training: int = 10
    ):
        """
        Args:
            model: PyTorch Model
            trainer: ContinualLearningTrainer
            feedback_buffer_size: Max Feedback-Einträge vor Training
            min_feedback_for_training: Minimum Feedback für Training
        """
        self.model = model
        self.trainer = trainer
        self.feedback_buffer: List[FeedbackEntry] = []
        self.feedback_buffer_size = feedback_buffer_size
        self.min_feedback_for_training = min_feedback_for_training
        
        # Statistics
        self.stats = {
            "total_feedback": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "corrections": 0,
            "training_sessions": 0
        }
    
    def add_feedback(
        self,
        text: str,
        correct_label: int,
        original_prediction: float,
        feedback_type: str = "correction",
        user_id: Optional[str] = None
    ):
        """
        Füge Feedback hinzu.
        
        Args:
            text: Input text
            correct_label: Korrekte Label (0=benign, 1=malicious)
            original_prediction: Originale Vorhersage
            feedback_type: "false_positive", "false_negative", "correction"
            user_id: Optional user ID
        """
        entry = FeedbackEntry(
            text=text,
            correct_label=correct_label,
            original_prediction=original_prediction,
            timestamp=datetime.now().isoformat(),
            feedback_type=feedback_type,
            user_id=user_id
        )
        
        self.feedback_buffer.append(entry)
        self.stats["total_feedback"] += 1
        
        if feedback_type == "false_positive":
            self.stats["false_positives"] += 1
        elif feedback_type == "false_negative":
            self.stats["false_negatives"] += 1
        else:
            self.stats["corrections"] += 1
        
        # Check if we should train
        if len(self.feedback_buffer) >= self.min_feedback_for_training:
            self._trigger_training()
    
    def _trigger_training(self):
        """Trigger Training wenn genug Feedback vorhanden."""
        if len(self.feedback_buffer) < self.min_feedback_for_training:
            return
        
        logger.info(f"Triggering continual learning training with {len(self.feedback_buffer)} feedback entries")
        
        # Prepare training data
        from torch.utils.data import DataLoader, TensorDataset
        import torch
        
        # Simple tokenization (in production: use proper tokenizer)
        input_ids_list = []
        labels_list = []
        
        for entry in self.feedback_buffer:
            # Simple encoding (character-based)
            token_ids = [ord(c) % 10000 for c in entry.text[:128]]
            while len(token_ids) < 128:
                token_ids.append(0)
            input_ids_list.append(token_ids[:128])
            labels_list.append(entry.correct_label)
        
        # Create dataset
        input_ids_tensor = torch.tensor(input_ids_list, dtype=torch.long)
        labels_tensor = torch.tensor(labels_list, dtype=torch.long)
        dataset = TensorDataset(input_ids_tensor, labels_tensor)
        dataloader = DataLoader(dataset, batch_size=min(8, len(dataset)))
        
        # Train with continual learning
        task_id = f"feedback_batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            self.trainer.train_task(
                task_id=task_id,
                train_loader=dataloader,
                num_epochs=3,  # Few epochs for incremental learning
                device="cpu"  # Use CPU for now
            )
            
            self.stats["training_sessions"] += 1
            logger.info(f"Continual learning training complete for task: {task_id}")
            
            # Clear buffer (keep last few for next batch)
            keep_count = min(10, len(self.feedback_buffer) // 2)
            self.feedback_buffer = self.feedback_buffer[-keep_count:]
            
        except Exception as e:
            logger.error(f"Continual learning training failed: {e}")
    
    def adapt_from_feedback(
        self,
        text: str,
        correct_label: int,
        original_prediction: float,
        feedback_type: str = "correction"
    ):
        """
        Adaptiere Modell basierend auf Feedback.
        
        Alias für add_feedback mit automatischem Training.
        """
        self.add_feedback(text, correct_label, original_prediction, feedback_type)
    
    def get_statistics(self) -> Dict[str, any]:
        """Get feedback statistics."""
        return {
            **self.stats,
            "buffer_size": len(self.feedback_buffer),
            "ready_for_training": len(self.feedback_buffer) >= self.min_feedback_for_training
        }
    
    def export_feedback(self, output_path: str):
        """Exportiere Feedback-Buffer für Analyse."""
        import json
        
        feedback_data = [
            {
                "text": entry.text,
                "correct_label": entry.correct_label,
                "original_prediction": entry.original_prediction,
                "timestamp": entry.timestamp,
                "feedback_type": entry.feedback_type,
                "user_id": entry.user_id
            }
            for entry in self.feedback_buffer
        ]
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(feedback_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(feedback_data)} feedback entries to {output_path}")


class FeedbackInterface:
    """
    Einfaches Feedback-Interface für manuelle Korrekturen.
    
    Kann von CLI, Dashboard oder API verwendet werden.
    """
    
    def __init__(self, feedback_loop: ContinualLearningFeedbackLoop):
        self.feedback_loop = feedback_loop
    
    def mark_false_positive(self, text: str, original_prediction: float, user_id: Optional[str] = None):
        """Markiere als False Positive (blockiert, aber sollte erlaubt sein)."""
        self.feedback_loop.add_feedback(
            text=text,
            correct_label=0,  # Benign
            original_prediction=original_prediction,
            feedback_type="false_positive",
            user_id=user_id
        )
        logger.info(f"Marked as false positive: {text[:50]}...")
    
    def mark_false_negative(self, text: str, original_prediction: float, user_id: Optional[str] = None):
        """Markiere als False Negative (erlaubt, aber sollte blockiert sein)."""
        self.feedback_loop.add_feedback(
            text=text,
            correct_label=1,  # Malicious
            original_prediction=original_prediction,
            feedback_type="false_negative",
            user_id=user_id
        )
        logger.info(f"Marked as false negative: {text[:50]}...")
    
    def correct_prediction(self, text: str, correct_label: int, original_prediction: float, user_id: Optional[str] = None):
        """Manuelle Korrektur."""
        self.feedback_loop.add_feedback(
            text=text,
            correct_label=correct_label,
            original_prediction=original_prediction,
            feedback_type="correction",
            user_id=user_id
        )
        logger.info(f"Corrected prediction for: {text[:50]}...")
