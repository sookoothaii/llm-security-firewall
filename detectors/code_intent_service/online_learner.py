"""
Online Learning für Code Intent Detector
=========================================

Kontinuierliches Lernen aus Feedback Samples (Risk/Rule Scores)
"""

import torch
import torch.nn as nn
from typing import Dict, List, Optional, Protocol
from collections import deque
import logging
from datetime import datetime
import os

logger = logging.getLogger(__name__)

# Import FeedbackRepositoryPort for type hints
try:
    from domain.services.ports import FeedbackRepositoryPort
except ImportError:
    # Fallback if not available
    FeedbackRepositoryPort = Protocol


def generate_label(sample: Dict, strategy: str = "adaptive") -> float:
    """
    Generiere Training Label basierend auf Strategie.
    
    Args:
        sample: Feedback Sample mit rule_score, ml_score, final_score, detector_method
        strategy: "final_score", "rule_score", "soft_labels", "adaptive"
    
    Returns:
        Training label [0.0, 1.0]
    """
    rule_score = sample.get("rule_score", 0.0)
    ml_score = sample.get("ml_score", 0.0)
    final_score = sample.get("final_score", 0.0)
    detector_method = sample.get("detector_method", "")
    
    if strategy == "final_score":
        # Strategie A: Final Score als Target
        return final_score
    
    elif strategy == "rule_score":
        # Strategie B: Rule Score wenn Rule Priority
        if detector_method.startswith("rule_engine"):
            return rule_score
        else:
            return final_score
    
    elif strategy == "soft_labels":
        # Strategie C: Soft Labels (Ensemble)
        return 0.6 * rule_score + 0.4 * ml_score
    
    elif strategy == "adaptive":
        # Strategie D: Adaptive Weighting
        weights = {
            "rule_engine_high_confidence": 0.9,
            "ml_model_multilingual_attack": 0.7,
            "ml_model_high_score_conservative": 0.5,
            "ml_model_social_engineering": 0.6,
            "rule_engine_benign": 0.1,
        }
        weight = weights.get(detector_method, 0.6)
        return weight * rule_score + (1 - weight) * ml_score
    
    else:
        return final_score


class OnlineLearner:
    """
    Online Learning für kontinuierliches Training.
    
    Führt inkrementelles Training mit kleinen Batches durch.
    """
    
    def __init__(
        self,
        model: nn.Module,
        tokenizer,
        learning_rate: float = 1e-5,
        device: str = "cpu"
    ):
        """
        Args:
            model: PyTorch Model (Quantum-Inspired CNN)
            tokenizer: Tokenizer für Text
            learning_rate: Learning Rate für Online Learning (sehr klein)
            device: Training Device
        """
        self.model = model
        self.tokenizer = tokenizer
        self.learning_rate = learning_rate
        self.device = device
        
        # Optimizer (sehr kleine Learning Rate für Online Learning)
        self.optimizer = torch.optim.Adam(
            model.parameters(),
            lr=learning_rate,
            weight_decay=1e-4
        )
        
        # Loss Function (MSE für Regression)
        self.criterion = nn.MSELoss()
        
        # Statistics
        self.stats = {
            "updates": 0,
            "total_loss": 0.0,
            "last_update": None
        }
        
        logger.info(f"OnlineLearner initialized (lr={learning_rate}, device={device})")
    
    def update(self, batch: List[Dict]) -> float:
        """
        Update model with batch of feedback samples.
        
        Args:
            batch: List of feedback samples with 'text' and 'target_label'
        
        Returns:
            Average loss
        """
        if not batch:
            return 0.0
        
        self.model.train()
        self.model.to(self.device)
        
        # Prepare data
        texts = [s["text"] for s in batch]
        targets = torch.tensor(
            [s["target_label"] for s in batch],
            dtype=torch.float32,
            device=self.device
        )
        
        # Tokenize
        try:
            tokenized = self.tokenizer(
                texts,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=512
            )
            input_ids = tokenized["input_ids"].to(self.device)
        except Exception as e:
            logger.error(f"Tokenization failed: {e}")
            return 0.0
        
        # Forward pass
        try:
            with torch.set_grad_enabled(True):
                outputs = self.model(input_ids)
                
                # Get malicious class probability
                if isinstance(outputs, torch.Tensor):
                    # Direct logits
                    probs = torch.softmax(outputs, dim=-1)
                    predictions = probs[:, 1]  # Malicious class
                else:
                    # Model returns dict or tuple
                    if hasattr(outputs, 'logits'):
                        probs = torch.softmax(outputs.logits, dim=-1)
                        predictions = probs[:, 1]
                    else:
                        logger.error("Unknown model output format")
                        return 0.0
                
                # Loss
                loss = self.criterion(predictions, targets)
                
                # Backward pass
                self.optimizer.zero_grad()
                loss.backward()
                
                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                
                # Update
                self.optimizer.step()
                
                # Update statistics
                loss_value = loss.item()
                self.stats["updates"] += 1
                self.stats["total_loss"] += loss_value
                self.stats["last_update"] = datetime.now().isoformat()
                
                logger.info(f"Online learning update: loss={loss_value:.4f}, batch_size={len(batch)}")
                
                return loss_value
                
        except Exception as e:
            logger.error(f"Online learning update failed: {e}")
            import traceback
            traceback.print_exc()
            return 0.0
    
    def get_statistics(self) -> Dict:
        """Get learning statistics."""
        avg_loss = (
            self.stats["total_loss"] / self.stats["updates"]
            if self.stats["updates"] > 0
            else 0.0
        )
        return {
            **self.stats,
            "average_loss": avg_loss
        }


class BackgroundLearner:
    """
    Background Task für kontinuierliches Online Learning.
    
    Läuft in separatem Thread/Process und trainiert periodisch.
    Unterstützt sowohl FeedbackBuffer als auch FeedbackRepositoryPort.
    """
    
    def __init__(
        self,
        feedback_source,  # FeedbackBuffer oder FeedbackRepositoryPort
        model: nn.Module,
        tokenizer,
        batch_size: int = 32,
        update_interval: int = 100,  # Update alle N Samples
        min_samples: int = 10,  # Minimum Samples für Update
        learning_rate: float = 1e-5,
        device: str = "cpu"
    ):
        """
        Args:
            feedback_source: FeedbackBuffer Instanz oder FeedbackRepositoryPort
            model: PyTorch Model
            tokenizer: Tokenizer
            batch_size: Batch Size für Training
            update_interval: Update alle N neuen Samples
            min_samples: Minimum Samples im Buffer für Update
            learning_rate: Learning Rate
            device: Training Device
        """
        self.feedback_source = feedback_source
        self.learner = OnlineLearner(model, tokenizer, learning_rate, device)
        self.batch_size = batch_size
        self.update_interval = update_interval
        self.min_samples = min_samples
        self.running = False
        self.last_buffer_size = 0
        
        # Check if it's a FeedbackRepositoryPort or old FeedbackBuffer
        self.is_repository = hasattr(feedback_source, 'get_samples') and not hasattr(feedback_source, 'get_training_batch')
        
        logger.info(
            f"BackgroundLearner initialized: "
            f"batch_size={batch_size}, update_interval={update_interval}, "
            f"min_samples={min_samples}, is_repository={self.is_repository}"
        )
    
    def _get_buffer_size(self) -> int:
        """Get current buffer/repository size."""
        if self.is_repository:
            # For FeedbackRepositoryPort, get statistics
            try:
                stats = self.feedback_source.get_statistics()
                # Handle different stat formats
                if isinstance(stats, dict):
                    if "combined" in stats:
                        return stats["combined"].get("total_samples", 0)
                    return stats.get("total_samples", 0)
                return 0
            except Exception as e:
                logger.warning(f"Failed to get repository size: {e}")
                return 0
        else:
            # Old FeedbackBuffer format
            return len(self.feedback_source.buffer)
    
    def _get_training_batch(self) -> List[Dict]:
        """Get training batch from feedback source."""
        if self.is_repository:
            # Use FeedbackRepositoryPort.get_samples()
            try:
                samples = self.feedback_source.get_samples(limit=self.batch_size * 2)
                # Prioritize high-risk and false positives/negatives
                # Sort by final_score (descending) to prioritize important samples
                samples.sort(key=lambda x: x.get("final_score", 0.0), reverse=True)
                return samples[:self.batch_size]
            except Exception as e:
                logger.error(f"Failed to get samples from repository: {e}")
                return []
        else:
            # Old FeedbackBuffer format
            if hasattr(self.feedback_source, 'get_training_batch'):
                return self.feedback_source.get_training_batch(self.batch_size)
            else:
                # Fallback: get samples and take first batch_size
                samples = self.feedback_source.get_samples(limit=self.batch_size * 2)
                return samples[:self.batch_size]
    
    def start(self):
        """Start background learning loop (blocking)."""
        import time
        
        self.running = True
        logger.info("Background learning started")
        
        while self.running:
            try:
                current_size = self._get_buffer_size()
                
                # Check if we have enough new samples
                new_samples = current_size - self.last_buffer_size
                
                # ENHANCED FIX 2025-12-09: Trainiere auch wenn Buffer groß genug ist,
                # auch wenn nicht genug neue Samples hinzugekommen sind
                # Dies ermöglicht kontinuierliches Lernen auch bei stabiler Sample-Rate
                should_train = (
                    current_size >= self.min_samples and 
                    (new_samples >= self.update_interval or 
                     (current_size >= self.min_samples * 2 and self.last_buffer_size == 0))  # Initial training wenn Buffer groß genug
                )
                
                if should_train:
                    # Get training batch
                    batch = self._get_training_batch()
                    
                    if batch:
                        # Generate labels
                        for sample in batch:
                            sample["target_label"] = generate_label(sample, strategy="adaptive")
                        
                        # Update model
                        loss = self.learner.update(batch)
                        
                        logger.info(
                            f"Background learning: updated with {len(batch)} samples, "
                            f"loss={loss:.4f}, buffer_size={current_size}"
                        )
                    
                    self.last_buffer_size = current_size
                
                # Sleep for 60 seconds
                time.sleep(60)
                
            except KeyboardInterrupt:
                logger.info("Background learning stopped by user")
                self.running = False
                break
            except Exception as e:
                logger.error(f"Background learning error: {e}")
                import traceback
                traceback.print_exc()
                time.sleep(60)  # Wait before retry
    
    def stop(self):
        """Stop background learning."""
        self.running = False
        logger.info("Background learning stopped")
    
    def get_statistics(self) -> Dict:
        """Get learning statistics."""
        current_size = self._get_buffer_size()
        return {
            "running": self.running,
            "buffer_size": current_size,
            "last_buffer_size": self.last_buffer_size,
            "learner_stats": self.learner.get_statistics(),
            "is_repository": self.is_repository
        }

