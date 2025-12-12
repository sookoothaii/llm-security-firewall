"""
Continual Learning für LLM Firewall
===================================

Elastic Weight Consolidation (EWC) und Synaptic Intelligence
für kontinuierliches Lernen ohne katastrophales Vergessen.

Inspiriert von Quantum ML Research (95.8% Genauigkeit).

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
License: MIT
"""

import torch
import torch.nn as nn
import numpy as np
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class TaskMemory:
    """Memory für einen Task (z.B. neue Threat-Kategorie)."""
    task_id: str
    fisher_information: Dict[str, torch.Tensor]  # F_i für EWC
    optimal_weights: Dict[str, torch.Tensor]  # theta*_i
    importance_weights: Dict[str, torch.Tensor]  # omega für Synaptic Intelligence


class ElasticWeightConsolidation:
    """
    Elastic Weight Consolidation (EWC) für Continual Learning.
    
    Verhindert katastrophales Vergessen durch Bestrafung von
    Änderungen an wichtigen Gewichten.
    """
    
    def __init__(self, lambda_ewc: float = 0.4):
        """
        Args:
            lambda_ewc: Stärke der EWC-Regularisierung
        """
        self.lambda_ewc = lambda_ewc
        self.task_memories: List[TaskMemory] = []
    
    def compute_fisher_information(
        self,
        model: nn.Module,
        dataloader: torch.utils.data.DataLoader,
        num_samples: int = 100
    ) -> Dict[str, torch.Tensor]:
        """
        Berechne Fisher Information Matrix F_i.
        
        F_i misst die Wichtigkeit jedes Parameters für Task i.
        """
        model.eval()
        fisher = {}
        
        # Initialisiere Fisher-Information
        for name, param in model.named_parameters():
            if param.requires_grad:
                fisher[name] = torch.zeros_like(param.data)
        
        # Berechne Fisher über Samples
        sample_count = 0
        for batch_idx, batch in enumerate(dataloader):
            if sample_count >= num_samples:
                break
            
            model.zero_grad()
            
            # Forward pass
            if isinstance(batch, dict):
                output = model(**batch)
            elif isinstance(batch, (list, tuple)):
                # TensorDataset returns (input_ids, labels) tuple
                input_ids = batch[0]
                output = model(input_ids)
            else:
                output = model(batch)
            
            # Backward pass (nur für Gradienten)
            if isinstance(output, torch.Tensor):
                loss = output.mean()
            else:
                loss = output.loss if hasattr(output, 'loss') else output[0]
            
            loss.backward()
            
            # Akkumuliere Fisher-Information: F_i = E[(grad_i)^2]
            for name, param in model.named_parameters():
                if param.requires_grad and param.grad is not None:
                    fisher[name] += param.grad.data ** 2
            
            sample_count += 1
        
        # Normalisiere
        for name in fisher:
            fisher[name] /= sample_count
        
        return fisher
    
    def save_task_memory(
        self,
        task_id: str,
        model: nn.Module,
        dataloader: torch.utils.data.DataLoader
    ):
        """Speichere Task-Memory für späteres EWC."""
        fisher = self.compute_fisher_information(model, dataloader)
        optimal_weights = {
            name: param.data.clone()
            for name, param in model.named_parameters()
            if param.requires_grad
        }
        
        memory = TaskMemory(
            task_id=task_id,
            fisher_information=fisher,
            optimal_weights=optimal_weights,
            importance_weights={}
        )
        
        self.task_memories.append(memory)
        logger.info(f"Saved task memory for task: {task_id}")
    
    def compute_ewc_loss(
        self,
        model: nn.Module
    ) -> torch.Tensor:
        """
        Berechne EWC-Regularisierungsterm.
        
        L_EWC = lambda * sum_i sum_k F_i^k * (theta_k - theta*_i^k)^2
        """
        if not self.task_memories:
            return torch.tensor(0.0, device=next(model.parameters()).device)
        
        ewc_loss = torch.tensor(0.0, device=next(model.parameters()).device)
        
        for memory in self.task_memories:
            for name, param in model.named_parameters():
                if name in memory.fisher_information and name in memory.optimal_weights:
                    fisher = memory.fisher_information[name]
                    optimal = memory.optimal_weights[name]
                    
                    # EWC-Term: F_i * (theta - theta*_i)^2
                    ewc_loss += (fisher * (param - optimal) ** 2).sum()
        
        return self.lambda_ewc * ewc_loss
    
    def add_to_loss(self, model: nn.Module, base_loss: torch.Tensor) -> torch.Tensor:
        """Füge EWC-Loss zum Basis-Loss hinzu."""
        ewc_loss = self.compute_ewc_loss(model)
        return base_loss + ewc_loss


class SynapticIntelligence:
    """
    Synaptic Intelligence (SI) - Alternative zu EWC.
    
    Verfolgt die Wichtigkeit von Synapsen während des Trainings.
    """
    
    def __init__(self, c: float = 0.1, xi: float = 0.1):
        """
        Args:
            c: Regularisierungsstärke
            xi: Dämpfungsparameter
        """
        self.c = c
        self.xi = xi
        self.omega: Dict[str, torch.Tensor] = {}  # Synaptic Importance
        self.theta_prev: Dict[str, torch.Tensor] = {}  # Previous weights
    
    def update_importance(
        self,
        model: nn.Module,
        loss: torch.Tensor
    ):
        """
        Update Synaptic Importance während Training.
        
        omega_k = omega_k + w_k * (dL/dw_k) * (w_k - w_k_prev)
        """
        for name, param in model.named_parameters():
            if param.requires_grad and param.grad is not None:
                if name not in self.omega:
                    self.omega[name] = torch.zeros_like(param.data)
                
                # Berechne Importance: omega += w * grad * (w - w_prev)
                if name in self.theta_prev:
                    delta = param.data - self.theta_prev[name]
                    self.omega[name] += param.grad.data.abs() * delta.abs()
                
                # Update previous weights
                self.theta_prev[name] = param.data.clone()
    
    def compute_si_loss(self, model: nn.Module) -> torch.Tensor:
        """
        Berechne SI-Regularisierungsterm.
        
        L_SI = c * sum_k omega_k * (theta_k - theta_k_prev)^2 / (xi + (theta_k - theta_k_prev)^2)
        """
        si_loss = torch.tensor(0.0, device=next(model.parameters()).device)
        
        for name, param in model.named_parameters():
            if name in self.omega and name in self.theta_prev:
                omega = self.omega[name]
                delta = param.data - self.theta_prev[name]
                
                # SI-Term: omega * delta^2 / (xi + delta^2)
                si_loss += (omega * delta ** 2 / (self.xi + delta ** 2)).sum()
        
        return self.c * si_loss
    
    def add_to_loss(self, model: nn.Module, base_loss: torch.Tensor) -> torch.Tensor:
        """Füge SI-Loss zum Basis-Loss hinzu."""
        si_loss = self.compute_si_loss(model)
        return base_loss + si_loss


class ContinualLearningTrainer:
    """
    Trainer für Continual Learning mit EWC oder SI.
    """
    
    def __init__(
        self,
        model: nn.Module,
        method: str = "ewc",  # "ewc" or "si"
        lambda_ewc: float = 0.4,
        c_si: float = 0.1
    ):
        self.model = model
        self.method = method
        
        if method == "ewc":
            self.continual_learner = ElasticWeightConsolidation(lambda_ewc=lambda_ewc)
        elif method == "si":
            self.continual_learner = SynapticIntelligence(c=c_si)
        else:
            raise ValueError(f"Unknown method: {method}")
    
    def train_task(
        self,
        task_id: str,
        train_loader: torch.utils.data.DataLoader,
        num_epochs: int = 10,
        optimizer: Optional[torch.optim.Optimizer] = None,
        device: str = "cuda"
    ):
        """
        Trainiere auf neuem Task mit Continual Learning.
        
        Args:
            task_id: Eindeutige Task-ID (z.B. "threat_category_2025_01")
            train_loader: DataLoader für neuen Task
            num_epochs: Anzahl Training-Epochs
            optimizer: Optimizer (wird erstellt falls None)
            device: Training Device
        """
        if optimizer is None:
            optimizer = torch.optim.Adam(self.model.parameters(), lr=1e-4)
        
        self.model.to(device)
        self.model.train()
        
        logger.info(f"Training task: {task_id} with {self.method}")
        
        for epoch in range(num_epochs):
            epoch_loss = 0.0
            num_batches = 0
            
            for batch in train_loader:
                optimizer.zero_grad()
                
                # Move batch to device
                if isinstance(batch, dict):
                    batch = {k: v.to(device) if isinstance(v, torch.Tensor) else v
                            for k, v in batch.items()}
                    output = self.model(**batch)
                elif isinstance(batch, (list, tuple)):
                    # TensorDataset returns (input_ids, labels) tuple
                    input_ids = batch[0].to(device)
                    labels = batch[1].to(device) if len(batch) > 1 else None
                    output = self.model(input_ids)
                else:
                    batch = batch.to(device)
                    output = self.model(batch)
                
                # Compute base loss
                if isinstance(batch, (list, tuple)) and len(batch) > 1:
                    # If we have labels, use CrossEntropyLoss
                    labels = batch[1].to(device)
                    if isinstance(output, torch.Tensor):
                        base_loss = nn.CrossEntropyLoss()(output, labels)
                    else:
                        base_loss = output.loss if hasattr(output, 'loss') else nn.CrossEntropyLoss()(output[0], labels)
                elif isinstance(output, torch.Tensor):
                    base_loss = output.mean()
                else:
                    base_loss = output.loss if hasattr(output, 'loss') else output[0]
                
                # Add continual learning regularization
                if self.method == "ewc":
                    total_loss = self.continual_learner.add_to_loss(self.model, base_loss)
                else:  # si
                    total_loss = self.continual_learner.add_to_loss(self.model, base_loss)
                    # Update importance during training
                    self.continual_learner.update_importance(self.model, base_loss)
                
                total_loss.backward()
                optimizer.step()
                
                epoch_loss += total_loss.item()
                num_batches += 1
            
            avg_loss = epoch_loss / num_batches if num_batches > 0 else 0.0
            logger.info(f"Epoch {epoch+1}/{num_epochs}, Loss: {avg_loss:.4f}")
        
        # Save task memory (for EWC)
        if self.method == "ewc":
            self.continual_learner.save_task_memory(task_id, self.model, train_loader)
        
        logger.info(f"Task {task_id} training complete")
