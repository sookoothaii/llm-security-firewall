"""
Robustheit durch Regularisierung
=================================

Unitäre Constraints und Orthogonalitäts-Strafen
für langfristige Anpassungsfähigkeit.

Inspiriert von Unitären Beschränkungen in Quantenschaltungen.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
License: MIT
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)


class OrthogonalRegularizer:
    """
    Orthogonalitäts-Regularisierung für Gewichtsmatrizen.
    
    Verhindert "Gewichts-Drift" und erhält Plastizität
    (inspiriert von unitären Constraints).
    """
    
    def __init__(self, lambda_ortho: float = 0.01):
        """
        Args:
            lambda_ortho: Stärke der Orthogonalitäts-Strafe
        """
        self.lambda_ortho = lambda_ortho
    
    def compute_orthogonal_loss(self, weight: torch.Tensor) -> torch.Tensor:
        """
        Berechne Orthogonalitäts-Strafe.
        
        Strafe: ||W^T W - I||_F^2
        (Frobenius-Norm der Abweichung von Identität)
        
        Args:
            weight: Gewichtsmatrix [out_features, in_features]
        
        Returns:
            Orthogonalitäts-Loss (Skalar)
        """
        # Nur für 2D-Matrizen
        if weight.dim() != 2:
            return torch.tensor(0.0, device=weight.device)
        
        out_features, in_features = weight.shape
        
        # Wenn Matrix nicht quadratisch, verwende reduzierte Form
        if out_features > in_features:
            # Verwende W W^T statt W^T W
            WWT = torch.mm(weight, weight.t())
            I = torch.eye(out_features, device=weight.device)
            loss = F.mse_loss(WWT, I)
        else:
            # Standard: W^T W
            WTW = torch.mm(weight.t(), weight)
            I = torch.eye(in_features, device=weight.device)
            loss = F.mse_loss(WTW, I)
        
        return self.lambda_ortho * loss
    
    def add_to_loss(
        self,
        model: nn.Module,
        base_loss: torch.Tensor,
        layer_names: Optional[list] = None
    ) -> torch.Tensor:
        """
        Füge Orthogonalitäts-Strafe zu allen Linear-Layern hinzu.
        
        Args:
            model: PyTorch Model
            base_loss: Basis-Loss
            layer_names: Optionale Liste von Layer-Namen (wenn None, alle Linear-Layer)
        
        Returns:
            Total Loss mit Orthogonalitäts-Strafe
        """
        total_ortho_loss = torch.tensor(0.0, device=base_loss.device)
        
        for name, module in model.named_modules():
            if isinstance(module, nn.Linear):
                # Prüfe ob Layer in Liste (falls angegeben)
                if layer_names is None or name in layer_names:
                    ortho_loss = self.compute_orthogonal_loss(module.weight)
                    total_ortho_loss += ortho_loss
        
        return base_loss + total_ortho_loss


class SpectralNormalization(nn.Module):
    """
    Spectral Normalization für Stabilität.
    
    Begrenzt die Lipschitz-Konstante des Layers.
    """
    
    def __init__(self, module: nn.Module, power_iterations: int = 1):
        """
        Args:
            module: Layer (z.B. nn.Linear, nn.Conv1d)
            power_iterations: Anzahl Power-Iterationen für Spektralnorm
        """
        super().__init__()
        self.module = module
        self.power_iterations = power_iterations
        
        # Registriere weight als Parameter
        if hasattr(module, 'weight'):
            weight = module.weight
            height = weight.shape[0]
            width = weight.view(height, -1).shape[1]
            
            # Initialisiere u und v für Power Iteration
            u = F.normalize(weight.new_empty(height).normal_(0, 1), dim=0)
            v = F.normalize(weight.new_empty(width).normal_(0, 1), dim=0)
            
            self.register_buffer('u', u)
            self.register_buffer('v', v)
    
    def compute_spectral_norm(self) -> torch.Tensor:
        """Berechne Spektralnorm mit Power Iteration."""
        weight = self.module.weight
        height = weight.shape[0]
        weight_matrix = weight.view(height, -1)
        
        u = self.u
        v = self.v
        
        # Power Iteration
        for _ in range(self.power_iterations):
            v = F.normalize(torch.mv(weight_matrix.t(), u), dim=0)
            u = F.normalize(torch.mv(weight_matrix, v), dim=0)
        
        # Spektralnorm: u^T W v
        sigma = torch.dot(u, torch.mv(weight_matrix, v))
        
        return sigma
    
    def forward(self, *args, **kwargs):
        """Forward pass mit spektral-normalisiertem Gewicht."""
        # Temporär normiere Gewicht
        sigma = self.compute_spectral_norm()
        if sigma > 1.0:
            self.module.weight.data /= sigma
        
        return self.module(*args, **kwargs)


def apply_spectral_normalization(model: nn.Module) -> nn.Module:
    """
    Wende Spectral Normalization auf alle Linear/Conv-Layer an.
    
    Args:
        model: PyTorch Model
    
    Returns:
        Model mit Spectral Normalization
    """
    for name, module in model.named_children():
        if isinstance(module, (nn.Linear, nn.Conv1d, nn.Conv2d)):
            # Ersetze Layer mit Spectral-Normalized Version
            setattr(model, name, SpectralNormalization(module))
        else:
            # Rekursiv für Sub-Module
            apply_spectral_normalization(module)
    
    return model


class RobustnessTrainer:
    """
    Trainer mit Robustheits-Regularisierung.
    """
    
    def __init__(
        self,
        model: nn.Module,
        lambda_ortho: float = 0.01,
        use_spectral_norm: bool = True
    ):
        """
        Args:
            model: PyTorch Model
            lambda_ortho: Stärke der Orthogonalitäts-Strafe
            use_spectral_norm: Verwende Spectral Normalization
        """
        self.model = model
        self.ortho_regularizer = OrthogonalRegularizer(lambda_ortho=lambda_ortho)
        
        if use_spectral_norm:
            self.model = apply_spectral_normalization(self.model)
            logger.info("Applied Spectral Normalization to model")
    
    def compute_total_loss(
        self,
        base_loss: torch.Tensor,
        layer_names: Optional[list] = None
    ) -> torch.Tensor:
        """
        Berechne Total Loss mit Robustheits-Regularisierung.
        
        Args:
            base_loss: Basis-Loss (z.B. CrossEntropy)
            layer_names: Optionale Liste von Layer-Namen für Ortho-Strafe
        
        Returns:
            Total Loss
        """
        total_loss = self.ortho_regularizer.add_to_loss(
            self.model,
            base_loss,
            layer_names=layer_names
        )
        
        return total_loss
