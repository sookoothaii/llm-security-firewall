"""
Quantum-Inspired Neural Architectures
======================================

QCNN-inspirierte hierarchische Architekturen zur Vermeidung
flacher Gradienten (Barren Plateaus).

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
License: MIT
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class HierarchicalBlock(nn.Module):
    """
    Hierarchischer Block (inspiriert von MERA-Struktur in QCNNs).
    
    Fördert lokale Wechselwirkungen und schrittweise Feature-Aggregation.
    """
    
    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        kernel_size: int = 3,
        stride: int = 1,
        depth: int = 2
    ):
        """
        Args:
            in_channels: Eingangs-Channels
            out_channels: Ausgangs-Channels
            kernel_size: Kernel-Größe
            stride: Stride
            depth: Tiefe der Hierarchie (mehr = tiefer, schmaler)
        """
        super().__init__()
        self.depth = depth
        
        # Hierarchische Schichten (tief und schmal)
        layers = []
        current_channels = in_channels
        
        for i in range(depth):
            # Jede Schicht reduziert Channels schrittweise
            next_channels = out_channels if i == depth - 1 else (current_channels + out_channels) // 2
            
            layers.append(nn.Conv1d(
                current_channels,
                next_channels,
                kernel_size=kernel_size,
                stride=stride,
                padding=kernel_size // 2
            ))
            layers.append(nn.BatchNorm1d(next_channels))
            layers.append(nn.ReLU())
            
            current_channels = next_channels
        
        self.layers = nn.Sequential(*layers)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass mit hierarchischer Verarbeitung."""
        return self.layers(x)


class QuantumInspiredCNN(nn.Module):
    """
    Quantum-Inspired CNN für Code/Text-Klassifikation.
    
    Architektur:
    - Tiefe, schmale, hierarchische Struktur (wie QCNN)
    - Vermeidet Barren Plateaus durch lokale Wechselwirkungen
    - Schrittweise Feature-Aggregation
    """
    
    def __init__(
        self,
        vocab_size: int,
        embedding_dim: int = 128,
        num_classes: int = 2,
        hidden_dims: List[int] = [256, 128, 64],
        kernel_sizes: List[int] = [3, 5, 7],
        dropout: float = 0.2
    ):
        """
        Args:
            vocab_size: Vokabular-Größe
            embedding_dim: Embedding-Dimension
            num_classes: Anzahl Klassen (z.B. malicious/benign)
            hidden_dims: Hidden-Dimensionen (hierarchisch absteigend)
            kernel_sizes: Kernel-Größen für verschiedene Skalen
            dropout: Dropout-Rate
        """
        super().__init__()
        
        # Embedding Layer
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        
        # Hierarchische Convolutional Blocks (wie QCNN)
        self.conv_blocks = nn.ModuleList()
        current_dim = embedding_dim
        
        for hidden_dim, kernel_size in zip(hidden_dims, kernel_sizes):
            block = HierarchicalBlock(
                in_channels=current_dim,
                out_channels=hidden_dim,
                kernel_size=kernel_size,
                depth=2  # Tiefe Hierarchie
            )
            self.conv_blocks.append(block)
            current_dim = hidden_dim
        
        # Global Pooling (wie in QCNN)
        self.global_pool = nn.AdaptiveAvgPool1d(1)
        
        # Classification Head
        self.classifier = nn.Sequential(
            nn.Linear(current_dim, current_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(current_dim // 2, num_classes)
        )
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass mit hierarchischer Feature-Extraktion.
        
        Args:
            x: Input Tensor [batch_size, seq_len]
        
        Returns:
            Logits [batch_size, num_classes]
        """
        # Embedding
        x = self.embedding(x)  # [batch, seq_len, embedding_dim]
        x = x.transpose(1, 2)  # [batch, embedding_dim, seq_len]
        
        # Hierarchische Convolutional Blocks
        for block in self.conv_blocks:
            x = block(x)  # Schrittweise Feature-Aggregation
        
        # Global Pooling
        x = self.global_pool(x)  # [batch, hidden_dim, 1]
        x = x.squeeze(-1)  # [batch, hidden_dim]
        
        # Classification
        logits = self.classifier(x)
        
        return logits


class DeepFeatureTower(nn.Module):
    """
    Deep Feature Tower für fortgeschrittene Daten-Kodierung.
    
    Inspiriert von "Data Re-uploading" in Quantum ML.
    Wiederholte, nicht-lineare Feature-Transformationen.
    """
    
    def __init__(
        self,
        input_dim: int,
        hidden_dims: List[int] = [256, 512, 256, 128],
        num_layers: int = 4,
        dropout: float = 0.1
    ):
        """
        Args:
            input_dim: Eingangs-Dimension
            hidden_dims: Hidden-Dimensionen für jeden Layer
            num_layers: Anzahl Transformationen
            dropout: Dropout-Rate
        """
        super().__init__()
        
        self.layers = nn.ModuleList()
        current_dim = input_dim
        
        for i in range(num_layers):
            hidden_dim = hidden_dims[i] if i < len(hidden_dims) else hidden_dims[-1]
            
            # Transformation mit Residual Connection
            layer = nn.Sequential(
                nn.Linear(current_dim, hidden_dim),
                nn.LayerNorm(hidden_dim),
                nn.GELU(),  # Nicht-lineare Aktivierung
                nn.Dropout(dropout)
            )
            self.layers.append(layer)
            
            # Residual connection (wenn Dimensionen passen)
            if current_dim == hidden_dim:
                self.use_residual = True
            else:
                self.use_residual = False
            
            current_dim = hidden_dim
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass mit wiederholten Transformationen.
        
        Args:
            x: Input Tensor [batch_size, input_dim]
        
        Returns:
            Encoded Features [batch_size, output_dim]
        """
        for layer in self.layers:
            x_new = layer(x)
            
            # Residual connection
            if self.use_residual and x.shape == x_new.shape:
                x = x + x_new
            else:
                x = x_new
        
        return x


class HybridDetector(nn.Module):
    """
    Hybrid Detector: Quantum-Inspired CNN + Rule-Based.
    
    Kombiniert parametrisiertes neuronales Netz mit
    regelbasiertem System (wie VQA).
    """
    
    def __init__(
        self,
        vocab_size: int,
        num_classes: int = 2,
        use_quantum_cnn: bool = True
    ):
        """
        Args:
            vocab_size: Vokabular-Größe
            num_classes: Anzahl Klassen
            use_quantum_cnn: Verwende Quantum-Inspired CNN
        """
        super().__init__()
        
        if use_quantum_cnn:
            self.neural_detector = QuantumInspiredCNN(
                vocab_size=vocab_size,
                num_classes=num_classes
            )
        else:
            # Standard CNN als Fallback
            self.neural_detector = nn.Sequential(
                nn.Embedding(vocab_size, 128),
                nn.Conv1d(128, 64, kernel_size=3),
                nn.ReLU(),
                nn.AdaptiveAvgPool1d(1),
                nn.Flatten(),
                nn.Linear(64, num_classes)
            )
        
        # Rule-based weights (werden von NN optimiert)
        self.rule_weights = nn.Parameter(torch.ones(10))  # 10 Regel-Kategorien
    
    def forward(
        self,
        x: torch.Tensor,
        rule_scores: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Forward pass: Kombiniere Neural + Rule-based.
        
        Args:
            x: Input Tensor [batch_size, seq_len]
            rule_scores: Rule-based Scores [batch_size, num_rules]
        
        Returns:
            Combined Logits [batch_size, num_classes]
        """
        # Neural Network Prediction
        neural_logits = self.neural_detector(x)
        
        # Rule-based Component (wenn verfügbar)
        if rule_scores is not None:
            # Weighted rule scores
            weighted_rules = rule_scores * self.rule_weights.unsqueeze(0)
            rule_contribution = weighted_rules.sum(dim=1, keepdim=True)
            
            # Combine: neural + rule-based
            combined_logits = neural_logits + rule_contribution
        else:
            combined_logits = neural_logits
        
        return combined_logits
