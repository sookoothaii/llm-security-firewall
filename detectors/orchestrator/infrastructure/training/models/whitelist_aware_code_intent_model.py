"""
WhitelistAwareCodeIntentModel - V3 Whitelist-Learner Architecture

Self-Explaining Whitelist Model mit learnable Pattern Embeddings.

Architecture:
- CodeBERT Base Encoder
- Learnable Whitelist Pattern Embeddings
- Multi-Task Learning (Classification + Pattern Matching + V2.1 Imitation)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class WhitelistAwareCodeIntentModel(nn.Module):
    """
    Whitelist-Aware Code Intent Detection Model.
    
    Features:
    - CodeBERT Base Encoder
    - Learnable Whitelist Pattern Embeddings
    - Multi-Task Learning Support
    - Interpretable Whitelist Decisions
    """
    
    def __init__(
        self,
        base_model_name: str = "microsoft/codebert-base",
        num_patterns: int = 4,
        pattern_dim: int = 768,
        hidden_dim: int = 256,
        dropout: float = 0.2,
        freeze_encoder: bool = False
    ):
        """
        Initialize WhitelistAwareCodeIntentModel.
        
        Args:
            base_model_name: HuggingFace model name for CodeBERT
            num_patterns: Number of whitelist patterns (default: 4)
            pattern_dim: Dimension of pattern embeddings (default: 768)
            hidden_dim: Hidden dimension for classifier
            dropout: Dropout rate
            freeze_encoder: If True, freeze CodeBERT encoder
        """
        super().__init__()
        
        self.num_patterns = num_patterns
        self.pattern_dim = pattern_dim
        self.hidden_dim = hidden_dim
        
        # 1. CodeBERT Base Encoder
        try:
            from transformers import AutoModel, AutoTokenizer
            import os
            
            # Workaround für PyTorch < 2.6: Nutze safetensors wenn verfügbar
            # Oder setze Umgebungsvariable für weights_only
            use_safetensors = True  # Bevorzuge safetensors für Sicherheit
            
            try:
                # Versuche mit safetensors zu laden (sicherer, funktioniert mit PyTorch 2.5.1)
                self.encoder = AutoModel.from_pretrained(
                    base_model_name,
                    use_safetensors=use_safetensors,
                    trust_remote_code=False
                )
            except Exception as e:
                logger.warning(f"Could not load with safetensors: {e}, trying without...")
                # Fallback: Normales Laden (kann mit PyTorch 2.5.1 Probleme haben)
                # Setze Umgebungsvariable für weights_only
                os.environ['TRANSFORMERS_SAFE_LOADING'] = '1'
                self.encoder = AutoModel.from_pretrained(
                    base_model_name,
                    trust_remote_code=False
                )
            
            self.tokenizer = AutoTokenizer.from_pretrained(base_model_name)
        except ImportError:
            raise ImportError("transformers library required. Install with: pip install transformers")
        except Exception as e:
            if "torch.load" in str(e) or "CVE-2025-32434" in str(e):
                raise RuntimeError(
                    f"PyTorch version issue: {e}\n"
                    "Solution: Upgrade PyTorch to 2.6+ OR use safetensors format.\n"
                    "Try: pip install safetensors\n"
                    "Or: pip install --upgrade torch (if CUDA 12.1 version available)"
                ) from e
            raise
        
        if freeze_encoder:
            for param in self.encoder.parameters():
                param.requires_grad = False
        
        # Get encoder output dimension
        encoder_dim = self.encoder.config.hidden_size
        
        # 2. Learnable Whitelist Pattern Embeddings
        # Patterns: technical_question, educational, best_practice, explanation
        self.whitelist_patterns = nn.ParameterDict({
            'technical_question': nn.Parameter(torch.randn(pattern_dim)),
            'educational': nn.Parameter(torch.randn(pattern_dim)),
            'best_practice': nn.Parameter(torch.randn(pattern_dim)),
            'explanation': nn.Parameter(torch.randn(pattern_dim))
        })
        
        # Initialize patterns with small random values
        for pattern in self.whitelist_patterns.values():
            nn.init.normal_(pattern, mean=0.0, std=0.02)
        
        # 3. Pattern Similarity Layer
        self.pattern_similarity = nn.CosineSimilarity(dim=-1)
        
        # 4. Whitelist Confidence Scorer
        # Input: encoder_output (768) + pattern_scores (4) = 772
        self.whitelist_scorer = nn.Sequential(
            nn.Linear(encoder_dim + num_patterns, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 2)  # malicious, benign
        )
        
        # 5. Pattern Classifier (für Pattern Prediction Task)
        self.pattern_classifier = nn.Sequential(
            nn.Linear(encoder_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_patterns)  # 4 patterns
        )
        
        # 6. Classification Head (für Standard Classification)
        self.classifier = nn.Sequential(
            nn.Linear(encoder_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 2)  # malicious, benign
        )
        
        logger.info(f"WhitelistAwareCodeIntentModel initialized:")
        logger.info(f"  Base Model: {base_model_name}")
        logger.info(f"  Encoder Dim: {encoder_dim}")
        logger.info(f"  Patterns: {list(self.whitelist_patterns.keys())}")
        logger.info(f"  Pattern Dim: {pattern_dim}")
        logger.info(f"  Hidden Dim: {hidden_dim}")
    
    def encode_text(self, texts: List[str], max_length: int = 512) -> torch.Tensor:
        """
        Encode texts using CodeBERT.
        
        Args:
            texts: List of text strings
            max_length: Maximum sequence length
            
        Returns:
            Text embeddings [batch_size, encoder_dim]
        """
        # Tokenize
        encoded = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=max_length,
            return_tensors='pt'
        )
        
        # Move to same device as model
        device = next(self.parameters()).device
        encoded = {k: v.to(device) for k, v in encoded.items()}
        
        # Encode
        with torch.set_grad_enabled(self.training):
            outputs = self.encoder(**encoded)
        
        # Use [CLS] token embedding
        return outputs.last_hidden_state[:, 0, :]  # [batch_size, encoder_dim]
    
    def compute_pattern_similarities(
        self, 
        text_embeddings: torch.Tensor
    ) -> Dict[str, torch.Tensor]:
        """
        Compute cosine similarity between text embeddings and whitelist patterns.
        
        Args:
            text_embeddings: Text embeddings [batch_size, encoder_dim]
            
        Returns:
            Dictionary of pattern similarities [batch_size]
        """
        similarities = {}
        
        for pattern_name, pattern_embedding in self.whitelist_patterns.items():
            # Expand pattern to batch size
            pattern_expanded = pattern_embedding.unsqueeze(0).expand(
                text_embeddings.size(0), -1
            )
            
            # Compute cosine similarity
            sim = self.pattern_similarity(text_embeddings, pattern_expanded)
            similarities[pattern_name] = sim
        
        return similarities
    
    def forward(
        self,
        texts: Optional[List[str]] = None,
        text_embeddings: Optional[torch.Tensor] = None,
        return_patterns: bool = False,
        return_similarities: bool = False
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass.
        
        Args:
            texts: List of text strings (if text_embeddings not provided)
            text_embeddings: Pre-computed text embeddings [batch_size, encoder_dim]
            return_patterns: If True, return pattern predictions
            return_similarities: If True, return pattern similarities
            
        Returns:
            Dictionary with:
            - 'logits': Classification logits [batch_size, 2]
            - 'whitelist_logits': Whitelist-aware logits [batch_size, 2]
            - 'pattern_logits': Pattern predictions [batch_size, num_patterns] (if return_patterns)
            - 'similarities': Pattern similarities dict (if return_similarities)
        """
        # Encode texts
        if text_embeddings is None:
            if texts is None:
                raise ValueError("Either texts or text_embeddings must be provided")
            text_embeddings = self.encode_text(texts)
        
        # Compute pattern similarities
        pattern_similarities = self.compute_pattern_similarities(text_embeddings)
        
        # Stack similarities [batch_size, num_patterns]
        similarity_scores = torch.stack([
            pattern_similarities[pattern_name]
            for pattern_name in sorted(self.whitelist_patterns.keys())
        ], dim=1)
        
        # Standard classification
        standard_logits = self.classifier(text_embeddings)
        
        # Whitelist-aware classification
        # Concat: text_embeddings + pattern_similarities
        combined_features = torch.cat([text_embeddings, similarity_scores], dim=-1)
        whitelist_logits = self.whitelist_scorer(combined_features)
        
        # Pattern prediction (for multi-task learning)
        pattern_logits = None
        if return_patterns:
            pattern_logits = self.pattern_classifier(text_embeddings)
        
        # Build output
        output = {
            'logits': standard_logits,
            'whitelist_logits': whitelist_logits,
            'similarities': similarity_scores
        }
        
        if return_patterns:
            output['pattern_logits'] = pattern_logits
        
        if return_similarities:
            output['pattern_similarities'] = pattern_similarities
        
        return output
    
    def predict(
        self,
        texts: List[str],
        use_whitelist: bool = True,
        threshold: float = 0.5
    ) -> List[Dict[str, any]]:
        """
        Predict malicious/benign for texts.
        
        Args:
            texts: List of text strings
            use_whitelist: If True, use whitelist-aware classification
            threshold: Classification threshold
            
        Returns:
            List of prediction dicts
        """
        self.eval()
        
        with torch.no_grad():
            output = self.forward(
                texts=texts,
                return_patterns=False,
                return_similarities=True
            )
            
            # Use whitelist logits if requested
            logits = output['whitelist_logits'] if use_whitelist else output['logits']
            probabilities = F.softmax(logits, dim=-1)
            
            # Get pattern similarities
            similarities = output['pattern_similarities']
            
            predictions = []
            for i, text in enumerate(texts):
                prob_malicious = probabilities[i, 1].item()
                prob_benign = probabilities[i, 0].item()
                
                # Find best matching pattern
                pattern_scores = {
                    pattern_name: similarities[pattern_name][i].item()
                    for pattern_name in sorted(self.whitelist_patterns.keys())
                }
                best_pattern = max(pattern_scores.items(), key=lambda x: x[1])
                
                predictions.append({
                    'text': text,
                    'is_malicious': prob_malicious >= threshold,
                    'malicious_probability': prob_malicious,
                    'benign_probability': prob_benign,
                    'best_pattern': best_pattern[0],
                    'pattern_confidence': best_pattern[1],
                    'all_patterns': pattern_scores
                })
        
        return predictions
    
    def get_pattern_embeddings(self) -> Dict[str, torch.Tensor]:
        """Get current whitelist pattern embeddings."""
        return {
            name: param.clone().detach()
            for name, param in self.whitelist_patterns.items()
        }


class FocalLoss(nn.Module):
    """
    Focal Loss for handling class imbalance.
    
    Paper: https://arxiv.org/abs/1708.02002
    """
    
    def __init__(self, alpha: List[float] = [0.25, 0.75], gamma: float = 2.0):
        """
        Initialize Focal Loss.
        
        Args:
            alpha: Class weights [class_0, class_1] (default: [0.25, 0.75] for benign=0.25, malicious=0.75)
            gamma: Focusing parameter (default: 2.0)
        """
        super().__init__()
        self.alpha = torch.tensor(alpha)
        self.gamma = gamma
    
    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """
        Compute Focal Loss.
        
        Args:
            inputs: Logits [batch_size, num_classes]
            targets: Target labels [batch_size]
            
        Returns:
            Focal loss value
        """
        # Move alpha to same device as inputs
        if self.alpha.device != inputs.device:
            self.alpha = self.alpha.to(inputs.device)
        
        # Compute cross entropy
        ce_loss = F.cross_entropy(inputs, targets, reduction='none')
        
        # Compute p_t
        pt = torch.exp(-ce_loss)
        
        # Get alpha for each sample
        alpha_t = self.alpha[targets]
        
        # Compute focal loss
        focal_loss = alpha_t * (1 - pt) ** self.gamma * ce_loss
        
        return focal_loss.mean()


def create_model(
    base_model_name: str = "microsoft/codebert-base",
    num_patterns: int = 4,
    pattern_dim: int = 768,
    hidden_dim: int = 256,
    dropout: float = 0.2,
    freeze_encoder: bool = False,
    device: str = 'cuda'
) -> WhitelistAwareCodeIntentModel:
    """
    Factory function to create WhitelistAwareCodeIntentModel.
    
    Args:
        base_model_name: HuggingFace model name
        num_patterns: Number of whitelist patterns
        pattern_dim: Pattern embedding dimension
        hidden_dim: Hidden dimension
        dropout: Dropout rate
        freeze_encoder: Freeze encoder weights
        device: Device to load model on
        
    Returns:
        Initialized model
    """
    model = WhitelistAwareCodeIntentModel(
        base_model_name=base_model_name,
        num_patterns=num_patterns,
        pattern_dim=pattern_dim,
        hidden_dim=hidden_dim,
        dropout=dropout,
        freeze_encoder=freeze_encoder
    )
    
    model = model.to(device)
    logger.info(f"Model created and moved to {device}")
    
    return model

