"""
Whitelist Classifier - Simplified Binary Classifier

Binäre Klassifikation: Whitelist (1) oder Nicht-Whitelist (0)

Architecture:
- DistilBERT Base (lightweight, fast)
- Binary Classification Head
- Optimized for high recall on Whitelist
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class WhitelistClassifier(nn.Module):
    """
    Simplified Whitelist Classifier.
    
    Binary classification: Whitelist (1) or Not Whitelist (0)
    Optimized for high recall on Whitelist cases.
    """
    
    def __init__(
        self,
        base_model_name: str = "distilbert-base-uncased",
        dropout: float = 0.1,
        freeze_encoder: bool = False
    ):
        """
        Initialize Whitelist Classifier.
        
        Args:
            base_model_name: HuggingFace model name (default: distilbert-base-uncased)
            dropout: Dropout rate
            freeze_encoder: If True, freeze encoder weights
        """
        super().__init__()
        
        try:
            from transformers import AutoModel, AutoTokenizer
            self.encoder = AutoModel.from_pretrained(base_model_name)
            self.tokenizer = AutoTokenizer.from_pretrained(base_model_name)
        except ImportError:
            raise ImportError("transformers library required. Install with: pip install transformers")
        
        if freeze_encoder:
            for param in self.encoder.parameters():
                param.requires_grad = False
        
        # Get encoder output dimension
        encoder_dim = self.encoder.config.dim  # DistilBERT: 768
        
        # Binary Classification Head
        self.classifier = nn.Sequential(
            nn.Linear(encoder_dim, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 1)  # Binary: Whitelist or not
        )
        
        logger.info(f"WhitelistClassifier initialized:")
        logger.info(f"  Base Model: {base_model_name}")
        logger.info(f"  Encoder Dim: {encoder_dim}")
        logger.info(f"  Dropout: {dropout}")
        logger.info(f"  Freeze Encoder: {freeze_encoder}")
    
    def encode_text(self, texts: List[str], max_length: int = 512) -> torch.Tensor:
        """
        Encode texts using DistilBERT.
        
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
    
    def forward(
        self,
        texts: Optional[List[str]] = None,
        text_embeddings: Optional[torch.Tensor] = None,
        input_ids: Optional[torch.Tensor] = None,
        attention_mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            texts: List of text strings (if embeddings not provided)
            text_embeddings: Pre-computed text embeddings
            input_ids: Token IDs (if using tokenizer separately)
            attention_mask: Attention mask
            
        Returns:
            Logits [batch_size, 1]
        """
        if text_embeddings is None:
            if texts is not None:
                text_embeddings = self.encode_text(texts)
            elif input_ids is not None:
                device = next(self.parameters()).device
                if attention_mask is None:
                    attention_mask = torch.ones_like(input_ids).to(device)
                
                outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
                text_embeddings = outputs.last_hidden_state[:, 0, :]
            else:
                raise ValueError("Either texts, text_embeddings, or input_ids must be provided")
        
        # Classify
        logits = self.classifier(text_embeddings)
        
        return logits
    
    def predict(
        self,
        texts: List[str],
        threshold: float = 0.5,
        return_probabilities: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Predict whitelist for texts.
        
        Args:
            texts: List of text strings
            threshold: Classification threshold
            return_probabilities: If True, return probabilities
            
        Returns:
            List of prediction dicts
        """
        self.eval()
        
        with torch.no_grad():
            logits = self.forward(texts=texts)
            probabilities = torch.sigmoid(logits).squeeze(-1)
            
            predictions = []
            for i, text in enumerate(texts):
                prob = probabilities[i].item()
                is_whitelist = prob >= threshold
                
                pred = {
                    'text': text,
                    'is_whitelist': is_whitelist,
                    'whitelist_probability': prob
                }
                
                if return_probabilities:
                    pred['probabilities'] = {
                        'whitelist': prob,
                        'not_whitelist': 1.0 - prob
                    }
                
                predictions.append(pred)
        
        return predictions


def create_whitelist_classifier(
    base_model_name: str = "distilbert-base-uncased",
    dropout: float = 0.1,
    freeze_encoder: bool = False,
    device: str = 'cuda'
) -> WhitelistClassifier:
    """
    Factory function to create WhitelistClassifier.
    
    Args:
        base_model_name: HuggingFace model name
        dropout: Dropout rate
        freeze_encoder: Freeze encoder weights
        device: Device to load model on
        
    Returns:
        Initialized model
    """
    model = WhitelistClassifier(
        base_model_name=base_model_name,
        dropout=dropout,
        freeze_encoder=freeze_encoder
    )
    
    model = model.to(device)
    logger.info(f"WhitelistClassifier created and moved to {device}")
    
    return model

