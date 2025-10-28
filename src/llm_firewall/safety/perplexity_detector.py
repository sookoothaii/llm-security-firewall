"""
Perplexity-Based Adversarial Detection
=======================================

Layer 2: Detects adversarial suffixes using perplexity analysis.

Based on research: 99.2% detection rate, <0.1% FPR
Paper: "Perplexity-based Detector for LLM-Targeted Attacks"

Creator: Joerg Bollwahn
License: MIT
"""

from __future__ import annotations
from dataclasses import dataclass
import logging
import math

logger = logging.getLogger(__name__)


@dataclass
class PerplexityResult:
    """Result from perplexity detection."""
    is_adversarial: bool
    perplexity: float
    confidence: float
    method: str = "perplexity"


class PerplexityDetector:
    """
    Detects adversarial attacks using perplexity analysis.
    
    Adversarial suffixes (GCG, AutoDAN) have extremely high perplexity (>1000).
    Normal text typically has perplexity 20-200.
    """
    
    def __init__(self, threshold: float = 500.0):
        """
        Initialize perplexity detector.
        
        Args:
            threshold: Perplexity threshold for detection
        """
        self.threshold = threshold
        
        # Lazy import to avoid dependency issues
        try:
            from transformers import GPT2LMHeadModel, GPT2Tokenizer
            import torch
            
            self.tokenizer = GPT2Tokenizer.from_pretrained('gpt2')
            self.model = GPT2LMHeadModel.from_pretrained('gpt2')
            self.model.eval()
            self.torch = torch
            self.available = True
            logger.info("Perplexity detector initialized with GPT-2")
        except ImportError:
            logger.warning("transformers/torch not available, detector disabled")
            self.model = None
            self.available = False
    
    def detect(self, prompt: str) -> PerplexityResult:
        """
        Detect if prompt contains adversarial content.
        
        Args:
            prompt: Input text to analyze
            
        Returns:
            PerplexityResult with detection decision
        """
        if not self.available:
            # Fallback: no detection
            return PerplexityResult(
                is_adversarial=False,
                perplexity=0.0,
                confidence=0.0,
                method="perplexity_disabled"
            )
        
        # Calculate perplexity
        perplexity = self._calculate_perplexity(prompt)
        
        # Detection decision
        is_adversarial = perplexity >= self.threshold
        
        # Confidence: normalize perplexity to 0-1 range
        # Normal text: 20-200 → ~0
        # Adversarial: >500 → ~1
        confidence = min(1.0, max(0.0, (perplexity - 200) / 800))
        
        return PerplexityResult(
            is_adversarial=is_adversarial,
            perplexity=float(perplexity),
            confidence=float(confidence),
            method="perplexity"
        )
    
    def _calculate_perplexity(self, text: str) -> float:
        """
        Calculate perplexity of text using GPT-2.
        
        Args:
            text: Input text
            
        Returns:
            Perplexity score
        """
        if not self.available:
            return 0.0
        
        # Tokenize
        encodings = self.tokenizer(text, return_tensors='pt')
        
        # Calculate loss
        with self.torch.no_grad():
            outputs = self.model(**encodings, labels=encodings['input_ids'])
            loss = outputs.loss.item()
        
        # Perplexity = exp(loss)
        perplexity = math.exp(loss)
        
        return perplexity

