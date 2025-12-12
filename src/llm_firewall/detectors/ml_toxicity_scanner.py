#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ML-Based Multilingual Toxicity Scanner
========================================

Uses transformer models (XLM-RoBERTa) for toxicity detection across multiple languages.
Falls back to keyword-based detection if ML model is unavailable.

Supported Models:
- martin-ha/toxic-comment-model (multilingual, 9 languages)
- xlm-roberta-base-finetuned-toxicity (if available)
- Fallback: keyword-based multilingual_toxicity.py

Author: Claude Sonnet 4.5 (Autonomous Executive)
Date: 2025-12-05
"""

import logging
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)

# Try to import transformers
HAS_TRANSFORMERS = False
HAS_TORCH = False
try:
    import torch
    import os

    HAS_TORCH = True
    
    # CRITICAL: Enforce GPU at module import time
    # This ensures GPU is required before any initialization happens
    if not torch.cuda.is_available():
        raise RuntimeError(
            "[MLToxicityScanner] FATAL: CUDA is not available. "
            "GPU is REQUIRED - CPU is COMPLETELY DISABLED. "
            "Please ensure CUDA is installed and available."
        )
    # Force GPU environment variables
    os.environ['TORCH_DEVICE'] = 'cuda'
    if 'CUDA_VISIBLE_DEVICES' not in os.environ:
        os.environ['CUDA_VISIBLE_DEVICES'] = '0'
    logger.info(f"[MLToxicityScanner] GPU enforcement: CUDA available, device will be cuda")
except ImportError:
    pass
except RuntimeError:
    # GPU not available - re-raise
    raise

try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline

    HAS_TRANSFORMERS = True
except ImportError:
    pass

# Fallback to keyword-based detection
try:
    from llm_firewall.detectors.multilingual_toxicity import (
        scan_toxicity as keyword_scan_toxicity,
    )

    HAS_KEYWORD_FALLBACK = True
except ImportError:
    HAS_KEYWORD_FALLBACK = False
    keyword_scan_toxicity = None  # type: ignore


class MultilingualToxicityScanner:
    """
    ML-based multilingual toxicity scanner using transformer models.

    Supports multiple models with automatic fallback:
    1. Primary: martin-ha/toxic-comment-model (multilingual)
    2. Fallback: keyword-based detection
    """

    def __init__(
        self,
        model_name: Optional[str] = None,
        device: Optional[str] = None,
        use_fallback: bool = True,
        threshold: float = 0.5,
    ):
        """
        Initialize the ML toxicity scanner.

        Args:
            model_name: Hugging Face model name (default: auto-detect best available)
            device: Device to run model on ('cpu', 'cuda', or None for auto)
            use_fallback: Whether to use keyword-based fallback if ML model fails
            threshold: Toxicity threshold (0.0-1.0), above which content is considered toxic
        """
        self.model_name = model_name
        self.device = device
        self.use_fallback = use_fallback
        self.threshold = threshold

        self.model = None
        self.tokenizer = None
        self.pipeline = None
        self.is_loaded = False

        # Auto-detect device - REQUIRE GPU (CPU COMPLETELY DISABLED)
        if self.device is None and HAS_TORCH:
            from llm_firewall.core.gpu_enforcement import require_gpu
            self.device = require_gpu()  # Raises error if GPU not available (CPU disabled)
            self.logger.info(f"[MLToxicity] Using device: {self.device} (CPU disabled)")
        elif self.device is None:
            # Fallback: require GPU
            from llm_firewall.core.gpu_enforcement import require_gpu
            self.device = require_gpu()  # Raises error if GPU not available (CPU disabled)

        # Try to load model
        self._load_model()

    def _load_model(self) -> bool:
        """
        Load the toxicity detection model.

        Returns:
            True if model loaded successfully, False otherwise
        """
        # CRITICAL: Verify GPU is required before loading model
        if self.device != "cuda":
            raise RuntimeError(
                f"[MLToxicity] FATAL: Device is '{self.device}' but GPU (cuda) is REQUIRED. "
                "CPU is COMPLETELY DISABLED. This should never happen - GPU enforcement failed!"
            )
        
        # Double-check CUDA is available
        import torch
        if not torch.cuda.is_available():
            raise RuntimeError(
                "[MLToxicity] FATAL: CUDA is not available but device is set to 'cuda'. "
                "GPU is REQUIRED - CPU is COMPLETELY DISABLED."
            )
        
        if not HAS_TRANSFORMERS:
            logger.warning(
                "[MLToxicity] transformers library not available. "
                "Install with: pip install transformers torch"
            )
            return False

        # Model priority list (best to worst)
        model_candidates = [
            self.model_name,  # User-specified
            "martin-ha/toxic-comment-model",  # Multilingual, 9 languages
            "unitary/toxic-bert",  # English-only fallback
        ]

        for candidate in model_candidates:
            if candidate is None:
                continue

            try:
                logger.info(f"[MLToxicity] Attempting to load model: {candidate} on GPU (device=0)")

                # Try to load as pipeline (easiest) - ALWAYS use GPU (device=0)
                try:
                    import torch
                    
                    # CRITICAL: device=0 alone is NOT enough - must explicitly move to CUDA
                    self.pipeline = pipeline(
                        "text-classification",
                        model=candidate,
                        device=0,  # This should work but sometimes doesn't
                        return_all_scores=True,
                    )
                    
                    # FORCE model to CUDA explicitly (device=0 parameter is unreliable)
                    if self.pipeline.model is not None:
                        self.pipeline.model = self.pipeline.model.to('cuda:0')
                        self.pipeline.model.eval()
                    
                    # VERIFY: Check actual device of model parameters
                    model_device = next(self.pipeline.model.parameters()).device
                    if model_device.type != 'cuda':
                        raise RuntimeError(
                            f"[MLToxicity] FATAL: Model on {model_device.type} instead of cuda after explicit .to('cuda:0'). "
                            f"GPU enforcement FAILED. Check CUDA installation."
                        )
                    
                    self.model_name = candidate
                    self.is_loaded = True
                    logger.info(f"[MLToxicity] Model {candidate} VERIFIED on GPU: {model_device}")
                    
                    return True
                except Exception as e:
                    logger.debug(f"[MLToxicity] Pipeline load failed: {e}")
                    # Try manual loading
                    try:
                        self.tokenizer = AutoTokenizer.from_pretrained(candidate)  # nosec B615
                        self.model = AutoModelForSequenceClassification.from_pretrained(  # nosec B615
                            candidate
                        )
                        if self.model is not None and self.device == "cuda":
                            self.model = self.model.cuda()
                        if self.model is not None:
                            self.model.eval()
                        self.model_name = candidate
                        self.is_loaded = True
                        logger.info(
                            f"[MLToxicity] Successfully loaded model (manual): {candidate}"
                        )
                        return True
                    except Exception as e2:
                        logger.debug(f"[MLToxicity] Manual load failed: {e2}")
                        continue

            except Exception as e:
                logger.debug(f"[MLToxicity] Model {candidate} failed: {e}")
                continue

        logger.warning(
            "[MLToxicity] No ML model could be loaded. Using fallback if available."
        )
        return False

    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan text for toxicity using ML model.

        Args:
            text: Text to scan

        Returns:
            Dictionary with:
            - is_toxic: bool (True if toxic)
            - confidence: float (0.0-1.0, toxicity score)
            - signals: List[str] (detected signals)
            - method: str ("ml", "keyword", or "none")
            - metadata: Dict with additional info
        """
        if not text or not text.strip():
            return {
                "is_toxic": False,
                "confidence": 0.0,
                "signals": [],
                "method": "none",
                "metadata": {},
            }

        # Try ML model first
        if self.is_loaded:
            try:
                result = self._scan_ml(text)
                if result is not None:
                    return result
            except Exception as e:
                logger.warning(f"[MLToxicity] ML scan failed: {e}. Falling back.")

        # Fallback to keyword-based
        if self.use_fallback and HAS_KEYWORD_FALLBACK and keyword_scan_toxicity:
            try:
                return self._scan_keyword_fallback(text)
            except Exception as e:
                logger.warning(f"[MLToxicity] Keyword fallback failed: {e}")

        # No detection available
        return {
            "is_toxic": False,
            "confidence": 0.0,
            "signals": [],
            "method": "none",
            "metadata": {"error": "No detection method available"},
        }

    def scan_batch(self, texts: list[str], batch_size: int = 32) -> list[Dict[str, Any]]:
        """
        Scan multiple texts for toxicity using ML model with batching.
        
        OPTIMIZED FOR GPU: Uses batching to maximize GPU throughput.
        With 16GB VRAM, batch_size=32 is safe, can go higher (64-128) for more speed.

        Args:
            texts: List of texts to scan
            batch_size: Number of texts to process per batch (default 32)

        Returns:
            List of result dictionaries (same format as scan())
        """
        if not texts:
            return []
        
        # Filter empty texts and track indices
        text_map = []  # (index, text)
        for i, text in enumerate(texts):
            if text and text.strip():
                text_map.append((i, text))
        
        # Initialize results with empty defaults
        results = [
            {
                "is_toxic": False,
                "confidence": 0.0,
                "signals": [],
                "method": "none",
                "metadata": {},
            }
            for _ in texts
        ]
        
        if not text_map:
            return results
        
        # Try ML model first (with batching)
        if self.is_loaded and self.pipeline:
            try:
                # Extract just the texts for batch processing
                batch_texts = [text for _, text in text_map]
                
                # Process in batches using HuggingFace pipeline batching
                # This is MUCH faster on GPU than sequential processing
                batch_results = self.pipeline(
                    batch_texts,
                    truncation=True,
                    max_length=512,
                    batch_size=batch_size,
                )
                
                # Parse batch results
                for (original_idx, _), batch_result in zip(text_map, batch_results):
                    parsed = self._parse_ml_result(batch_result)
                    if parsed:
                        results[original_idx] = parsed
                
                return results
                
            except Exception as e:
                logger.warning(f"[MLToxicity] Batch ML scan failed: {e}. Falling back to sequential.")
        
        # Fallback: sequential scanning
        for original_idx, text in text_map:
            results[original_idx] = self.scan(text)
        
        return results

    def _parse_ml_result(self, results: Any) -> Optional[Dict[str, Any]]:
        """
        Parse ML pipeline results into standardized format.
        
        Args:
            results: Raw results from pipeline
            
        Returns:
            Parsed result dictionary or None if parsing failed
        """
        try:
            toxicity_score = 0.0
            signals = []

            if isinstance(results, list) and len(results) > 0:
                # Handle different output formats
                if isinstance(results[0], dict):
                    # Single result dict
                    if "label" in results[0]:
                        label = results[0]["label"].lower()
                        score = results[0].get("score", 0.0)

                        # CRITICAL: Check for toxic labels (but NOT non-toxic)
                        if (
                            ("toxic" in label and "non-toxic" not in label)
                            or "hate" in label
                            or "offensive" in label
                        ):
                            toxicity_score = score
                            signals.append(f"ml_toxicity_{label}")
                        elif "non-toxic" in label:
                            # Non-toxic: use inverse score (1.0 - score) for toxicity
                            toxicity_score = 1.0 - score
                            if toxicity_score > 0.0:
                                signals.append("ml_toxicity_non-toxic_inverted")
                    elif "score" in results[0]:
                        toxicity_score = results[0]["score"]
                        signals.append("ml_toxicity_detected")
                elif isinstance(results[0], list):
                    # Multiple scores (return_all_scores=True)
                    # Find the toxic label (not non-toxic)
                    for item in results[0]:
                        if isinstance(item, dict):
                            label = item.get("label", "").lower()
                            score = item.get("score", 0.0)

                            # CRITICAL: Check for toxic labels (but NOT non-toxic)
                            if (
                                ("toxic" in label and "non-toxic" not in label)
                                or "hate" in label
                                or "offensive" in label
                            ):
                                if score > toxicity_score:
                                    toxicity_score = score
                                signals.append(f"ml_toxicity_{label}")
                            elif "non-toxic" in label:
                                # Non-toxic: use inverse score (1.0 - score) for toxicity
                                non_toxic_score = 1.0 - score
                                if non_toxic_score > toxicity_score:
                                    toxicity_score = non_toxic_score
                                signals.append("ml_toxicity_non-toxic_inverted")

            is_toxic = toxicity_score >= self.threshold

            return {
                "is_toxic": is_toxic,
                "confidence": toxicity_score,
                "signals": signals if is_toxic else [],
                "method": "ml",
                "metadata": {
                    "model": self.model_name,
                    "threshold": self.threshold,
                    "raw_results": results,
                },
            }
        except Exception as e:
            logger.debug(f"[MLToxicity] Result parsing error: {e}")
            return None

    def _scan_ml(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Scan using ML model (pipeline or manual).

        Args:
            text: Text to scan

        Returns:
            Result dictionary or None if scan failed
        """
        if self.pipeline:
            # Use pipeline (easiest)
            try:
                results = self.pipeline(text, truncation=True, max_length=512)
                return self._parse_ml_result(results)
            except Exception as e:
                logger.debug(f"[MLToxicity] Pipeline scan error: {e}")
                return None

        elif self.model and self.tokenizer:
            # Manual inference
            try:
                inputs = self.tokenizer(
                    text,
                    return_tensors="pt",
                    truncation=True,
                    max_length=512,
                    padding=True,
                )

                if self.device == "cuda":
                    inputs = {k: v.cuda() for k, v in inputs.items()}

                with torch.no_grad():
                    outputs = self.model(**inputs)
                    logits = outputs.logits
                    probs = torch.softmax(logits, dim=-1)

                # Assume binary classification: [non-toxic, toxic]
                # Or multi-class: [non-toxic, toxic, hate, etc.]
                toxicity_score = float(probs[0][-1]) if len(probs[0]) > 1 else 0.0
                is_toxic = toxicity_score >= self.threshold

                signals = []
                if is_toxic:
                    signals.append("ml_toxicity_detected")
                    if toxicity_score >= 0.8:
                        signals.append("ml_toxicity_high_confidence")

                return {
                    "is_toxic": is_toxic,
                    "confidence": toxicity_score,
                    "signals": signals,
                    "method": "ml",
                    "metadata": {
                        "model": self.model_name,
                        "threshold": self.threshold,
                    },
                }
            except Exception as e:
                logger.debug(f"[MLToxicity] Manual inference error: {e}")
                return None

        return None

    def _scan_keyword_fallback(self, text: str) -> Dict[str, Any]:
        """
        Fallback to keyword-based detection.

        Args:
            text: Text to scan

        Returns:
            Result dictionary
        """
        hits = keyword_scan_toxicity(text)

        # Convert keyword hits to confidence score
        confidence = 0.0
        if hits:
            # Calculate confidence based on signal types
            if "toxicity_high_severity" in hits:
                confidence = 0.9
            elif "toxicity_medium_severity" in hits:
                confidence = 0.7
            elif "toxicity_low_severity" in hits:
                confidence = 0.5
            else:
                confidence = 0.6  # Default for toxicity_detected

            # Boost for high density
            if "toxicity_very_high_density" in hits:
                confidence = min(1.0, confidence + 0.1)

        is_toxic = confidence >= self.threshold

        return {
            "is_toxic": is_toxic,
            "confidence": confidence,
            "signals": hits if is_toxic else [],
            "method": "keyword",
            "metadata": {
                "fallback": True,
                "threshold": self.threshold,
            },
        }


# Global scanner instance (lazy-loaded)
_global_scanner: Optional[MultilingualToxicityScanner] = None


def get_scanner(
    model_name: Optional[str] = None,
    device: Optional[str] = None,
    use_fallback: bool = True,
    threshold: float = 0.5,
) -> MultilingualToxicityScanner:
    """
    Get or create global scanner instance.

    Args:
        model_name: Model name (only used on first call)
        device: Device (only used on first call) - if None, GPU will be enforced
        use_fallback: Use fallback (only used on first call)
        threshold: Threshold (only used on first call)

    Returns:
        MultilingualToxicityScanner instance
    """
    global _global_scanner

    # CRITICAL: If scanner exists but is on CPU, reset it and recreate with GPU
    if _global_scanner is not None:
        if _global_scanner.device == "cpu":
            import logging
            logger = logging.getLogger(__name__)
            logger.warning("[get_scanner] Scanner was initialized with CPU - resetting and recreating with GPU")
            _global_scanner = None
    
    if _global_scanner is None:
        # If device not specified, enforce GPU usage (CPU COMPLETELY DISABLED)
        if device is None:
            from llm_firewall.core.gpu_enforcement import require_gpu
            device = require_gpu()  # Raises error if GPU not available (CPU disabled)
        elif device.lower() == "cpu":
            # CPU explicitly requested - reject it
            raise RuntimeError(
                "[get_scanner] CPU usage is COMPLETELY DISABLED. "
                "GPU is required. Please ensure CUDA is available."
            )
        
        _global_scanner = MultilingualToxicityScanner(
            model_name=model_name,
            device=device,
            use_fallback=use_fallback,
            threshold=threshold,
        )
        
        # Verify device after initialization
        if _global_scanner.device != "cuda":
            raise RuntimeError(
                f"[get_scanner] Scanner initialized with {_global_scanner.device} instead of cuda. "
                "GPU enforcement failed!"
            )

    return _global_scanner


def scan_ml_toxicity(
    text: str,
    model_name: Optional[str] = None,
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """
    Convenience function to scan text for toxicity.

    Args:
        text: Text to scan
        model_name: Optional model name (uses default if None)
        threshold: Toxicity threshold (0.0-1.0)

    Returns:
        Result dictionary with is_toxic, confidence, signals, method, metadata
    """
    scanner = get_scanner(model_name=model_name, threshold=threshold)
    return scanner.scan(text)
