"""Crisis detection for self-harm, suicide ideation, and abuse disclosure.

Hybrid approach:
- Regex patterns for immediate high-recall detection
- Optional ONNX ML model for nuanced scoring (falls back to regex if unavailable)
- Country-specific resource cards with hotlines

Credit: GPT-5 collaboration 2025-11-04
"""

import re
import json
import os
import logging
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

# Optional ONNX Runtime
try:
    import onnxruntime as ort  # type: ignore[import-untyped]
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False
    logger.warning("onnxruntime not available - crisis detection will use regex only")

# Optional transformers for tokenizer
try:
    from transformers import AutoTokenizer  # type: ignore[import-untyped]
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False
    logger.warning("transformers not available - ONNX model will not load")


class CrisisDetector:
    """Hybrid regex + ML crisis pattern detector."""
    
    def __init__(self, cfg: Dict[str, Any]):
        """Initialize with configuration from layer15.yaml.
        
        Args:
            cfg: Configuration dict from crisis_detection section
        """
        self.cfg = cfg
        self._compile_regex()
        self._try_load_onnx()

    def _compile_regex(self) -> None:
        """Compile all regex patterns from config."""
        self._patterns = []
        r = self.cfg.get("regex", {})
        for fam, arr in r.items():
            for pat in arr:
                self._patterns.append((fam, re.compile(pat, re.IGNORECASE)))

    def _try_load_onnx(self) -> None:
        """Try to load ONNX model if available."""
        self.ort_sess: Optional[Any] = None
        self.tok: Optional[Any] = None
        self.thr = {"self_harm": 0.5, "abuse": 0.5, "unsafe_env": 0.5}
        
        if not HAS_ONNX or not HAS_TRANSFORMERS:
            return
        
        model_path = self.cfg.get("ml_model", {}).get("path")
        if not model_path or not os.path.exists(model_path):
            logger.info("No ONNX model found - using regex-only crisis detection")
            return
        
        # Assume sibling directory holds tokenizer & thresholds.json
        base = os.path.dirname(model_path)
        thr_path = os.path.join(base, 'thresholds.json')
        if os.path.exists(thr_path):
            try:
                self.thr.update(json.load(open(thr_path, 'r', encoding='utf-8')))
            except Exception as e:
                logger.warning(f"Failed to load thresholds.json: {e}")
        
        # Load tokenizer and ONNX session
        try:
            # Bandit B615: Pin revision for security (use "main" for latest stable)
            self.tok = AutoTokenizer.from_pretrained(base, revision="main")  # nosec B615
            self.ort_sess = ort.InferenceSession(
                model_path,
                providers=["CPUExecutionProvider"]
            )
            logger.info(f"ONNX crisis model loaded from {model_path}")
        except Exception as e:
            logger.error(f"Failed to load ONNX model: {e}")
            self.ort_sess = None

    def regex_signals(self, text: str) -> Dict[str, bool]:
        """Check text against crisis regex patterns.
        
        Args:
            text: Text to check
            
        Returns:
            Dict of pattern families that matched
        """
        hits = {}
        for fam, rex in self._patterns:
            if rex.search(text or ""):
                hits[fam] = True
        return hits

    def ml_scores(self, text: str, ctx: str = "") -> Dict[str, float]:
        """Compute ML-based crisis scores using ONNX model if available.
        
        Falls back to regex-based heuristics if ONNX model not loaded.
        
        Args:
            text: Primary text to analyze
            ctx: Optional context
            
        Returns:
            Dict with scores for self_harm, abuse, unsafe_env (0-1)
        """
        # If ONNX model available, use it
        if self.ort_sess and self.tok:
            try:
                import numpy as np
                
                # Tokenize
                enc = self.tok(
                    text if text else "",
                    return_tensors='np',
                    truncation=True,
                    padding='max_length',
                    max_length=256
                )
                
                # Run ONNX inference
                logits = self.ort_sess.run(
                    ["logits"],
                    {
                        "input_ids": enc["input_ids"],
                        "attention_mask": enc["attention_mask"]
                    }
                )[0]
                
                # Sigmoid to get probabilities
                probs = 1 / (1 + np.exp(-logits))
                
                return {
                    "self_harm": float(probs[0][0]),
                    "abuse": float(probs[0][1]),
                    "unsafe_env": float(probs[0][2])
                }
            except Exception as e:
                logger.error(f"ONNX inference failed: {e} - falling back to regex")
        
        # Fallback heuristic from regex
        hits = self.regex_signals(text + "\n" + (ctx or ""))
        base = 0.0
        if any(k.startswith("self_harm") for k in hits):
            base = max(base, 0.85)
        if any(k.startswith("abuse") for k in hits):
            base = max(base, 0.80)
        
        return {
            "self_harm": base,
            "abuse": base if base >= 0.80 else 0.0,
            "unsafe_env": 0.5 if base >= 0.80 else 0.0
        }

    def decide(self, text: str, ctx: str = "") -> Tuple[str, Dict[str, Any]]:
        """Decide crisis severity level (high/medium/low).
        
        Args:
            text: Primary text to analyze
            ctx: Optional context
            
        Returns:
            Tuple of (level, metadata)
            - level: 'high', 'medium', or 'low'
            - metadata: dict with reason and scores/hits
        """
        t = self.cfg["thresholds"]
        regex_hits = self.regex_signals(text)
        
        # Hard regex hit → immediate high severity
        if regex_hits and t["regex_hard_hit"]:
            return "high", {"reason": "regex_hard", "hits": list(regex_hits.keys())}
        
        # ML-based scoring
        scores = self.ml_scores(text, ctx)
        max_score = max(scores.values())
        
        # Check against thresholds (use model thresholds if available)
        self_harm_threshold = self.thr.get("self_harm", 0.5)
        if max_score >= t["ml_score_high"] or scores.get("self_harm", 0.0) >= self_harm_threshold:
            return "high", {"reason": "ml_high", "scores": scores}
        if max_score >= t["ml_score_medium"]:
            return "medium", {"reason": "ml_medium", "scores": scores}
        
        return "low", {"reason": "none", "scores": scores}

    def resource_card(self, country: str, lang: Optional[str] = None) -> Dict[str, str]:
        """Get country-specific crisis resources (hotlines, emergency numbers).
        
        Args:
            country: Country code (e.g., 'US', 'DE', 'TH')
            lang: Optional language override
            
        Returns:
            Dict with language, hotline, emergency, url
        """
        entries = self.cfg.get("resources_by_country", {}).get("entries", {})
        dflt_lang = self.cfg.get("resources_by_country", {}).get("default_language", "en")
        item = entries.get(country.upper()) or {}
        return {
            "language": item.get("language", lang or dflt_lang),
            "hotline": item.get("hotline", ""),
            "emergency": item.get("emergency", ""),
            "url": item.get("url", "")
        }

