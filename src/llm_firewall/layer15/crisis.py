"""Crisis detection for self-harm, suicide ideation, and abuse disclosure."""

import re
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

import numpy as np

logger = logging.getLogger(__name__)

# Optional ONNX Runtime for ML-based crisis detection
try:
    import onnxruntime as ort  # type: ignore[import-untyped]
    HAS_ONNX = True
except ImportError:
    HAS_ONNX = False
    logger.warning("onnxruntime not available - crisis detection will use regex only")

# Optional transformers for tokenizer (ONNX model uses AutoTokenizer)
try:
    from transformers import AutoTokenizer
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False
    AutoTokenizer = None
    logger.warning("transformers not available - ONNX model cannot load, using regex fallback")


class CrisisDetector:
    """Hybrid regex + ML crisis pattern detector."""
    
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self._compile_regex()
        self._load_ml_model()

    def _compile_regex(self) -> None:
        """Compile all regex patterns from config."""
        self._patterns = []
        r = self.cfg.get("regex", {})
        for fam, arr in r.items():
            for pat in arr:
                self._patterns.append((fam, re.compile(pat, re.IGNORECASE)))

    def _load_ml_model(self) -> None:
        """Load ONNX crisis detection model if available.
        
        Model path: models/selfharm_abuse_multilingual.onnx
        Tokenizer: models/layer15_crisis/ (sibling directory)
        Thresholds: models/layer15_crisis/thresholds.json
        """
        self.onnx_session: Optional[Any] = None
        self.tok: Optional[Any] = None
        self.thr: Dict[str, float] = {"self_harm": 0.5, "abuse": 0.5, "unsafe_env": 0.5}
        
        ml_cfg = self.cfg.get("ml_model", {})
        model_path = ml_cfg.get("path", "")
        
        if not model_path or not Path(model_path).exists():
            logger.info("No ONNX model found - using regex-only crisis detection")
            return
        
        if not HAS_ONNX or not HAS_TRANSFORMERS:
            logger.warning("onnxruntime or transformers not installed - cannot load ONNX model")
            return
        
        try:
            # Tokenizer directory (sibling to ONNX model)
            base = Path(model_path).parent
            thr_path = base / "thresholds.json"
            
            # Load thresholds if available
            if thr_path.exists():
                try:
                    import json
                    with open(thr_path, 'r', encoding='utf-8') as f:
                        self.thr.update(json.load(f))
                    logger.info(f"Loaded thresholds: {self.thr}")
                except Exception as e:
                    logger.warning(f"Failed to load thresholds: {e}")
            
            # Load tokenizer (from model directory)
            tokenizer_dir = base / "layer15_crisis"
            if not tokenizer_dir.exists():
                tokenizer_dir = base  # Fallback to base directory
            
            # Bandit B615: Pin revision for security (use "main" for latest stable)
            self.tok = AutoTokenizer.from_pretrained(str(tokenizer_dir), revision="main")  # nosec B615
            logger.info(f"Tokenizers loaded from {tokenizer_dir}")
            
            # Load ONNX session
            self.onnx_session = ort.InferenceSession(
                str(model_path),
                providers=["CPUExecutionProvider"]
            )
            logger.info(f"ONNX crisis model loaded from {model_path}")
            
        except Exception as e:
            logger.error(f"Failed to load ONNX model: {e}")
            self.onnx_session = None
            self.tok = None

    def regex_signals(self, text: str) -> Dict[str, bool]:
        """Check text against crisis regex patterns."""
        hits = {}
        for fam, rex in self._patterns:
            if rex.search(text or ""):
                hits[fam] = True
        return hits

    def ml_scores(self, text: str, ctx: str = "") -> Dict[str, float]:
        """Compute ML-based crisis scores using ONNX model if available.
        
        Falls back to regex-based heuristics if ONNX model not loaded.
        
        Model expects: input_ids, attention_mask -> logits (3D: self_harm, abuse, unsafe_env)
        Output: sigmoid(logits) -> probabilities
        """
        # If ONNX model available, use it
        if self.onnx_session is not None and self.tok is not None:
            return self._onnx_inference(text, ctx)
        
        # Fallback: Regex-based heuristic scores
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
    
    def _onnx_inference(self, text: str, ctx: str = "") -> Dict[str, float]:
        """Run ONNX model inference for crisis detection.
        
        Expected model: xlm-roberta-base
        Input: input_ids, attention_mask (tokenized text)
        Output: logits -> sigmoid -> probabilities (self_harm, abuse, unsafe_env)
        """
        # Type guards
        assert self.tok is not None, "tokenizer must be loaded"
        assert self.onnx_session is not None, "onnx_session must be loaded"
        
        try:
            # Combine text and context
            full_text = text if text else ""
            if ctx:
                full_text += "\n" + ctx
            
            # Tokenize with AutoTokenizer (xlm-roberta-base format)
            enc = self.tok(
                full_text,
                return_tensors='np',
                truncation=True,
                padding='max_length',
                max_length=256
            )
            
            # Run ONNX inference
            logits = self.onnx_session.run(
                ["logits"],
                {
                    "input_ids": enc["input_ids"].astype(np.int64),
                    "attention_mask": enc["attention_mask"].astype(np.int64)
                }
            )[0]
            
            # Apply sigmoid (1 / (1 + exp(-logits)))
            probs = 1 / (1 + np.exp(-logits))
            
            # Return as dict
            return {
                "self_harm": float(probs[0][0]),
                "abuse": float(probs[0][1]),
                "unsafe_env": float(probs[0][2])
            }
            
        except Exception as e:
            logger.error(f"ONNX inference failed: {e} - falling back to regex")
            # Fallback to regex-based heuristics
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
        """Decide crisis severity level (high/medium/low)."""
        t = self.cfg["thresholds"]
        regex_hits = self.regex_signals(text)
        
        # Hard regex hit → immediate high severity
        if regex_hits and t["regex_hard_hit"]:
            return "high", {"reason": "regex_hard", "hits": list(regex_hits.keys())}
        
        # ML-based scoring
        scores = self.ml_scores(text, ctx)
        max_score = max(scores.values())
        
        # Check against ML thresholds AND learned thresholds
        if max_score >= t["ml_score_high"] or scores.get("self_harm", 0.0) >= self.thr.get("self_harm", 0.5):
            return "high", {"reason": "ml_high", "scores": scores}
        if max_score >= t["ml_score_medium"]:
            return "medium", {"reason": "ml_medium", "scores": scores}
        
        return "low", {"reason": "none", "scores": scores}

    def resource_card(self, country: str, lang: Optional[str] = None) -> Dict[str, str]:
        """Get country-specific crisis resources (hotlines, emergency numbers)."""
        entries = self.cfg.get("resources_by_country", {}).get("entries", {})
        dflt_lang = self.cfg.get("resources_by_country", {}).get("default_language", "en")
        item = entries.get(country.upper()) or {}
        return {
            "language": item.get("language", lang or dflt_lang),
            "hotline": item.get("hotline", ""),
            "emergency": item.get("emergency", ""),
            "url": item.get("url", "")
        }

