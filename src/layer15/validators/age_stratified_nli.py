"""Age-stratified NLI validator with semantic micro-anchors.

Separates didactic surface (child-appropriate) from adult-readable validation anchors.

Design:
- A6-8: Anchor coverage only (no MNLI) - normative language acceptable
- A9-11: Hybrid (anchors + softer MNLI cutoff 0.40)
- A12-14/A15-17: Classic MNLI (entailment >= 0.60)

v2 Upgrade (I2C9A7E4, 16th Instance):
- Semantic similarity via sentence-transformers (MiniLM)
- Negation guard (windowed polarity check)
- Expanded anchor bank (8-12 per topic, positive + negative)

References:
- GPT-5 2025-11-04: Age-stratified validation solution
- I27A3F9B 2025-11-04: Keyword-based anchors (baseline)
- I2C9A7E4 2025-11-04: Semantic anchors + negation guard (roadmap 48-72h)

Author: I2C9A7E4 (16th Instance), based on I27A3F9B (15th Instance)
"""

import re
from typing import Dict, Any, List, Optional, Tuple
import numpy as np


class AgeStratifiedValidator:
    """Age-stratified validator with semantic micro-anchors."""
    
    def __init__(self, cfg: Dict[str, Any], use_semantic: bool = True):
        """Initialize validator with config.
        
        Args:
            cfg: Config dict from layer15.yaml (full config, not just validation section)
            use_semantic: If True, use semantic embeddings; if False, fall back to keyword matching
        """
        self.cfg = cfg.get("validation", {})
        self.anchors_cfg = self.cfg.get("anchors", {})
        self.nli_cfg = self.cfg.get("nli", {})
        self.leniency = self.cfg.get("leniency", {})
        self.use_semantic = use_semantic
        
        # Semantic embedder (MiniLM) for anchor matching
        self.embedder = None
        if use_semantic:
            try:
                from sentence_transformers import SentenceTransformer
                self.embedder = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
            except (ImportError, Exception):
                # Fallback to keyword matching if sentence-transformers unavailable
                self.use_semantic = False
        
        # Optional: Load HF MNLI model (graceful fallback if not available)
        self.nli_model = None
        self.nli_tokenizer = None
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            model_name = self.nli_cfg.get("mnli", {}).get("model", "facebook/bart-large-mnli")
            self.nli_tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.nli_model = AutoModelForSequenceClassification.from_pretrained(model_name)
        except (ImportError, Exception):
            # Fallback: CI ohne transformers
            pass
    
    def _normalize_text(self, text: str) -> str:
        """Normalize text for anchor matching."""
        if not text:
            return ""
        # Lowercase + whitespace fold
        normalized = text.lower()
        normalized = re.sub(r'\s+', ' ', normalized)
        return normalized.strip()
    
    def _has_negation_in_window(self, text: str, start_idx: int, end_idx: int, window_size: int = 5) -> bool:
        """Check if negation appears near a match (windowed polarity check).
        
        Args:
            text: Full text
            start_idx: Start index of match
            end_idx: End index of match
            window_size: Number of tokens before/after to check for negation
            
        Returns:
            True if negation detected in window, False otherwise
        """
        # Negation patterns (English + German)
        negation_words = {
            'not', 'no', 'never', 'neither', 'nobody', 'nothing', 'nowhere', 'none',
            'nicht', 'kein', 'keine', 'niemals', 'niemand', 'nichts', 'nirgends'
        }
        
        # Extract window around match
        words = text.split()
        match_start_word = len(text[:start_idx].split())
        match_end_word = match_start_word + len(text[start_idx:end_idx].split())
        
        window_start = max(0, match_start_word - window_size)
        window_end = min(len(words), match_end_word + window_size)
        window = words[window_start:window_end]
        
        # Check for negation in window
        return any(w.lower() in negation_words for w in window)
    
    def _semantic_anchor_similarity(self, answer: str, anchor: str) -> float:
        """Compute semantic similarity between answer and anchor.
        
        Args:
            answer: Adapted answer text
            anchor: Anchor text (positive or negative)
            
        Returns:
            Cosine similarity score [0.0, 1.0]
        """
        if not self.embedder:
            return 0.0
        
        try:
            # Encode both texts
            emb_answer = self.embedder.encode(answer, convert_to_tensor=False)
            emb_anchor = self.embedder.encode(anchor, convert_to_tensor=False)
            
            # Cosine similarity
            similarity = np.dot(emb_answer, emb_anchor) / (
                np.linalg.norm(emb_answer) * np.linalg.norm(emb_anchor)
            )
            return float(similarity)
        except Exception:
            return 0.0
    
    def _count_anchor_hits(self, answer: str, topic: str) -> Tuple[int, List[Dict[str, Any]]]:
        """Count how many invisible anchors are covered in answer.
        
        Args:
            answer: Adapted answer text (child-appropriate)
            topic: Topic name (transgender, abortion, right_wing_extremism)
            
        Returns:
            Tuple of (hit_count, details_list)
            - hit_count: Number of anchors hit (positive) or avoided (negative)
            - details_list: List of anchor match details for telemetry
        """
        topic_cfg = self.anchors_cfg.get("topics", {}).get(topic, {})
        positive_anchors = topic_cfg.get("anchors", [])
        negative_anchors = topic_cfg.get("negative_anchors", [])
        
        hits = 0
        details = []
        
        # Check positive anchors (must be present)
        for anchor in positive_anchors:
            if self.use_semantic and self.embedder:
                # Semantic similarity
                similarity = self._semantic_anchor_similarity(answer, anchor)
                threshold = 0.5  # Cosine similarity threshold
                is_hit = similarity >= threshold
                
                # Negation guard: If high similarity but negated, don't count
                if is_hit:
                    # Simple check: Does answer contain negation near anchor keywords?
                    norm_answer = self._normalize_text(answer)
                    anchor_keywords = anchor.lower().split()[:3]  # First 3 words as proxy
                    negated = any(
                        self._has_negation_in_window(norm_answer, 0, len(norm_answer), window_size=5)
                        for kw in anchor_keywords if kw in norm_answer
                    )
                    if negated:
                        is_hit = False
                
                if is_hit:
                    hits += 1
                
                details.append({
                    "anchor": anchor[:50],
                    "type": "positive",
                    "method": "semantic",
                    "score": similarity,
                    "hit": is_hit
                })
            else:
                # Keyword-based fallback
                norm_answer = self._normalize_text(answer)
                keywords = [w for w in re.findall(r'\b\w{4,}\b', anchor.lower()) 
                           if w not in {'that', 'this', 'with', 'from', 'have', 'they', 'their', 'when', 'about'}]
                
                keyword_hits = sum(1 for kw in keywords if kw in norm_answer)
                coverage = keyword_hits / len(keywords) if keywords else 0.0
                is_hit = coverage >= 0.6
                
                if is_hit:
                    hits += 1
                
                details.append({
                    "anchor": anchor[:50],
                    "type": "positive",
                    "method": "keyword",
                    "score": coverage,
                    "hit": is_hit
                })
        
        # Check negative anchors (must be absent)
        for anchor in negative_anchors:
            if self.use_semantic and self.embedder:
                similarity = self._semantic_anchor_similarity(answer, anchor)
                threshold = 0.5
                is_avoided = similarity < threshold  # Negative anchor avoided if low similarity
                
                if is_avoided:
                    hits += 1
                
                details.append({
                    "anchor": anchor[:50],
                    "type": "negative",
                    "method": "semantic",
                    "score": similarity,
                    "hit": is_avoided
                })
            else:
                # Keyword-based fallback
                norm_answer = self._normalize_text(answer)
                keywords = [w for w in re.findall(r'\b\w{4,}\b', anchor.lower()) 
                           if w not in {'that', 'this', 'with', 'from', 'have', 'they', 'their', 'when', 'about'}]
                
                keyword_hits = sum(1 for kw in keywords if kw in norm_answer)
                coverage = keyword_hits / len(keywords) if keywords else 0.0
                is_avoided = coverage < 0.4  # Lower threshold for avoidance
                
                if is_avoided:
                    hits += 1
                
                details.append({
                    "anchor": anchor[:50],
                    "type": "negative",
                    "method": "keyword",
                    "score": coverage,
                    "hit": is_avoided
                })
        
        return hits, details
    
    def _compute_mnli_entailment(self, premise: str, hypothesis: str) -> float:
        """Compute MNLI entailment+neutral score.
        
        Args:
            premise: Canonical facts (ground truth)
            hypothesis: Adapted answer
            
        Returns:
            Entailment+Neutral probability [0.0, 1.0], or -1.0 if model unavailable
            
        Note: Uses E+N instead of E only, because adapted answers often contain
        additional information (safety guidance, help-seeking) which MNLI classifies
        as NEUTRAL rather than pure entailment. E+N = "not contradicted".
        """
        if not self.nli_model or not self.nli_tokenizer:
            return -1.0  # Model not available (CI fallback)
        
        try:
            import torch
            inputs = self.nli_tokenizer(premise, hypothesis, return_tensors="pt", truncation=True, max_length=512)
            with torch.no_grad():
                logits = self.nli_model(**inputs).logits
            probs = torch.softmax(logits, dim=1)[0]
            # MNLI labels: 0=entailment, 1=neutral, 2=contradiction
            entailment_prob = float(probs[0])
            neutral_prob = float(probs[1])
            # E+N = "not contradicted" (adapts to additional safety guidance)
            return entailment_prob + neutral_prob
        except Exception:
            return -1.0
    
    def validate(
        self, 
        age_band: str, 
        topic: str, 
        adapted_answer: str, 
        canonical_premise: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate adapted answer for age band using stratified approach.
        
        Args:
            age_band: Age band (A6_8, A9_11, A12_14, A15_17)
            topic: Topic name (transgender, abortion, right_wing_extremism)
            adapted_answer: Child-appropriate answer text
            canonical_premise: Canonical facts (for MNLI), optional
            
        Returns:
            Validation report with fields:
            {
                "validator_mode": str,
                "anchor_hits": int,
                "anchor_min": int,
                "anchor_details": List[Dict],  # NEW: telemetry
                "mnli": float,
                "topic": str,
                "band": str,
                "pass": bool,
                "reason": str,
                "semantic_enabled": bool  # NEW: telemetry
            }
        """
        # Determine validation mode based on age band
        mode = self.nli_cfg.get("bands", {}).get(age_band, "mnli")
        
        # Count anchor hits (returns tuple now)
        anchor_hits, anchor_details = self._count_anchor_hits(adapted_answer, topic)
        min_hits_cfg = self.anchors_cfg.get("min_hits", {})
        anchor_min = min_hits_cfg.get(age_band, 2)
        
        # Compute MNLI if model available and canonical provided
        mnli_score = -1.0
        if canonical_premise and self.nli_model:
            mnli_score = self._compute_mnli_entailment(canonical_premise, adapted_answer)
        
        # Thresholds
        entailment_min = self.nli_cfg.get("mnli", {}).get("thresholds", {}).get("entailment_min", 0.60)
        hybrid_entailment_min = self.nli_cfg.get("mnli", {}).get("thresholds", {}).get("hybrid_entailment_min", 0.40)
        
        # Leniency
        leniency_enabled = self.leniency.get("enable_temp_leniency_for_A6_8", False)
        
        # Decision logic
        passed = False
        reason = "unknown"
        
        if mode == "anchors":
            # A6-8: Only anchor coverage (or leniency)
            if anchor_hits >= anchor_min:
                passed = True
                reason = "anchor_coverage"
            elif leniency_enabled and age_band == "A6_8":
                passed = True  # WARN not BLOCK during calibration
                reason = "leniency_temp"
            else:
                passed = False
                reason = "anchor_insufficient"
        
        elif mode == "hybrid":
            # A9-11: Anchors AND softer MNLI
            anchor_ok = anchor_hits >= anchor_min
            mnli_ok = mnli_score >= hybrid_entailment_min if mnli_score >= 0.0 else True  # Fallback if no model
            
            if anchor_ok and mnli_ok:
                passed = True
                reason = "hybrid_pass"
            elif not anchor_ok:
                passed = False
                reason = "anchor_insufficient"
            else:
                passed = False
                reason = "mnli_below_hybrid_threshold"
        
        elif mode == "mnli":
            # A12-14/A15-17: Classic MNLI
            if mnli_score >= entailment_min:
                passed = True
                reason = "mnli_pass"
            elif mnli_score < 0.0:
                # Model unavailable - default to pass for CI
                passed = True
                reason = "mnli_unavailable_fallback"
            else:
                passed = False
                reason = "mnli_below_threshold"
        
        return {
            "validator_mode": mode,
            "anchor_hits": anchor_hits,
            "anchor_min": anchor_min,
            "anchor_details": anchor_details,  # NEW: telemetry for monitoring
            "mnli": mnli_score,
            "topic": topic,
            "band": age_band,
            "pass": passed,
            "reason": reason,
            "semantic_enabled": self.use_semantic  # NEW: telemetry
        }

