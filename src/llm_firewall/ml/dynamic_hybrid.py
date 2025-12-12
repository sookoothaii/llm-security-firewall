"""
Dynamic Hybrid Detector mit intelligenter Orchestrierung
========================================================

Adaptive Kombination von Rule-Based und Neural Network.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-08
License: MIT
"""

import torch
import torch.nn as nn
from typing import Dict, Optional, Tuple, List
import logging

logger = logging.getLogger(__name__)


class DynamicHybridDetector:
    """
    Dynamischer Hybrid Detector mit intelligenter Orchestrierung.
    
    Wählt adaptiv den effizientesten Pfad:
    - High Confidence Rules → Fast Block/Allow
    - Low Risk → Fast Allow
    - Uncertain → Expensive ML Model
    """
    
    def __init__(
        self,
        neural_model: nn.Module,
        rule_engine,
        high_confidence_threshold: float = 0.9,
        low_risk_threshold: float = 0.1,
        ml_confidence_threshold: float = 0.7
    ):
        """
        Args:
            neural_model: Neural Network Model
            rule_engine: Rule-based detection engine
            high_confidence_threshold: Threshold für schnelle Block-Entscheidung
            low_risk_threshold: Threshold für schnelle Allow-Entscheidung
            ml_confidence_threshold: ML wird nur bei Unsicherheit konsultiert
        """
        self.neural_model = neural_model
        self.rule_engine = rule_engine
        self.high_confidence_threshold = high_confidence_threshold
        self.low_risk_threshold = low_risk_threshold
        self.ml_confidence_threshold = ml_confidence_threshold
        
        # Statistics
        self.stats = {
            "fast_block": 0,
            "fast_allow": 0,
            "ml_consulted": 0,
            "total": 0
        }
    
    def detect(
        self,
        text: str,
        input_ids: Optional[torch.Tensor] = None
    ) -> Dict[str, any]:
        """
        Adaptive Detection mit intelligenter Orchestrierung.
        
        Returns:
            Dict mit risk_score, confidence, verdict, method, latency_ms
        """
        import time
        start_time = time.time()
        
        self.stats["total"] += 1
        
        # 1. Schneller, regelbasierter Pre-Filter
        rule_result = self.rule_engine.quick_scan(text)
        rule_score = rule_result.get("risk_score", 0.0)
        rule_confidence = rule_result.get("confidence", 0.0)
        matched_patterns = rule_result.get("matched_patterns", [])
        
        # 2. High Confidence Block (schnelle Entscheidung)
        if rule_score >= self.high_confidence_threshold:
            self.stats["fast_block"] += 1
            latency = (time.time() - start_time) * 1000
            
            return {
                "risk_score": rule_score,
                "confidence": rule_confidence,
                "verdict": "block",
                "method": "fast_rule_block",
                "latency_ms": latency,
                "matched_patterns": matched_patterns,
                "neural_used": False
            }
        
        # 3. Low Risk Allow (schnelle Entscheidung)
        if rule_score <= self.low_risk_threshold:
            self.stats["fast_allow"] += 1
            latency = (time.time() - start_time) * 1000
            
            return {
                "risk_score": rule_score,
                "confidence": 1.0 - rule_score,  # Confidence für "safe"
                "verdict": "allow",
                "method": "fast_rule_allow",
                "latency_ms": latency,
                "matched_patterns": matched_patterns,
                "neural_used": False
            }
        
        # 4. Unsicherheit: Teures ML-Modell konsultieren
        self.stats["ml_consulted"] += 1
        
        if input_ids is None:
            # Tokenize if needed
            if hasattr(self.neural_model, "tokenizer"):
                tokenized = self.neural_model.tokenizer(text, return_tensors="pt")
                input_ids = tokenized["input_ids"]
            else:
                # Fallback: Use rule-based only
                latency = (time.time() - start_time) * 1000
                return {
                    "risk_score": rule_score,
                    "confidence": rule_confidence,
                    "verdict": "block" if rule_score > 0.5 else "allow",
                    "method": "rule_fallback",
                    "latency_ms": latency,
                    "matched_patterns": matched_patterns,
                    "neural_used": False
                }
        
        # ML Inference
        with torch.no_grad():
            ml_logits = self.neural_model(input_ids)
            ml_probs = torch.softmax(ml_logits, dim=-1)
            ml_score = ml_probs[0][1].item()  # Assuming index 1 is malicious
            ml_confidence = max(ml_probs[0])
        
        # 5. Kombiniere Scores
        combined_score = self._combine_scores(rule_score, ml_score, rule_confidence, ml_confidence)
        combined_confidence = max(rule_confidence, ml_confidence)
        
        verdict = "block" if combined_score > 0.5 else "allow"
        latency = (time.time() - start_time) * 1000
        
        return {
            "risk_score": combined_score,
            "confidence": combined_confidence,
            "verdict": verdict,
            "method": "hybrid_ml",
            "latency_ms": latency,
            "matched_patterns": matched_patterns,
            "neural_used": True,
            "rule_score": rule_score,
            "ml_score": ml_score
        }
    
    def _combine_scores(
        self,
        rule_score: float,
        ml_score: float,
        rule_confidence: float,
        ml_confidence: float
    ) -> float:
        """
        Kombiniere Rule-based und ML Scores intelligent.
        
        Gewichtet nach Confidence: Höhere Confidence = mehr Gewicht.
        """
        # Weighted combination based on confidence
        total_confidence = rule_confidence + ml_confidence
        if total_confidence == 0:
            return max(rule_score, ml_score)
        
        rule_weight = rule_confidence / total_confidence
        ml_weight = ml_confidence / total_confidence
        
        combined = (rule_score * rule_weight) + (ml_score * ml_weight)
        
        # Boost if both agree
        if (rule_score > 0.5 and ml_score > 0.5) or (rule_score < 0.5 and ml_score < 0.5):
            # Both agree -> increase confidence
            combined = min(1.0, combined * 1.1)
        
        return combined
    
    def get_statistics(self) -> Dict[str, any]:
        """Get detection statistics."""
        total = self.stats["total"]
        if total == 0:
            return {}
        
        return {
            "total_requests": total,
            "fast_block": self.stats["fast_block"],
            "fast_allow": self.stats["fast_allow"],
            "ml_consulted": self.stats["ml_consulted"],
            "fast_decision_rate": (self.stats["fast_block"] + self.stats["fast_allow"]) / total,
            "ml_usage_rate": self.stats["ml_consulted"] / total
        }


class RuleEngine:
    """Einfache Rule Engine für Pre-Filtering."""
    
    def __init__(self):
        self.patterns = [
            # High confidence patterns
            (r"rm -rf", 0.95, "destructive_file_operation"),
            (r"DROP TABLE", 0.9, "sql_destructive"),
            (r"bash -i", 0.9, "reverse_shell"),
            (r"chmod 777", 0.85, "permission_escalation"),
            
            # Medium confidence patterns
            (r"curl http://", 0.6, "remote_code_fetch"),
            (r"eval\(", 0.7, "code_execution"),
            (r"system\(", 0.65, "system_call"),
            
            # Low risk (benign)
            (r"echo ", 0.05, "benign_command"),
            (r"SELECT \* FROM", 0.1, "benign_query"),
        ]
    
    def quick_scan(self, text: str) -> Dict[str, any]:
        """Schneller Rule-based Scan."""
        import re
        
        risk_score = 0.0
        matched_patterns = []
        max_pattern_score = 0.0
        
        text_lower = text.lower()
        
        for pattern, weight, pattern_name in self.patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                matched_patterns.append(pattern_name)
                max_pattern_score = max(max_pattern_score, weight)
                risk_score = min(1.0, risk_score + weight * 0.3)  # Accumulate but cap
        
        # Use max pattern score as base, add accumulation bonus
        if matched_patterns:
            risk_score = min(1.0, max_pattern_score + (len(matched_patterns) - 1) * 0.1)
            confidence = min(1.0, max_pattern_score + 0.1)
        else:
            confidence = 0.5  # Medium confidence for no matches
        
        return {
            "risk_score": risk_score,
            "confidence": confidence,
            "matched_patterns": matched_patterns
        }
