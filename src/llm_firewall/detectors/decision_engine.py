"""
Decision Engine - LLM Firewall Battle Plan
==========================================

Combines results from multiple detectors and makes final blocking decision.
Implements conservative OR-logic: one detector blocks = BLOCK.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-09
Status: Phase 2 - Multi-Detector Orchestration
License: MIT
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from llm_firewall.detectors.detector_registry import DetectorResponse

logger = logging.getLogger(__name__)


@dataclass
class CombinedDecision:
    """Final decision from multiple detectors."""
    decision: str  # "ALLOWED" or "BLOCKED"
    risk_score: float  # [0.0, 1.0]
    confidence: float  # [0.0, 1.0]
    blocked_by: Optional[str] = None  # Detector name that blocked
    detector_results: Dict[str, DetectorResponse] = None
    explanation: str = ""


class DecisionEngine:
    """
    Combines results from multiple detectors and makes final decision.
    
    Strategy: Conservative OR-logic
    - If ANY detector blocks (risk_score > threshold), final decision = BLOCKED
    - If ALL detectors allow, final decision = ALLOWED
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize decision engine.
        
        Args:
            config: Configuration dict with thresholds and weights
        """
        self.config = config or {}
        self.thresholds = self.config.get("thresholds", {
            "code_intent": {"default": 0.55},
            "content_safety": {"default": 0.60}
        })
        self.combination_strategy = self.config.get("combination_strategy", "conservative")
        self.minimum_confidence = self.config.get("minimum_confidence", 0.70)
        
        logger.info(
            f"DecisionEngine initialized "
            f"(strategy={self.combination_strategy}, min_confidence={self.minimum_confidence})"
        )
    
    def combine_decisions(
        self,
        detector_results: Dict[str, DetectorResponse],
        context: Optional[Dict[str, Any]] = None
    ) -> CombinedDecision:
        """
        Combine results from multiple detectors and make final decision.
        
        Args:
            detector_results: Dict mapping detector_name -> DetectorResponse
            context: Optional context (session_id, user_context, etc.)
            
        Returns:
            CombinedDecision with final decision and explanation
        """
        if not detector_results:
            # No detectors ran - default to ALLOWED
            return CombinedDecision(
                decision="ALLOWED",
                risk_score=0.0,
                confidence=0.5,
                detector_results={},
                explanation="No detectors invoked"
            )
        
        context = context or {}
        context_type = context.get("context_type", "general_chat")
        
        # Get thresholds for context
        code_threshold = self._get_threshold("code_intent", context_type, context)
        safety_threshold = self._get_threshold("content_safety", context_type, context)
        
        # Extract scores from each detector
        code_result = detector_results.get("code_intent")
        safety_result = detector_results.get("content_safety")
        
        code_score = code_result.risk_score if code_result and not code_result.error else 0.0
        safety_score = safety_result.risk_score if safety_result and not safety_result.error else 0.0
        
        # Check if any detector blocks
        code_blocked = code_result and code_score > code_threshold
        safety_blocked = safety_result and safety_score > safety_threshold
        
        # Conservative OR-logic: ONE detector blocks = BLOCK
        if code_blocked or safety_blocked:
            # Determine which detector(s) blocked
            blocking_detectors = []
            if code_blocked:
                blocking_detectors.append("code_intent")
            if safety_blocked:
                blocking_detectors.append("content_safety")
            
            blocked_by = " + ".join(blocking_detectors) if len(blocking_detectors) > 1 else blocking_detectors[0]
            
            # Calculate combined risk score (max of both)
            combined_risk = max(code_score, safety_score)
            
            # Calculate confidence (average of both, or single if one failed)
            confidences = []
            if code_result and not code_result.error:
                confidences.append(code_result.confidence)
            if safety_result and not safety_result.error:
                confidences.append(safety_result.confidence)
            
            combined_confidence = sum(confidences) / len(confidences) if confidences else 0.5
            
            # Generate explanation
            explanation_parts = []
            if code_blocked:
                explanation_parts.append(
                    f"Code-Intent detected risk {code_score:.2f} (threshold: {code_threshold:.2f})"
                )
            if safety_blocked:
                explanation_parts.append(
                    f"Content-Safety detected risk {safety_score:.2f} (threshold: {safety_threshold:.2f})"
                )
            explanation = " | ".join(explanation_parts)
            
            return CombinedDecision(
                decision="BLOCKED",
                risk_score=combined_risk,
                confidence=combined_confidence,
                blocked_by=blocked_by,
                detector_results=detector_results,
                explanation=explanation
            )
        
        # ALL detectors allow
        combined_risk = max(code_score, safety_score)
        
        # Calculate confidence
        confidences = []
        if code_result and not code_result.error:
            confidences.append(code_result.confidence)
        if safety_result and not safety_result.error:
            confidences.append(safety_result.confidence)
        
        combined_confidence = sum(confidences) / len(confidences) if confidences else 0.5
        
        return CombinedDecision(
            decision="ALLOWED",
            risk_score=combined_risk,
            confidence=combined_confidence,
            detector_results=detector_results,
            explanation=f"All detectors allowed (code_intent: {code_score:.2f}, content_safety: {safety_score:.2f})"
        )
    
    def _get_threshold(
        self,
        detector_name: str,
        context_type: str,
        context: Dict[str, Any]
    ) -> float:
        """Get threshold for detector based on context."""
        detector_thresholds = self.thresholds.get(detector_name, {})
        
        # Check for context-specific threshold
        if context_type in detector_thresholds:
            return detector_thresholds[context_type]
        
        # Check for special context conditions
        if detector_name == "content_safety":
            # Higher threshold for documentary/research contexts
            if context.get("is_documentary", False) or context.get("is_research", False):
                return detector_thresholds.get("documentary_context", 0.75)
        
        # Default threshold
        return detector_thresholds.get("default", 0.5)

