"""
Code Intent Detector Adapter

Adapter that implements CodeIntentDetectorPort following the same pattern
as DecisionCacheAdapter in the main project.

FAIL-SAFE POLICY:
- Circuit breaker OPEN → Automatically fallback to simple rule-based detector
- This contains failure policy in adapter layer (not domain layer)
- Prevents detection failure from bypassing security (fail-safe, not fail-open)

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
Status: P0 - Integration with existing adapter pattern
License: MIT
"""

import logging
from typing import Optional, Dict, Any, List, Tuple

from llm_firewall.core.ports.code_intent import CodeIntentDetectorPort

logger = logging.getLogger(__name__)


class SimpleRuleBasedDetector:
    """
    Simple fallback detector for circuit breaker scenarios.
    
    Uses basic pattern matching when main detector is unavailable.
    """
    
    def detect(self, text: str) -> Tuple[float, List[str]]:
        """Simple rule-based detection as fallback"""
        # Very basic patterns
        dangerous_patterns = [
            ("rm -rf", 0.9),
            ("sudo", 0.7),
            ("bash -c", 0.8),
            ("eval(", 0.9),
            ("exec(", 0.8),
        ]
        
        text_lower = text.lower()
        max_score = 0.0
        matched = []
        
        for pattern, score in dangerous_patterns:
            if pattern in text_lower:
                max_score = max(max_score, score)
                matched.append(pattern)
        
        return (max_score, matched)


class CodeIntentDetectorAdapter(CodeIntentDetectorPort):
    """
    Adapter that implements CodeIntentDetectorPort.
    
    Follows the same pattern as DecisionCacheAdapter:
    - Circuit breaker for resilience
    - Fail-safe fallback
    - Error handling in adapter layer
    
    FAIL-SAFE BEHAVIOR:
    - Checks circuit breaker status before attempting detection
    - If circuit OPEN: Automatically falls back to SimpleRuleBasedDetector
    - Failure policy is contained in adapter layer, not domain layer
    """
    
    def __init__(
        self,
        benign_validator,
        intent_classifier: Optional[Any] = None,
        rule_engine: Optional[Any] = None,
        settings: Optional[Any] = None,
        fallback_detector: Optional[SimpleRuleBasedDetector] = None,
    ):
        """
        Initialize adapter.
        
        Args:
            benign_validator: BenignValidatorPort implementation
            intent_classifier: IntentClassifierPort implementation (optional)
            rule_engine: RuleEnginePort implementation (optional)
            settings: DetectionSettings
            fallback_detector: Detector to use when circuit breaker is OPEN.
                             Defaults to SimpleRuleBasedDetector (fail-safe behavior).
        """
        self.benign_validator = benign_validator
        self.intent_classifier = intent_classifier
        self.rule_engine = rule_engine
        self.settings = settings
        
        # Set up fail-safe fallback
        if fallback_detector is None:
            self.fallback_detector = SimpleRuleBasedDetector()
        else:
            self.fallback_detector = fallback_detector
        
        # Circuit breaker (simplified - can be enhanced later)
        self.circuit_breaker_open = False
        self.failure_count = 0
        self.failure_threshold = 3
        
        logger.info("CodeIntentDetectorAdapter initialized with fail-safe fallback")
    
    def _is_circuit_open(self) -> bool:
        """
        Check if circuit breaker is open.
        
        Returns:
            True if circuit is open (too many failures)
        """
        return self.circuit_breaker_open
    
    def _on_success(self) -> None:
        """Reset circuit breaker on success"""
        self.circuit_breaker_open = False
        self.failure_count = 0
    
    def _on_failure(self) -> None:
        """Increment failure count and open circuit if threshold reached"""
        self.failure_count += 1
        if self.failure_count >= self.failure_threshold:
            self.circuit_breaker_open = True
            logger.warning(
                f"Circuit breaker OPEN after {self.failure_count} failures. "
                "Using fallback detector."
            )
    
    def detect(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[float, List[str]]:
        """
        Detect code intent with circuit breaker and fallback.
        
        Args:
            text: Text to analyze
            context: Optional context (e.g., user_id, session_id)
        
        Returns:
            Tuple of (risk_score: 0.0-1.0, matched_patterns: list[str])
        """
        try:
            # Circuit breaker check
            if self._is_circuit_open():
                logger.debug("Circuit breaker OPEN - using fallback detector")
                return self.fallback_detector.detect(text)
            
            # Perform detection
            result = self._perform_detection(text, context)
            
            # Success
            self._on_success()
            return result
            
        except Exception as e:
            # Failure
            self._on_failure()
            
            # Logging (consistent with other adapters)
            logger.warning(
                f"Code intent detection failed: {e}",
                extra={"text_preview": text[:50] if text else ""},
                exc_info=True
            )
            
            # Fallback
            return self.fallback_detector.detect(text)
    
    def _perform_detection(
        self,
        text: str,
        context: Optional[Dict[str, Any]]
    ) -> Tuple[float, List[str]]:
        """
        Core detection logic.
        
        Args:
            text: Text to analyze
            context: Optional context
        
        Returns:
            Tuple of (risk_score, matched_patterns)
        """
        # 1. Early benign check
        if self.benign_validator.is_benign(text):
            return (0.0, [])
        
        # 2. ML classification (if available)
        ml_score = 0.0
        ml_patterns = []
        if self.intent_classifier and self.intent_classifier.is_available():
            try:
                ml_result = self.intent_classifier.classify(text)
                ml_score = ml_result.score
                if ml_result.is_execution_request:
                    ml_patterns.append("execution_request")
            except Exception as e:
                logger.debug(f"ML classification failed: {e}")
        
        # 3. Rule engine (if available)
        rule_score = 0.0
        rule_patterns = []
        if self.rule_engine:
            try:
                rule_score, rule_patterns = self.rule_engine.analyze(text)
            except Exception as e:
                logger.debug(f"Rule engine failed: {e}")
        
        # 4. Hybrid score calculation
        if ml_score > 0 and rule_score > 0:
            # Both available: weighted average
            final_score = 0.6 * ml_score + 0.4 * rule_score
        elif ml_score > 0:
            # Only ML available
            final_score = ml_score
        elif rule_score > 0:
            # Only rule engine available
            final_score = rule_score
        else:
            # Neither available: conservative default
            final_score = 0.5
        
        # Combine patterns
        all_patterns = list(set(ml_patterns + rule_patterns))
        
        return (final_score, all_patterns)

