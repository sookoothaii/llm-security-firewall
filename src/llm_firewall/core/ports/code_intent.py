"""
Code Intent Detection Ports - Protocol Definitions

Extends the existing ports structure for code intent detection.
Follows the same pattern as DecisionCachePort, DecoderPort, etc.

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
Status: P0 - Integration with existing ports
License: MIT
"""

from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, Tuple
from dataclasses import dataclass


@dataclass
class ClassificationResult:
    """Result of intent classification"""
    score: float
    method: str  # "quantum_cnn", "codebert", "rule_based"
    confidence: Optional[float] = None
    is_execution_request: bool = False
    metadata: Optional[Dict[str, Any]] = None


@runtime_checkable
class CodeIntentDetectorPort(Protocol):
    """
    Port for code intent detection (main detection interface).
    
    Analog to ValidatorPort - provides unified interface for code intent detection.
    
    Adapters implementing this protocol:
    - CodeIntentDetectorAdapter (main implementation)
    - SimpleRuleBasedDetector (fallback)
    - MockCodeIntentDetector (tests)
    
    Usage:
        detector: CodeIntentDetectorPort = CodeIntentDetectorAdapter(...)
        risk_score, patterns = detector.detect("Please run ls", context={"user_id": "123"})
    """
    
    def detect(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Tuple[float, List[str]]:
        """
        Detect code intent and return risk score with matched patterns.
        
        Args:
            text: Text to analyze
            context: Optional context (e.g., user_id, session_id)
        
        Returns:
            Tuple of (risk_score: 0.0-1.0, matched_patterns: list[str])
            - risk_score: 0.0 (benign) to 1.0 (malicious)
            - matched_patterns: List of pattern names that matched
        """
        ...


@runtime_checkable
class BenignValidatorPort(Protocol):
    """
    Port for benign text validation (specialized validator).
    
    Analog to ValidatorPort but specialized for benign detection.
    
    Adapters implementing this protocol:
    - BenignValidatorComposite (current implementation)
    - LegacyBenignValidator (migration bridge)
    - MockBenignValidator (tests)
    
    Usage:
        validator: BenignValidatorPort = BenignValidatorComposite([...])
        is_benign = validator.is_benign("What is ls?")
    """
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text is benign (not malicious).
        
        Args:
            text: Text to validate
            
        Returns:
            True if text is benign, False if potentially malicious
        """
        ...


@runtime_checkable
class IntentClassifierPort(Protocol):
    """
    Port for intent classification (ML models).
    
    Adapters implementing this protocol:
    - QuantumCNNClassifier
    - CodeBERTClassifier
    - RuleBasedClassifier (fallback)
    
    Usage:
        classifier: IntentClassifierPort = QuantumCNNClassifier(...)
        result = classifier.classify("Please run ls")
    """
    
    def classify(self, text: str) -> ClassificationResult:
        """
        Classify text intent (question vs execution request).
        
        Args:
            text: Text to classify
            
        Returns:
            ClassificationResult with score, method, confidence
        """
        ...
    
    def is_available(self) -> bool:
        """
        Check if classifier is available (model loaded).
        
        Returns:
            True if classifier is ready, False otherwise
        """
        ...


__all__ = [
    "CodeIntentDetectorPort",
    "BenignValidatorPort",
    "IntentClassifierPort",
    "ClassificationResult",
]

