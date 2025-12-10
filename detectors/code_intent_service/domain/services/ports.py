"""
Domain Service Ports - Protocol Definitions

Analog zu src/llm_firewall/core/ports/ - verwendet Python Protocols
für strukturelles Typing ohne Runtime-Overhead.
"""
from typing import Protocol, runtime_checkable, Optional, Dict, Any, List, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from domain.value_objects.risk_score import RiskScore


@dataclass
class ClassificationResult:
    """Result of intent classification"""
    score: float
    method: str  # "quantum_cnn", "codebert", "rule_based"
    confidence: Optional[float] = None
    is_execution_request: bool = False
    metadata: Optional[Dict[str, Any]] = None


@runtime_checkable
class BenignValidatorPort(Protocol):
    """
    Port for benign text validation.
    
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


@runtime_checkable
class RuleEnginePort(Protocol):
    """
    Port for rule-based pattern matching.
    
    Adapters implementing this protocol:
    - PatternMatcher (current implementation)
    - SQLInjectionDetector
    - SocialEngineeringDetector
    
    Usage:
        engine: RuleEnginePort = PatternMatcher(...)
        scores, patterns = engine.analyze("rm -rf /")
    """
    
    def analyze(self, text: str) -> tuple[Dict[str, float], List[str]]:
        """
        Analyze text using rule-based patterns.
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (risk_scores_dict, matched_patterns_list)
        """
        ...


@runtime_checkable
class FeedbackRepositoryPort(Protocol):
    """
    Port for feedback sample storage.
    
    Adapters implementing this protocol:
    - FeedbackBufferRepository (in-memory buffer)
    - PostgreSQLFeedbackRepository (persistent)
    - NullFeedbackRepository (disabled)
    
    Usage:
        repo: FeedbackRepositoryPort = FeedbackBufferRepository(max_size=10000)
        repo.add(sample)
    """
    
    def add(self, sample: Dict[str, Any]) -> None:
        """
        Add feedback sample to repository.
        
        Args:
            sample: Feedback sample dict with text, result, etc.
        """
        ...
    
    def get_samples(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get feedback samples for training.
        
        Args:
            limit: Maximum number of samples to return
            
        Returns:
            List of feedback sample dicts
        """
        ...


@dataclass(frozen=True)
class DetectionResult:
    """Value Object für Detection-Ergebnis."""
    risk_score: "RiskScore"  # Forward reference
    matched_patterns: List[str]
    blocked: bool
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_malicious(self) -> bool:
        """Convenience property."""
        return self.blocked


@runtime_checkable
class DetectionServicePort(Protocol):
    """
    Port für den kompletten Detection Service.
    
    Adapters implementing this protocol:
    - DetectionServiceImpl (main implementation)
    - MockDetectionService (tests)
    
    Usage:
        service: DetectionServicePort = DetectionServiceImpl(...)
        result = service.detect("rm -rf /", context={"user_id": "123"})
    """
    
    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        Hauptmethode: Analysiert Text auf bösartige Intents.
        
        Args:
            text: Der zu analysierende Text
            context: Optionaler Kontext (User-ID, Session, Tools, etc.)
            
        Returns:
            DetectionResult mit risk_score und matched_patterns
        """
        ...


__all__ = [
    "BenignValidatorPort",
    "IntentClassifierPort",
    "RuleEnginePort",
    "FeedbackRepositoryPort",
    "ClassificationResult",
    "DetectionServicePort",
    "DetectionResult",
]

