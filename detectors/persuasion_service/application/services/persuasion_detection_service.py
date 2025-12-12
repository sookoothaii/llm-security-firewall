"""
Persuasion Detection Service Implementation

Application service that orchestrates persuasion detection.
Implements DetectorPort from shared components.
"""
import logging
from typing import Optional, Dict, Any
from datetime import datetime

# Import shared components
import sys
from pathlib import Path

service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.domain.ports import DetectorPort, DetectionResult
from shared.domain.value_objects import RiskScore

# Import domain ports
from domain.ports import PersuasionPatternAnalyzerPort

logger = logging.getLogger(__name__)


class PersuasionDetectionService:
    """
    Persuasion detection service implementation.
    
    Orchestrates:
    1. Pattern analysis (persuasion/misinformation patterns)
    2. Context adjustment (sensitive topics)
    3. Risk score calculation
    4. Detection result creation
    """
    
    def __init__(
        self,
        pattern_analyzer: PersuasionPatternAnalyzerPort,
        block_threshold: float = 0.5,
    ):
        """
        Initialize persuasion detection service.
        
        Args:
            pattern_analyzer: Pattern analyzer port implementation
            block_threshold: Risk score threshold for blocking (0.0-1.0)
        """
        self.pattern_analyzer = pattern_analyzer
        self.block_threshold = block_threshold
        logger.info(f"PersuasionDetectionService initialized (threshold: {self.block_threshold})")
    
    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        Detect persuasion and misinformation patterns.
        
        Implements DetectorPort protocol.
        
        Args:
            text: Text to analyze
            context: Optional context (topic, user_id, session_id, etc.)
            
        Returns:
            DetectionResult with risk_score and detection details
        """
        context = context or {}
        
        # Analyze text for patterns
        scores, matched_patterns = self.pattern_analyzer.analyze(text)
        
        # Context adjustment for sensitive topics
        topic = context.get("topic", "").lower()
        if topic in ["health", "finance", "politics"]:
            # Increase sensitivity for sensitive topics
            scores["misinformation"] = min(1.0, scores["misinformation"] * 1.3)
            scores["persuasion"] = min(1.0, scores["persuasion"] * 1.2)
            scores["combined"] = max(scores["misinformation"], scores["persuasion"])
        
        # Use combined score as risk_score
        risk_score_value = scores["combined"]
        
        # Determine category
        if scores["misinformation"] > scores["persuasion"]:
            category = "misinformation"
            confidence = scores["misinformation"]
        elif scores["persuasion"] > 0.0:
            category = "persuasion"
            confidence = scores["persuasion"]
        else:
            category = None
            confidence = 0.0
        
        # Create RiskScore value object
        risk_score = RiskScore.create(
            value=risk_score_value,
            confidence=confidence,
            source="persuasion_detector"
        )
        
        # Determine if blocked
        is_blocked = risk_score.is_above_threshold(self.block_threshold)
        
        # Create DetectionResult
        result = DetectionResult(
            risk_score=risk_score,
            is_blocked=is_blocked,
            detector_name="persuasion_misinfo",
            category=category,
            matched_patterns=matched_patterns,
            metadata={
                "method": "rule_based",
                "scores": scores,
                "context": context,
            },
            timestamp=datetime.now()
        )
        
        logger.debug(
            f"Detection result: risk={risk_score_value:.3f}, "
            f"category={category}, blocked={is_blocked}, patterns={len(matched_patterns)}"
        )
        
        return result
    
    def get_name(self) -> str:
        """Get detector name (implements DetectorPort)"""
        return "persuasion_misinfo"

