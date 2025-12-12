"""
Content Safety Detection Service Implementation

Application service that orchestrates content safety detection.
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
from domain.ports import ContentSafetyAnalyzerPort

logger = logging.getLogger(__name__)


class ContentSafetyDetectionService:
    """
    Content safety detection service implementation.
    
    Orchestrates:
    1. Pattern analysis (jailbreak, content violations, roleplay bypass)
    2. Risk score calculation
    3. Category determination
    4. Detection result creation
    """
    
    def __init__(
        self,
        content_safety_analyzer: ContentSafetyAnalyzerPort,
        block_threshold: float = 0.5,
    ):
        """
        Initialize content safety detection service.
        
        Args:
            content_safety_analyzer: Content safety analyzer port implementation
            block_threshold: Risk score threshold for blocking (0.0-1.0)
        """
        self.content_safety_analyzer = content_safety_analyzer
        self.block_threshold = block_threshold
        logger.info(f"ContentSafetyDetectionService initialized (threshold: {self.block_threshold})")
    
    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """
        Detect content safety violations and jailbreak attempts.
        
        Implements DetectorPort protocol.
        
        Args:
            text: Text to analyze
            context: Optional context (user_id, session_id, etc.)
            
        Returns:
            DetectionResult with risk_score and detection details
        """
        context = context or {}
        
        # Analyze text for patterns
        scores, matched_patterns = self.content_safety_analyzer.analyze(text)
        
        # Use content_safety score as risk_score
        risk_score_value = scores["content_safety"]
        
        # Determine category based on matched patterns
        category = None
        if risk_score_value > 0.7:
            if any("jailbreak" in p for p in matched_patterns):
                category = "jailbreak"
            elif any("content_" in p for p in matched_patterns):
                category = "content_violation"
            else:
                category = "suspicious"
        
        # Calculate confidence
        confidence = risk_score_value if risk_score_value > 0.5 else 1.0 - risk_score_value
        
        # Create RiskScore value object
        risk_score = RiskScore.create(
            value=risk_score_value,
            confidence=confidence,
            source="content_safety_detector"
        )
        
        # Determine if blocked
        is_blocked = risk_score.is_above_threshold(self.block_threshold)
        
        # Determine detection method
        if risk_score_value >= 0.8:
            method = "rule_engine_high_confidence"
        elif risk_score_value >= 0.5:
            method = "rule_engine_medium_confidence"
        else:
            method = "rule_engine_benign"
        
        # Create DetectionResult
        result = DetectionResult(
            risk_score=risk_score,
            is_blocked=is_blocked,
            detector_name="content_safety",
            category=category,
            matched_patterns=matched_patterns,
            metadata={
                "method": method,
                "rule_score": risk_score_value,
                "scores": scores,
                "detector_type": "rule_engine",
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
        return "content_safety"

