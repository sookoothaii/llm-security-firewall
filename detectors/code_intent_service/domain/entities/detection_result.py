"""
Detection Result Entity

Core business object representing the result of a detection operation.
"""
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime

import sys
from pathlib import Path

# Add detectors directory to path for shared imports
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.domain.value_objects import RiskScore


@dataclass
class DetectionResult:
    """Result of a code intent detection operation"""
    
    risk_score: RiskScore
    is_blocked: bool
    category: Optional[str] = None  # "cybercrime", "misinformation", etc.
    matched_patterns: List[str] = None
    metadata: Dict[str, Any] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        """Initialize defaults"""
        if self.matched_patterns is None:
            self.matched_patterns = []
        if self.metadata is None:
            self.metadata = {}
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response"""
        return {
            "risk_score": float(self.risk_score),
            "confidence": self.risk_score.confidence,
            "is_blocked": self.is_blocked,
            "category": self.category,
            "matched_patterns": self.matched_patterns,
            "metadata": {
                **self.metadata,
                "source": self.risk_score.source,
                "timestamp": self.timestamp.isoformat(),
            }
        }

