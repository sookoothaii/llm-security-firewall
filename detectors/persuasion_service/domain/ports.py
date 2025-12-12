"""
Persuasion Service Domain Ports

Service-specific ports for persuasion detection.
Uses shared DetectorPort as base.
"""
from typing import Protocol, runtime_checkable, Dict, List, Optional, Any

# Import shared ports
import sys
from pathlib import Path

service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.domain.ports import DetectorPort, DetectionResult


@runtime_checkable
class PersuasionPatternAnalyzerPort(Protocol):
    """
    Port for analyzing persuasion patterns in text.
    
    Encapsulates the pattern matching logic.
    """
    
    def analyze(self, text: str) -> tuple[Dict[str, float], List[str]]:
        """
        Analyze text for persuasion patterns.
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (scores_dict, matched_patterns_list)
            - scores_dict: {"misinformation": float, "persuasion": float, "combined": float, "benign": float}
            - matched_patterns: List of pattern names that matched
        """
        ...

