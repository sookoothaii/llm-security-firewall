"""
Content Safety Service Domain Ports

Service-specific ports for content safety detection.
Uses shared DetectorPort as base.
"""
from typing import Protocol, runtime_checkable, Dict, List

# Import shared components
import sys
from pathlib import Path

service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))


@runtime_checkable
class ContentSafetyAnalyzerPort(Protocol):
    """
    Port for analyzing content safety violations and jailbreak attempts.
    
    Encapsulates the pattern matching logic for:
    - Jailbreak patterns
    - Content safety violations
    - Roleplay bypass attempts
    """
    
    def analyze(self, text: str) -> tuple[Dict[str, float], List[str]]:
        """
        Analyze text for content safety violations.
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (scores_dict, matched_patterns_list)
            - scores_dict: {"content_safety": float, "benign": float}
            - matched_patterns: List of pattern names that matched
        """
        ...

