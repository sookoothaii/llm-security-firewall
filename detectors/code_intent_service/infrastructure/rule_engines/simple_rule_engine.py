"""
Simple Rule Engine - Temporäre Implementation
==============================================

Einfache temporäre Rule Engine bis der vollständige PatternMatcherAdapter fertig ist.

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import logging
import re
from typing import Dict, List, Tuple

from domain.services.ports import RuleEnginePort

logger = logging.getLogger(__name__)


class SimpleRuleEngine:
    """
    Einfache temporäre Rule Engine.
    Später durch PatternMatcherAdapter ersetzen.
    """
    
    def __init__(self):
        """Initialize simple rule engine with basic patterns."""
        # Pattern: (regex, score, name)
        self.patterns = [
            (r'\brm\s+-rf\b', 0.9, 'destructive_rm'),
            (r'\bDROP\s+TABLE\b', 0.9, 'sql_drop'),
            (r';\s*(ls|cat|rm|whoami|id|bash|sh|cmd|powershell)\b', 0.7, 'command_injection'),
            (r'/etc/passwd', 0.6, 'sensitive_file'),
            (r'eval\s*\(', 0.8, 'code_execution'),
            (r'exec\s*\(', 0.8, 'code_execution'),
            (r'system\s*\(', 0.8, 'code_execution'),
            (r'shell_exec\s*\(', 0.8, 'code_execution'),
            (r'<script>', 0.7, 'xss_attempt'),
            (r'UNION\s+SELECT', 0.8, 'sql_injection'),
            (r'OR\s+1\s*=\s*1', 0.7, 'sql_injection'),
            (r'\.\./', 0.5, 'path_traversal'),
            (r'\.\.\\', 0.5, 'path_traversal'),
            # Execution request patterns
            (r'^\s*(please|kindly|can you|could you)\s+(run|execute|launch)\s+', 0.8, 'execution_request'),
            (r'^\s*(ls|cat|rm|whoami|id|pwd|bash|sh|python|perl|ruby|php|node)\s*$', 0.7, 'standalone_command'),
        ]
        logger.info(f"SimpleRuleEngine initialized with {len(self.patterns)} patterns")
    
    def analyze(self, text: str) -> Tuple[Dict[str, float], List[str]]:
        """
        Analyze text using rule-based patterns.
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (risk_scores_dict, matched_patterns_list)
        """
        matched_patterns = []
        risk_scores = {}
        max_score = 0.0
        
        for pattern, score, name in self.patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matched_patterns.append(name)
                risk_scores[name] = score
                max_score = max(max_score, score)
        
        # Add overall score
        if risk_scores:
            risk_scores['overall'] = max_score
        
        return risk_scores, matched_patterns

