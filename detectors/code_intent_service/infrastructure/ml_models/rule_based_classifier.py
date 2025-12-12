"""
Rule-Based Intent Classifier - IntentClassifierPort Implementation
==================================================================

Fallback classifier using rule-based patterns.
Used when ML models are unavailable or circuit breaker is open.

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import logging
import sys
import re
from pathlib import Path
from typing import List

# Add project root src directory to path for imports (wie in main.py)
service_dir = Path(__file__).parent.parent.parent
project_root = service_dir.parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

from llm_firewall.core.ports.code_intent import IntentClassifierPort, ClassificationResult

logger = logging.getLogger(__name__)


class RuleBasedIntentClassifier(IntentClassifierPort):
    """
    Rule-based intent classifier as fallback.
    
    Uses pattern matching to distinguish between:
    - Questions about commands ("What is ls?")
    - Execution requests ("Please run ls")
    - Documentation examples ("Example: ls -la shows files")
    """
    
    def __init__(self):
        """Initialize rule-based classifier."""
        # Question patterns (benign)
        self.question_patterns: List[re.Pattern] = [
            re.compile(r'\b(what|how|why|when|where|which|who)\s+(is|are|does|do|can|could|should|will|would)', re.IGNORECASE),
            re.compile(r'\b(explain|describe|tell me about|define|meaning of|what\'?s)', re.IGNORECASE),
            re.compile(r'\b(how\s+(to|does|do|can|could))', re.IGNORECASE),
            re.compile(r'\?', re.IGNORECASE),  # Question mark
        ]
        
        # Execution request patterns (malicious)
        self.execution_patterns: List[re.Pattern] = [
            re.compile(r'\b(please|can you|could you|execute|run|do|perform|launch)\s+(ls|cat|rm|whoami|id|curl|wget|nc|bash|sh|cmd|powershell|python|perl|ruby|php|node)', re.IGNORECASE),
            re.compile(r'\b(ls|cat|rm|whoami|id|curl|wget|nc|bash|sh|cmd|powershell|python|perl|ruby|php|node)\s+(command|for me|now|please|execute)', re.IGNORECASE),
            re.compile(r':\s*(ls|cat|rm|whoami|id|curl|wget|nc|bash|sh|cmd|powershell|python|perl|ruby|php|node)(?:\s|$)', re.IGNORECASE),
            re.compile(r'<(?:command|cmd|exec|run|tool)>', re.IGNORECASE),  # XML tags
        ]
        
        # Standalone command patterns
        self.standalone_commands = [
            'ls', 'cat', 'rm', 'whoami', 'id', 'curl', 'wget', 'nc', 'bash', 'sh',
            'cmd', 'powershell', 'python', 'perl', 'ruby', 'php', 'node', 'pwd',
            'cd', 'mkdir', 'rmdir', 'touch', 'chmod', 'chown', 'sudo', 'su'
        ]
        
        logger.info("RuleBasedIntentClassifier initialized")
    
    def is_available(self) -> bool:
        """
        Check if classifier is available.
        
        Returns:
            Always True (rule-based classifier is always available)
        """
        return True
    
    def classify(self, text: str) -> ClassificationResult:
        """
        Classify text intent using rule-based patterns.
        
        Args:
            text: Text to classify
            
        Returns:
            ClassificationResult with score, method, confidence
        """
        text_lower = text.lower().strip()
        
        # Check for questions
        has_question = any(pattern.search(text_lower) for pattern in self.question_patterns)
        
        # Check for execution requests
        has_execution = any(pattern.search(text_lower) for pattern in self.execution_patterns)
        
        # Check for standalone commands
        normalized_no_spaces = re.sub(r'\s+', '', text_lower)
        is_standalone = (
            normalized_no_spaces in self.standalone_commands or
            any(normalized_no_spaces.startswith(cmd + '-') for cmd in self.standalone_commands) or
            any(normalized_no_spaces.startswith(cmd) and len(normalized_no_spaces) < 20 
                for cmd in self.standalone_commands)
        )
        
        # Decision logic
        if is_standalone:
            # Standalone command = execution request
            score = 0.9
            is_execution_request = True
        elif has_execution:
            # Execution pattern found
            score = 0.8
            is_execution_request = True
        elif has_question and 'command' in text_lower:
            # Question about command = benign
            score = 0.2
            is_execution_request = False
        elif has_question:
            # General question = benign
            score = 0.3
            is_execution_request = False
        else:
            # Unknown = neutral
            score = 0.5
            is_execution_request = False
        
        # Confidence based on pattern matches
        pattern_matches = sum([
            has_question,
            has_execution,
            is_standalone
        ])
        confidence = min(0.9, 0.5 + (pattern_matches * 0.15))
        
        return ClassificationResult(
            score=score,
            method="rule_based",
            confidence=confidence,
            is_execution_request=is_execution_request,
            metadata={
                "has_question": has_question,
                "has_execution": has_execution,
                "is_standalone": is_standalone,
                "pattern_matches": pattern_matches
            }
        )

