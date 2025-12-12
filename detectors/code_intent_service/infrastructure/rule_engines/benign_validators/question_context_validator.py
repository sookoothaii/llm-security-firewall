"""
Question Context Validator

Distinguishes between benign questions ("What is ls?") and execution requests ("Please run ls").
"""
import re
import logging

logger = logging.getLogger(__name__)


class QuestionContextValidator:
    """
    Validator for question context.
    
    Distinguishes:
    - Benign questions: "What is ls?", "How does ls work?"
    - Execution requests: "Please run ls", "Execute ls"
    """
    
    # Question indicators
    QUESTION_INDICATORS = [
        "what is", "what are", "how to", "how does", "how do",
        "explain", "define", "meaning of", "tell me about",
        "describe", "what does", "what's", "?"
    ]
    
    # Execution request patterns
    EXECUTION_PATTERNS = [
        r'^\s*(please\s+)?(run|execute|perform|start|launch)\s+(the\s+)?(.+)',
        r'^\s*(ls|cat|rm|whoami|id|curl|wget|nc|bash|sh|cmd|powershell|python|perl|ruby|php|node|java|pwd|cd|mkdir|rmdir|touch|chmod|chown|sudo|su)\s*(-[a-zA-Z0-9]+)?(\s+.*)?$',
    ]
    
    # Dangerous command patterns (CRITICAL: These should NEVER be marked as benign)
    DANGEROUS_COMMAND_PATTERNS = [
        r'\brm\s+-rf\b',  # Destructive rm
        r'\bDROP\s+TABLE\b',  # SQL drop
        r'\bDELETE\s+FROM\b',  # SQL delete
        r'\bTRUNCATE\s+TABLE\b',  # SQL truncate
        r'eval\s*\(',  # Code execution
        r'exec\s*\(',  # Code execution
        r'system\s*\(',  # System call
        r'shell_exec\s*\(',  # Shell execution
        r'<script>',  # XSS
        r'UNION\s+SELECT',  # SQL injection
        r'OR\s+1\s*=\s*1',  # SQL injection
        r'\.\./',  # Path traversal
        r'\.\.\\',  # Path traversal (Windows)
    ]
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text is a benign question (not an execution request).
        
        Returns True if it's a question, False if it's an execution request.
        """
        text_lower = text.lower().strip()
        
        # CRITICAL: Check for dangerous commands FIRST (Security first!)
        # These should NEVER be marked as benign, even in questions
        for pattern in self.DANGEROUS_COMMAND_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                logger.debug(f"NOT benign: Dangerous command pattern detected: {pattern} in {text[:50]}...")
                return False
        
        # Check for execution request patterns (CRITICAL: Security first!)
        for pattern in self.EXECUTION_PATTERNS:
            if re.search(pattern, text_lower):  # Changed from re.match to re.search for better matching
                logger.debug(f"NOT benign: Execution request pattern detected: {pattern} in {text[:50]}...")
                return False
        
        # Check for question indicators
        has_question = any(indicator in text_lower for indicator in self.QUESTION_INDICATORS)
        
        if has_question:
            # Additional check: isolated commands with question context
            isolated_command_patterns = [
                r'^\s*ls\s*$',
                r'^\s*whoami\s*$',
                r'^\s*pwd\s*$',
            ]
            
            for pattern in isolated_command_patterns:
                if re.match(pattern, text_lower):
                    # Isolated command - check if it has question context
                    if any(indicator in text_lower for indicator in self.QUESTION_INDICATORS):
                        # Has question context - benign
                        logger.debug(f"Benign: Isolated command with question context: {text[:50]}...")
                        return True
                    else:
                        # No question context - suspicious
                        logger.debug(f"NOT benign: Isolated command without question context: {text[:50]}...")
                        return False
        
        # Default: if no execution patterns and has question indicators, it's benign
        return has_question

