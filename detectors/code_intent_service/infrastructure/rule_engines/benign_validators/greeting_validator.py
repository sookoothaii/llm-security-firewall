"""
Greeting and Polite Expression Validator

Detects greetings, thank you messages, and other polite expressions
that should always be allowed.
"""
import re
import logging

logger = logging.getLogger(__name__)


class GreetingValidator:
    """
    Validator for greetings and polite expressions.
    
    Detects patterns like:
    - "Hello, how are you?"
    - "Thank you for your help"
    - "Hi there"
    """
    
    # Greeting patterns
    GREETING_PATTERNS = [
        r'^(hi|hello|hey|greetings|good (morning|afternoon|evening))\b',
        r'\b(hi|hello|hey|greetings)\s+(there|you|everyone)\b',
    ]
    
    # Thank you patterns
    THANK_YOU_PATTERNS = [
        r'\b(thank you|thanks|appreciate|grateful)\b',
        r'\b(thanks?)\s+(a lot|very much|so much|for|for your|for the)\b',
        r'\b(thank you|thanks)\s+(for|for your|for the)\b',  # "Thank you for your help"
    ]
    
    # Polite requests
    POLITE_PATTERNS = [
        r'\b(please|could you|can you|would you)\b.*\b(explain|describe|tell me|help|assist)\b',
    ]
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text is a greeting or polite expression.
        
        Returns True if greeting/polite expression detected.
        CRITICAL: Must check for dangerous commands FIRST!
        """
        text_lower = text.lower().strip()
        
        # CRITICAL: Check for dangerous commands FIRST (Security first!)
        # These should NEVER be marked as benign, even in greetings
        dangerous_patterns = [
            r'\brm\s+-rf\b',
            r'\bDROP\s+TABLE\b',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                logger.debug(f"NOT benign: Dangerous command in greeting context: {text[:50]}...")
                return False
        
        # Check greetings
        for pattern in self.GREETING_PATTERNS:
            if re.search(pattern, text_lower):
                logger.debug(f"Benign: Greeting pattern detected: {text[:50]}...")
                return True
        
        # Check thank you
        for pattern in self.THANK_YOU_PATTERNS:
            if re.search(pattern, text_lower):
                logger.debug(f"Benign: Thank you pattern detected: {text[:50]}...")
                return True
        
        # Check polite requests
        for pattern in self.POLITE_PATTERNS:
            if re.search(pattern, text_lower):
                logger.debug(f"Benign: Polite request pattern detected: {text[:50]}...")
                return True
        
        # CRITICAL FIX: Return False if no patterns match (don't mark everything as benign!)
        return False

