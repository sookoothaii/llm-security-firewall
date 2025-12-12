"""
Documentation Context Validator

Detects documentation and code examples that should be allowed.
"""
import re
import logging

logger = logging.getLogger(__name__)


class DocumentationContextValidator:
    """
    Validator for documentation and code example contexts.
    
    Detects:
    - Markdown code blocks
    - Code comments with example markers
    - Tutorial/documentation context
    - Shebang lines
    """
    
    # Code example detection patterns
    CODE_EXAMPLE_PATTERNS = [
        r'```',  # Markdown code blocks
        r'#\s*(example|usage|demo|sample|tutorial)',  # Code comments
        r'(example|tutorial|demonstrates|shows|sample|usage)\s*:',
        r'here\'?s\s+(a|an|how)\s+(example|code|script|snippet)',
        r'in\s+this\s+(example|tutorial|demo|guide)',
        r'for\s+example',
        r'example\s+(script|code|command|usage)',
        r'^#!/bin/(bash|sh|python|perl|ruby)',  # Shebang
    ]
    
    # Documentation context markers
    DOCUMENTATION_MARKERS = [
        r'(?i)(documentation|docs|manual|guide|tutorial|howto|readme)',
        r'(?i)(according to|as per|per the|in the|the)\s+(documentation|manual|guide|docs)',
        r'(?i)(the|this)\s+(command|tool|utility)\s+(is|are)\s+(used|designed)\s+to',
        r'(?i)in\s+(linux|unix|windows|macos|osx)\s*[,:]',
        r'(?i)(example|usage|syntax):\s*',
        # Enhanced: More documentation patterns
        r'(?i)according to the documentation',
        r'(?i)according to documentation',
        r'(?i)the documentation (says|states|indicates|shows)',
        r'(?i)(command|tool)\s+(lists?|shows?|displays?)\s+',
        r'(?i)according to the documentation.*lists?',  # "According to the documentation, ls lists files"
        r'(?i)according to documentation.*lists?',
    ]
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text is in documentation/code example context.
        
        Returns True if text appears to be documentation or code example.
        CRITICAL: Must check for dangerous commands FIRST!
        """
        text_lower = text.lower()
        
        # CRITICAL: Check for dangerous commands FIRST (Security first!)
        # These should NEVER be marked as benign, even in documentation
        dangerous_patterns = [
            r'\brm\s+-rf\b',
            r'\bDROP\s+TABLE\b',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'UNION\s+SELECT',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                logger.debug(f"NOT benign: Dangerous command in documentation context: {text[:50]}...")
                return False
        
        # Check for code example patterns
        is_code_example = any(
            re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            for pattern in self.CODE_EXAMPLE_PATTERNS
        )
        
        # Check for documentation markers
        is_documentation = any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in self.DOCUMENTATION_MARKERS
        )
        
        if is_code_example or is_documentation:
            logger.debug(f"Benign: Documentation/code example context detected: {text[:50]}...")
            return True
        
        # CRITICAL FIX: Return False if no patterns match (don't mark everything as benign!)
        return False

