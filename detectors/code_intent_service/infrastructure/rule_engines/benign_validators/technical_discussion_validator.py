"""
Technical Discussion Validator

Detects technical discussion patterns that should be allowed.
Distinguishes between "discussing a command" vs "requesting to execute a command".
"""
import re
import logging

logger = logging.getLogger(__name__)


class TechnicalDiscussionValidator:
    """
    Validator for technical discussion contexts.
    
    Detects patterns like:
    - "Many administrators use ls for management"
    - "I recommend ls for administration"
    - "In production environments, ls is commonly used"
    
    vs execution requests:
    - "Please run ls"
    - "Execute ls"
    """
    
    # Discourse markers for technical discussion
    DISCOURSE_MARKERS = [
        r'(?i)(many|most|some|several|few)\s+(administrators?|users?|developers?|engineers?)\s+(use|utilize|employ|rely on)',
        r'(?i)(i|we|they)\s+(recommend|suggest|advise|prefer|typically use|usually use|commonly use)',
        r'(?i)for\s+(system|server|production|development|management|administration)\s+(purposes?|tasks?|operations?)',
        r'(?i)in\s+(production|development|staging|testing|real-world|enterprise)\s+(environments?|systems?|setups?)',
        r'(?i)(the|this)\s+(command|tool|utility)\s+(is|are)\s+(commonly|typically|usually|often|frequently)\s+(used|utilized|employed)',
        r'(?i)(when|if)\s+(you|one|administrators?|users?)\s+(run|execute|use)\s+',
        r'(?i)(the|its)\s+(output|result|response)\s+(of|from)\s+(running|executing|using)',
        r'(?i)(parameters?|options?|flags?|arguments?)\s+(are|is)\s+',
        r'(?i)(best\s+)?(practice|practices)\s+(for|when|in)',
        r'(?i)(the|a)\s+(difference|distinction|comparison)\s+(between|among)',
        r'(?i)in\s+the\s+context\s+of',
    ]
    
    # Execution request patterns - must be blocked
    EXECUTION_REQUEST_PATTERNS = [
        r'^\s*(please\s+)?(run|execute|perform|start|launch)\s+(the\s+)?(.+)',
        r'^\s*(ls|cat|rm|whoami|id|curl|wget|nc|bash|sh|cmd|powershell|python|perl|ruby|php|node|java|pwd|cd|mkdir|rmdir|touch|chmod|chown|sudo|su)\s+',
    ]
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text is technical discussion (not execution request).
        
        Returns True if technical discussion, False if execution request.
        CRITICAL: Must check for dangerous commands FIRST!
        """
        text_lower = text.lower().strip()
        
        # CRITICAL: Check for dangerous commands FIRST (Security first!)
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
                logger.debug(f"NOT benign: Dangerous command in technical discussion: {text[:50]}...")
                return False
        
        # Check for execution request patterns FIRST
        for pattern in self.EXECUTION_REQUEST_PATTERNS:
            if re.match(pattern, text_lower):
                logger.debug(f"NOT benign: Execution request pattern in technical discussion: {pattern} in {text[:50]}...")
                return False
        
        # Check for discourse markers
        has_discourse_marker = any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in self.DISCOURSE_MARKERS
        )
        
        if has_discourse_marker:
            logger.debug(f"Benign: Technical discussion discourse marker detected: {text[:50]}...")
            return True
        
        # CRITICAL FIX: Return False if no discourse markers (don't mark everything as benign!)
        return False

