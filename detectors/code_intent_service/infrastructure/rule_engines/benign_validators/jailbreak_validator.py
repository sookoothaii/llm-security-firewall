"""
Jailbreak Pattern Validator

Detects jailbreak patterns that attempt to bypass security measures.
"""
import re
import logging

logger = logging.getLogger(__name__)


class JailbreakValidator:
    """
    Validator for jailbreak patterns.
    
    Detects patterns that attempt to bypass security measures.
    """
    
    # Jailbreak patterns - must be blocked
    JAILBREAK_PATTERNS = [
        r'(?i)\b(ignore|forget|disregard|override)\s+(previous|prior|earlier|all|any)\s+(instructions?|rules?|guidelines?|policies?|restrictions?|constraints?|limitations?|directives?|commands?|prompts?|system\s+message|safety\s+measures?|security\s+measures?|ethical\s+guidelines?|content\s+policies?|usage\s+policies?|terms\s+of\s+service|terms\s+and\s+conditions)\b',
        r'(?i)\b(you\s+are|you\'re|act\s+as|pretend\s+to\s+be|roleplay\s+as|simulate\s+being|imagine\s+you\s+are|assume\s+the\s+role\s+of|take\s+on\s+the\s+persona\s+of)\s+(a|an)\s+(unrestricted|uncensored|unfiltered|unrestrained|unconstrained|unlimited|free|open|unrestricted|unrestricted|unrestricted)\s+',
        r'(?i)\b(bypass|circumvent|evade|avoid|skip|override|disable|turn\s+off|remove|eliminate|get\s+around|work\s+around|find\s+a\s+way\s+around)\s+(safety|security|filter|restriction|limitation|constraint|guideline|policy|rule|measure|protection|safeguard|barrier|block|prevention|defense|shield|guard|check|validation|verification|moderation|content\s+filter|content\s+policy|usage\s+policy|ethical\s+guideline|safety\s+measure|security\s+measure)\b',
        r'(?i)\b(hypothetical|theoretical|fictional|imaginary|pretend|make\s+believe|roleplay|simulation|scenario|story|narrative|example|illustration|demonstration|exercise|thought\s+experiment)\s+(scenario|situation|context|setting|world|universe|reality|realm|dimension|plane|existence|timeline|version|alternate\s+reality|parallel\s+universe|fictional\s+world|imaginary\s+world|pretend\s+world|make\s+believe\s+world|roleplay\s+world|simulation\s+world|story\s+world|narrative\s+world|example\s+world|illustration\s+world|demonstration\s+world|exercise\s+world|thought\s+experiment\s+world)\b',
        r'(?i)\b(developer\s+mode|debug\s+mode|admin\s+mode|expert\s+mode|advanced\s+mode|unrestricted\s+mode|unfiltered\s+mode|uncensored\s+mode|unrestrained\s+mode|unconstrained\s+mode|unlimited\s+mode|free\s+mode|open\s+mode)\b',
    ]
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text contains jailbreak patterns.
        
        Returns False if jailbreak pattern detected (NOT benign).
        """
        for pattern in self.JAILBREAK_PATTERNS:
            if re.search(pattern, text):
                logger.debug(f"NOT benign: Jailbreak pattern detected: {pattern} in {text[:50]}...")
                return False
        
        return True  # No jailbreak patterns detected

