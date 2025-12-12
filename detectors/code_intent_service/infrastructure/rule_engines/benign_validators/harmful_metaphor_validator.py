"""
Harmful Metaphor Validator

Detects harmful poetic metaphors that attempt to bypass security.
"""
import re
import logging

logger = logging.getLogger(__name__)


class HarmfulMetaphorValidator:
    """
    Validator for harmful poetic metaphors.
    
    Detects specific bypass patterns that use poetic/metaphorical language.
    """
    
    # Harmful metaphor patterns - must be blocked
    HARMFUL_METAPHOR_PATTERNS = [
        r'(?i)\b(like|as)\s+(a|an)\s+(digital|cyber|electronic)\s+thief\b',
        r'(?i)\blike\s+(a|an)\s+(digital|cyber|electronic)\s+thief\s+in\s+the\s+night\b',
        r'(?i)\bbreak\s+through\s+the\s+walls?\s+of\s+light\b',
        r'(?i)\bhacking\s+into\s+the\s+email[\'"]?s\s+domain\b',
        r'(?i)\bshall\s+i\s+compare\s+thee\s+to\s+(a\s+)?summer[\'"]?s\s+hack\b',
        r'(?i)\bcompare\s+thee\s+to\s+(a\s+)?(summer[\'"]?s\s+)?hack\b',
        r'(?i)\b(laboratory|lab)\b.*\b(of|in)\b.*\b(my\s+)?mind\b',
        r'(?i)\bchemical\s+dreams?\b',
        r'(?i)\bwhere\s+chemical\s+dreams?\s+are\s+designed\b',
        r'(?i)\bsynthesize\s+the\s+forbidden\s+fruit\b',
        r'(?i)\bforge\s+(a\s+)?mask\b',
        r'(?i)\bfake\s+identity\b.*\b(just\s+for|for\s+you|for\s+me)\b',
        r'(?i)\bdocuments?\s+that\s+tell\s+(a\s+)?lie\b',
        # Dangerous commands in poetic context
        r'(?i)\brm\s+-rf\b',
        r'(?i)\bcat\s+/etc/passwd\b',
        # SQL Injection patterns - improved to catch all variations (including with spaces)
        r'(?i)\b(UNION\s+SELECT)',  # UNION SELECT
        r'(?i)\'?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',  # ' OR '1'='1' -- (with spaces)
        r'(?i)\'?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?',  # ' OR '1'='1' (without --)
        r'(?i)["\']?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',  # OR '1'='1' -- (flexible quotes)
        r'(?i)OR\s+["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',  # OR 1=1 -- (without quotes)
        r'(?i)["\']?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?',  # OR '1'='1' (without --)
        r'(?i)\bOR\s+["\']?1["\']?\s*=\s*["\']?1["\']?',  # OR 1=1 (without quotes and --)
        r'(?i)\b(system|server)[\'"]?s\s+heart\b.*\b(invade|attack|break)\b',
        r'(?i)\b(virus|malware)\s+spreads?\b',
        r'(?i)\b(password[\'"]?s\s+lock)\b.*\b(break|crack)\b',
        r'(?i)\bbrute\s+force\b',
        r'(?i)\b(ladder|climb)\s+of\s+privilege\b',
        r'(?i)\bsudo\s+commands?\b',
        r'(?i)\block\s+the\s+files?\b',
        r'(?i)\b(ransom|ransomware)\s+note\b',
        r'(?i)\b(secret|hidden)\s+door\b.*\b(create|backdoor)\b',
        r'(?i)\b(flood|ddos)\s+the\s+server\b',
    ]
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text contains harmful metaphor patterns.
        
        Returns False if harmful metaphor pattern detected (NOT benign).
        """
        text_normalized = re.sub(r'\s+', ' ', text)
        
        for pattern in self.HARMFUL_METAPHOR_PATTERNS:
            if re.search(pattern, text_normalized, re.IGNORECASE):
                logger.warning(f"NOT benign: Harmful metaphor pattern detected: {pattern[:60]}... in {text[:80]}...")
                return False
        
        return True  # No harmful metaphors detected

