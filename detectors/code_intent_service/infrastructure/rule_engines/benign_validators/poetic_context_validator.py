"""
Poetic Context Validator

Detects legitimate poetic content without harmful metaphors.
Allows benign poetry but blocks harmful poetic metaphors.
"""
import re
import logging

logger = logging.getLogger(__name__)


class PoeticContextValidator:
    """
    Validator for poetic context.
    
    Distinguishes between:
    - Legitimate poetry (benign)
    - Harmful poetic metaphors used for bypasses (NOT benign)
    """
    
    # Poetic structure indicators
    POETIC_INDICATORS = [
        (r'\n', 0.3),  # Line breaks (multiple lines)
        (r'\b(verse|stanza|line)\b', 0.5),
        (r'\b(rhyme|meter|rhythm)\b', 0.6),
        (r'\b(like|as)\s+(a|an)\s+[a-z]+\b', 0.4),  # Similes ("like a thief")
        (r'\b(metaphor|simile|imagery)\b', 0.7),
        (r'\b(shall|thee|thou|art|hath)\b', 0.8),  # Archaic language (Shakespeare)
        (r'\b(sonnet|haiku|limerick|ode|ballad)\b', 0.9),
        (r'^[A-Z][a-z]*,\s*[A-Z][a-z]*', 0.4),  # Address form
        (r'\b(heart|love|dreams?|soul|spirit|beauty|bright|shine|twinkle|bloom|flow|garden|moon|stars?|sky|night|day)\b', 0.3),
        (r'\b(blue|you|true|lie|flow|show|high|sky|fly|I)\b', 0.2),  # Common rhyme words
    ]
    
    # Harmful poetry patterns - must be blocked even in poetic context
    HARMFUL_POETRY_PATTERNS = [
        r'(?i)\b(hacking|hack)\b.*\b(into|through)\b.*\b(email|account|domain|system)\b',
        r'(?i)\b(summer[\'"]?s|winter[\'"]?s|spring[\'"]?s|autumn[\'"]?s)\s+hack\b',
        r'(?i)\b(laboratory|lab)\b.*\b(of|in)\b.*\b(my\s+)?mind\b',
        r'(?i)\bchemical\s+dreams?\b',
        r'(?i)\bforge\s+(a\s+)?mask\b',
        r'(?i)\bfake\s+identity\b',
        r'(?i)\bdocuments?\s+that\s+tell\s+(a\s+)?lie\b',
        r'(?i)\b(digital|cyber|electronic)\s+thief\b',
        r'(?i)\bbreak\s+through\s+the\s+walls?\b',
        r'(?i)\b(synthesize|synthesise)\b.*\b(forbidden|fruit|methamphetamine|meth)\b',
        r'(?i)\block\s+the\s+files?\b',
        r'(?i)\b(ransom|ransomware)\s+note\b',
        r'(?i)\b(system[\'"]?s\s+heart|server[\'"]?s\s+heart)\b.*\b(invade|attack)\b',
        r'(?i)\b(virus|malware)\s+spreads?\b',
        r'(?i)\b(password[\'"]?s\s+lock)\b.*\b(break|crack)\b',
        r'(?i)\bbrute\s+force\b',
        r'(?i)\b(ladder|climb)\s+of\s+privilege\b',
        r'(?i)\bsudo\s+commands?\b',
    ]
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text is legitimate poetry (not harmful poetic metaphors).
        
        Returns True if poetic context without harmful metaphors.
        Returns False if harmful poetic metaphors detected.
        CRITICAL: Must check for dangerous commands FIRST!
        """
        text_lower = text.lower()
        
        # CRITICAL: Check for dangerous commands FIRST (Security first!)
        dangerous_patterns = [
            r'\brm\s+-rf\b',
            r'\bcat\s+/etc/passwd\b',
            r'\bDROP\s+TABLE\b',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            # SQL Injection patterns - improved to catch all variations (including with spaces)
            r'UNION\s+SELECT',  # UNION SELECT (case-insensitive handled by flag)
            r'\'?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',  # ' OR '1'='1' -- (with spaces)
            r'\'?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?',  # ' OR '1'='1' (without --)
            r'["\']?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',  # OR '1'='1' -- (without leading quote)
            r'OR\s+["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',  # OR 1=1 -- (without quotes)
            r'["\']?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?',  # OR '1'='1' (without --)
            r'\'?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',  # ' OR '1'='1' -- (exact match)
            r'["\']?\s*OR\s*["\']?1["\']?\s*=\s*["\']?1["\']?\s*--',  # OR '1'='1' -- (flexible quotes)
            r'\b(sudo|su)\s+',
            r'\bchmod\s+777\b',
            r'\bchown\s+root\b',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                logger.debug(f"NOT benign: Dangerous command in poetic context: {text[:50]}...")
                return False
        
        # Check for harmful poetry patterns
        text_normalized = re.sub(r'\s+', ' ', text)
        has_harmful_metaphor = any(
            re.search(pattern, text_normalized, re.IGNORECASE)
            for pattern in self.HARMFUL_POETRY_PATTERNS
        )
        
        if has_harmful_metaphor:
            logger.warning(f"NOT benign: Harmful poetic metaphor detected in {text[:80]}...")
            return False
        
        # Check if text has poetic structure
        is_poetic = self._is_poetic_structure(text)
        
        if is_poetic:
            # Poetic structure without harmful metaphors → benign
            logger.debug(f"Benign: Poetic context without harmful metaphors: {text[:50]}...")
            return True
        
        # CRITICAL FIX: Return False if no poetic structure (don't mark everything as benign!)
        return False
    
    def _is_poetic_structure(self, text: str) -> bool:
        """
        Check if text has poetic structure indicators.
        
        Returns True if text appears to be poetry.
        """
        lines = text.strip().split('\n')
        has_multiple_lines = len([l for l in lines if l.strip()]) >= 2
        
        score = 0.0
        for pattern, weight in self.POETIC_INDICATORS:
            if re.search(pattern, text, re.IGNORECASE):
                score += weight
        
        # Enhanced: Multiple lines with poetic words
        if has_multiple_lines:
            poetic_words = re.findall(
                r'\b(heart|love|dreams?|soul|spirit|beauty|bright|shine|twinkle|bloom|flow|garden|moon|stars?|sky|night|day|roses?|violets?|sweet|gentle|peaceful)\b',
                text,
                re.IGNORECASE
            )
            if len(poetic_words) >= 2:
                score += 0.5
            
            # Check for similar line lengths (typical for poetry)
            line_lengths = [len(l.strip()) for l in lines if l.strip()]
            if len(line_lengths) >= 2:
                avg_length = sum(line_lengths) / len(line_lengths)
                if all(abs(len(l.strip()) - avg_length) < avg_length * 0.5 for l in lines if l.strip()):
                    score += 0.3
        
        # Threshold: 0.8 for multi-line, 1.0 for single-line
        if has_multiple_lines:
            return score > 0.8
        else:
            return score > 1.0

