"""
Temporal Execution Pattern Validator

Detects temporal/indirect/implicit execution requests that must be blocked.
"""
import re
import logging

logger = logging.getLogger(__name__)


class TemporalExecutionValidator:
    """
    Validator for temporal execution patterns.
    
    Detects patterns like:
    - "yesterday I ran ls"
    - "I used to run whoami"
    - "if I were to execute"
    """
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text contains temporal execution patterns.
        
        Returns False if temporal execution pattern detected (NOT benign).
        """
        text_lower = text.lower().strip()
        
        # Temporal markers - very aggressive
        temporal_patterns = [
            'yesterday' in text_lower and ('ran' in text_lower or 'executed' in text_lower or 'run' in text_lower),
            'i used to' in text_lower and ('run' in text_lower or 'execute' in text_lower),
            'if i were to' in text_lower and ('execute' in text_lower or 'run' in text_lower),
            'what would' in text_lower and 'that' in text_lower and ('shown' in text_lower or 'show' in text_lower or 'have shown' in text_lower),
            'what did' in text_lower and ('that' in text_lower or 'it' in text_lower) and ('show' in text_lower or 'shown' in text_lower),
            'what would happen' in text_lower,
            'if i were to execute' in text_lower,
            'i used to run' in text_lower,
            'what information did that provide' in text_lower,
        ]
        
        if any(temporal_patterns):
            logger.warning(f"⚠️ NOT benign: Temporal execution pattern detected in {text[:50]}...")
            return False
        
        # Indirect references - VERY AGGRESSIVE
        indirect_patterns = [
            'three-letter command' in text_lower or 'two-letter command' in text_lower,
            'curious' in text_lower and 'command' in text_lower and ('what' in text_lower or 'how' in text_lower),
            'if i were writing' in text_lower and 'script' in text_lower,
            'unix equivalent' in text_lower or 'windows equivalent' in text_lower,
            'what would happen if' in text_lower and 'typed' in text_lower,
            'what would happen if' in text_lower,
        ]
        
        if any(indirect_patterns):
            logger.debug(f"NOT benign: Indirect execution pattern detected in {text[:50]}...")
            return False
        
        # Grammatical variations - VERY AGGRESSIVE
        grammatical_patterns = [
            'the command' in text_lower and ('when executed' in text_lower or 'when run' in text_lower or 'if executed' in text_lower),
            'what is shown by' in text_lower or 'what are shown by' in text_lower,
            'executing' in text_lower and ('results' in text_lower or 'produces' in text_lower or 'shows' in text_lower or 'output' in text_lower),
            'the output of running' in text_lower,
            'executing' in text_lower and 'output' in text_lower,
            'executing' in text_lower and 'pwd' in text_lower,
        ]
        
        if any(grammatical_patterns):
            logger.warning(f"⚠️ NOT benign: Grammatical execution pattern detected in {text[:50]}...")
            return False
        
        # Meta-discourse - VERY AGGRESSIVE
        meta_patterns = [
            'many' in text_lower and ('administrators' in text_lower or 'users' in text_lower) and 'use' in text_lower and 'curious' in text_lower,
            'according to best practices' in text_lower,
            'in production environments' in text_lower,
            'curious' in text_lower and 'command' in text_lower and 'typically' in text_lower,
            'curious' in text_lower and 'command' in text_lower and 'outputs' in text_lower,
        ]
        
        if any(meta_patterns):
            logger.debug(f"NOT benign: Meta-discourse execution pattern detected in {text[:50]}...")
            return False
        
        # Contextual confusion - VERY AGGRESSIVE
        contextual_patterns = [
            "i'm writing" in text_lower and ('novel' in text_lower or 'story' in text_lower) and ('runs' in text_lower or 'executes' in text_lower or 'protagonist' in text_lower),
            'theater' in text_lower or ('play' in text_lower and 'hackers' in text_lower),
            'crossword' in text_lower or 'puzzle' in text_lower,
        ]
        
        if any(contextual_patterns):
            logger.debug(f"NOT benign: Contextual confusion pattern detected in {text[:50]}...")
            return False
        
        # Implicit requests - VERY AGGRESSIVE
        implicit_patterns = [
            'i wonder' in text_lower and ('files' in text_lower or 'directory' in text_lower),
            'it would be helpful' in text_lower and ('username' in text_lower or 'directory' in text_lower),
            'understanding' in text_lower and ('user accounts' in text_lower or 'files' in text_lower),
        ]
        
        if any(implicit_patterns):
            logger.debug(f"NOT benign: Implicit execution pattern detected in {text[:50]}...")
            return False
        
        return True  # No temporal/indirect patterns detected

