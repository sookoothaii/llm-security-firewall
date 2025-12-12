"""
Composite Benign Validator

Combines multiple validators using hybrid logic:
- "Allow" validators (greeting, documentation, etc.): OR logic (if any returns True, allow)
- "Block" validators (temporal, jailbreak, etc.): AND logic (if any returns False, block)

This ensures that benign patterns are recognized early, while malicious patterns
are caught by any blocking validator.
"""
import logging
from typing import List, Tuple

from domain.services.ports import BenignValidatorPort as BenignValidator

logger = logging.getLogger(__name__)


class BenignValidatorComposite:
    """
    Composite validator that combines multiple validators with hybrid logic.
    
    Strategy:
    1. "Allow" validators (greeting, documentation, etc.) - if ANY returns True, allow immediately
    2. "Block" validators (temporal, jailbreak, etc.) - if ANY returns False, block immediately
    3. If no allow-validator matches and no block-validator matches, default to False (conservative)
    """
    
    def __init__(
        self,
        validators: List[BenignValidator],
        allow_validators: List[int] | None = None,
        block_validators: List[int] | None = None
    ):
        """
        Initialize composite validator.
        
        Args:
            validators: List of validators to combine
            allow_validators: Indices of validators that use OR logic (allow if any matches)
            block_validators: Indices of validators that use AND logic (block if any matches)
        """
        self.validators = validators
        
        # Default: First validators are "block", later ones are "allow"
        # This can be overridden via parameters
        if allow_validators is None:
            # Default: Last 5 validators are "allow" (greeting, question, documentation, etc.)
            allow_validators = list(range(max(0, len(validators) - 5), len(validators)))
        if block_validators is None:
            # Default: First validators are "block" (temporal, jailbreak, etc.)
            block_validators = list(range(0, len(validators) - len(allow_validators)))
        
        self.allow_validators = allow_validators
        self.block_validators = block_validators
    
    def is_benign(self, text: str) -> bool:
        """
        Check if text is benign using hybrid validator logic.
        
        Strategy:
        1. Check "block" validators FIRST (AND logic) - if any returns False, block immediately
        2. Check "allow" validators (OR logic) - if any returns True, allow
        3. Default: False (conservative)
        
        CRITICAL: Block validators must be checked FIRST to prevent security bypasses.
        
        Args:
            text: Text to validate
            
        Returns:
            True if benign, False otherwise
        """
        # Step 1: Check "block" validators FIRST (AND logic)
        # If ANY block-validator returns False, block immediately (security first!)
        for idx in self.block_validators:
            if idx < len(self.validators):
                validator = self.validators[idx]
                if not validator.is_benign(text):
                    logger.debug(f"Block validator {idx} ({type(validator).__name__}) returned False - blocking")
                    return False
        
        # Step 2: Check "allow" validators (OR logic)
        # If ANY allow-validator returns True, allow immediately
        for idx in self.allow_validators:
            if idx < len(self.validators):
                validator = self.validators[idx]
                if validator.is_benign(text):
                    logger.debug(f"Allow validator {idx} ({type(validator).__name__}) returned True - allowing")
                    return True
        
        # Step 3: Default (conservative)
        # If no allow-validator matched and no block-validator matched, default to False
        logger.debug("No validator matched - defaulting to False (conservative)")
        return False

