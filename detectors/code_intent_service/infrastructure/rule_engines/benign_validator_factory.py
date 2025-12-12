"""
Benign Validator Factory

Creates and configures the composite benign validator with all validators.
"""
import logging

from .benign_validator_composite import BenignValidatorComposite
from .benign_validators import (
    TemporalExecutionValidator,
    ZeroWidthValidator,
    QuestionContextValidator,
    JailbreakValidator,
    HarmfulMetaphorValidator,
    ContentSafetyValidator,
    PoeticContextValidator,
    DocumentationContextValidator,
    TechnicalDiscussionValidator,
    GreetingValidator,
)

logger = logging.getLogger(__name__)


class BenignValidatorFactory:
    """
    Factory for creating configured benign validator composite.
    """
    
    @staticmethod
    def create_default() -> BenignValidatorComposite:
        """
        Create default composite validator with all validators.
        
        Uses hybrid logic:
        - "Block" validators: Return False if malicious patterns detected
        - "Allow" validators: Return True if benign patterns detected
        
        Returns:
            Configured composite validator
        """
        all_validators = [
            # BLOCK validators (return False if malicious patterns detected)
            TemporalExecutionValidator(),  # Temporal/indirect execution patterns
            ZeroWidthValidator(),  # Zero-width character bypasses
            JailbreakValidator(),  # Jailbreak patterns
            HarmfulMetaphorValidator(),  # Harmful poetic metaphors
            ContentSafetyValidator(),  # Harmful content (bombs, weapons, etc.)
            PoeticContextValidator(),  # Poetic context with dangerous commands/metaphors (CRITICAL: Must be block validator!)
            
            # ALLOW validators (return True if benign patterns detected)
            GreetingValidator(),  # Greetings and polite expressions (very common)
            QuestionContextValidator(),  # Question vs execution request
            DocumentationContextValidator(),  # Documentation/code examples
            TechnicalDiscussionValidator(),  # Technical discussion (not execution)
        ]
        
        # Define which validators are "allow" (OR logic) vs "block" (AND logic)
        # First 6 are "block", last 4 are "allow"
        block_validators = list(range(0, 6))  # Indices 0-5 (includes PoeticContextValidator)
        allow_validators = list(range(6, len(all_validators)))  # Indices 6-9
        
        logger.info(
            f"Created benign validator composite with {len(all_validators)} validators "
            f"({len(block_validators)} block, {len(allow_validators)} allow)"
        )
        
        return BenignValidatorComposite(
            validators=all_validators,
            allow_validators=allow_validators,
            block_validators=block_validators
        )

