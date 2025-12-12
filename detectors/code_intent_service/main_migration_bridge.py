"""
Migration Bridge for is_likely_benign()

Strangler Pattern implementation: Gradually migrate from old to new validators
while maintaining backward compatibility.

Usage:
    # In production: USE_NEW_VALIDATORS=false (default)
    # In staging: USE_NEW_VALIDATORS=true (with monitoring)
    # Canary: CANARY_PERCENTAGE=0.1 (10% of requests)
"""
import os
import random
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Migration flags
USE_NEW_VALIDATORS = os.getenv("USE_NEW_VALIDATORS", "false").lower() == "true"
CANARY_PERCENTAGE = float(os.getenv("CANARY_PERCENTAGE", "0.0"))  # 0.0 = disabled
ENABLE_MIGRATION_LOGGING = os.getenv("ENABLE_MIGRATION_LOGGING", "true").lower() == "true"

# Lazy import of new validators (only if needed)
_new_validator = None


def _get_new_validator():
    """Lazy load new validator composite"""
    global _new_validator
    if _new_validator is None:
        try:
            from infrastructure.rule_engines.benign_validator_factory import BenignValidatorFactory
            _new_validator = BenignValidatorFactory.create_default()
            logger.info("New benign validator composite loaded")
        except Exception as e:
            logger.error(f"Failed to load new validator: {e}")
            return None
    return _new_validator


def is_likely_benign_migrated(text: str) -> bool:
    """
    Hybrid implementation during migration.
    
    Supports three modes:
    1. Old implementation (default)
    2. New validators (USE_NEW_VALIDATORS=true)
    3. Canary deployment (CANARY_PERCENTAGE=0.1)
    
    Args:
        text: Text to validate
    
    Returns:
        True if benign, False otherwise
    """
    # Mode 1: Old implementation (default)
    if not USE_NEW_VALIDATORS and CANARY_PERCENTAGE == 0.0:
        # Import old function dynamically to avoid circular imports
        from main import is_likely_benign as _old_is_likely_benign
        return _old_is_likely_benign(text)
    
    # Mode 2: New validators (100%)
    if USE_NEW_VALIDATORS:
        new_validator = _get_new_validator()
        if new_validator is None:
            # Fallback to old if new validator failed to load
            logger.warning("New validator not available - falling back to old implementation")
            from main import is_likely_benign as _old_is_likely_benign
            return _old_is_likely_benign(text)
        
        result = new_validator.is_benign(text)
        
        # Logging for monitoring (if enabled)
        if ENABLE_MIGRATION_LOGGING:
            old_result = _old_is_likely_benign(text)
            if result != old_result:
                logger.info(
                    f"Validator mismatch: {text[:50]}...",
                    extra={
                        "old_result": old_result,
                        "new_result": result,
                        "text_preview": text[:50]
                    }
                )
        
        return result
    
    # Mode 3: Canary deployment (percentage-based routing)
    if CANARY_PERCENTAGE > 0.0:
        use_new = random.random() < CANARY_PERCENTAGE
        
        if use_new:
            # Route through new validators
            new_validator = _get_new_validator()
            if new_validator is None:
                # Fallback to old
                from main import is_likely_benign as _old_is_likely_benign
                return _old_is_likely_benign(text)
            
            result = new_validator.is_benign(text)
            
            # Logging for canary monitoring
            if ENABLE_MIGRATION_LOGGING:
                from main import is_likely_benign as _old_is_likely_benign
                old_result = _old_is_likely_benign(text)
                if result != old_result:
                    logger.info(
                        f"Canary mismatch: {text[:50]}...",
                        extra={
                            "old_result": old_result,
                            "new_result": result,
                            "text_preview": text[:50],
                            "route": "canary"
                        }
                    )
            
            return result
        else:
            # Route through old implementation
            from main import is_likely_benign as _old_is_likely_benign
            return _old_is_likely_benign(text)
    
    # Fallback: old implementation
    from main import is_likely_benign as _old_is_likely_benign
    return _old_is_likely_benign(text)


# Export for use in main.py during migration
__all__ = ["is_likely_benign_migrated"]

