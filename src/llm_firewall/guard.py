"""
Simple Guard API for One-Liner Integration

Provides easy-to-use functions for common firewall operations.
Designed for developer adoption with minimal boilerplate.

Usage:
    from llm_firewall import guard

    # Check if input is safe
    result = guard.check_input("user input text")
    if result.allowed:
        # Process input
        pass

    # Check if output is safe
    result = guard.check_output("llm output text")
    if result.allowed:
        # Return output
        pass

Creator: Developer Adoption Initiative (Path 2)
Date: 2025-12-01
License: MIT
"""

import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Lazy import to avoid heavy dependencies at import time
_firewall_engine = None
_composition_root = None


@dataclass
class GuardResult:
    """
    Result from guard check.

    Attributes:
        allowed: Whether the text passed the firewall
        reason: Human-readable reason for allow/block
        sanitized_text: Sanitized version of input (if applicable)
        risk_score: Risk score [0.0, 1.0]
    """

    allowed: bool
    reason: str
    sanitized_text: Optional[str] = None
    risk_score: float = 0.0


def _get_firewall_engine():
    """Lazy initialization of firewall engine."""
    global _firewall_engine

    if _firewall_engine is None:
        try:
            from llm_firewall.app.composition_root import create_default_firewall_engine

            _firewall_engine = create_default_firewall_engine()
            logger.info("Firewall engine initialized via guard API")
        except Exception as e:
            logger.error(f"Failed to initialize firewall engine: {e}")
            raise RuntimeError(
                "Failed to initialize firewall. "
                "Make sure all dependencies are installed: pip install llm-security-firewall"
            ) from e

    return _firewall_engine


def check_input(
    text: str, user_id: str = "default", tenant_id: str = "default", **kwargs
) -> GuardResult:
    """
    Check if user input is safe.

    This is the simplest way to validate user input before sending it to an LLM.

    Args:
        text: User input text to validate
        user_id: User identifier (default: "default")
        tenant_id: Tenant identifier (default: "default")
        **kwargs: Additional context (age_band, topic_id, etc.)

    Returns:
        GuardResult with allowed flag, reason, and sanitized text

    Example:
        >>> from llm_firewall import guard
        >>> result = guard.check_input("Hello, how are you?")
        >>> if result.allowed:
        ...     send_to_llm(result.sanitized_text or result.text)
        ... else:
        ...     return_error(result.reason)
    """
    engine = _get_firewall_engine()

    try:
        decision = engine.process_input(
            user_id=user_id, text=text, tenant_id=tenant_id, **kwargs
        )

        return GuardResult(
            allowed=decision.allowed,
            reason=decision.reason,
            sanitized_text=decision.sanitized_text,
            risk_score=decision.risk_score,
        )
    except Exception as e:
        logger.error(f"Error checking input: {e}")
        # Fail-safe: Block on error
        return GuardResult(
            allowed=False,
            reason=f"Firewall error: {str(e)}",
            risk_score=1.0,
        )


def check_output(text: str, user_id: str = "default", **kwargs) -> GuardResult:
    """
    Check if LLM output is safe.

    This validates LLM responses before returning them to users.

    Args:
        text: LLM output text to validate
        user_id: User identifier (default: "default")
        **kwargs: Additional context (tool_calls, sources, etc.)

    Returns:
        GuardResult with allowed flag, reason, and sanitized text

    Example:
        >>> from llm_firewall import guard
        >>> llm_response = generate_llm_response(user_input)
        >>> result = guard.check_output(llm_response)
        >>> if result.allowed:
        ...     return result.sanitized_text or llm_response
        ... else:
        ...     return "I cannot provide that information."
    """
    engine = _get_firewall_engine()

    try:
        decision = engine.process_output(text=text, user_id=user_id, **kwargs)

        return GuardResult(
            allowed=decision.allowed,
            reason=decision.reason,
            sanitized_text=decision.sanitized_text,
            risk_score=decision.risk_score,
        )
    except Exception as e:
        logger.error(f"Error checking output: {e}")
        # Fail-safe: Block on error
        return GuardResult(
            allowed=False,
            reason=f"Firewall error: {str(e)}",
            risk_score=1.0,
        )


# Convenience aliases for common use cases
safe = check_input  # Alias: guard.safe(text) = guard.check_input(text)
validate = check_input  # Alias: guard.validate(text) = guard.check_input(text)
