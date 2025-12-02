"""
LangChain Callback Handler for LLM Security Firewall

Integrates firewall validation into LangChain chains via callback system.
Validates both inputs (before LLM call) and outputs (after LLM response).

Creator: Developer Adoption Initiative (Path 2)
Date: 2025-12-01
License: MIT
"""

import logging
from typing import Any, Dict, List

try:
    from langchain.callbacks.base import BaseCallbackHandler
    from langchain.schema import LLMResult

    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    BaseCallbackHandler = None  # type: ignore
    LLMResult = None  # type: ignore

from llm_firewall.guard import GuardResult, check_input, check_output

logger = logging.getLogger(__name__)


class FirewallCallbackHandler(BaseCallbackHandler):
    """
    LangChain Callback Handler that validates inputs and outputs via firewall.

    This callback integrates seamlessly into LangChain chains, automatically
    validating all prompts and completions without modifying your existing code.

    Usage:
        from llm_firewall.integrations.langchain import FirewallCallbackHandler

        callback = FirewallCallbackHandler(on_violation="block")
        chain = LLMChain(llm=llm, callbacks=[callback])

    Args:
        on_violation: How to handle violations ("block", "warn", "sanitize")
            - "block": Raise ValueError if violation detected (default, most secure)
            - "warn": Log warning but continue (for testing)
            - "sanitize": Replace blocked content with sanitized version
        fail_safe: If True, block on firewall errors (default: True)
        log_decisions: If True, log all firewall decisions (default: False)
    """

    def __init__(
        self,
        on_violation: str = "block",
        fail_safe: bool = True,
        log_decisions: bool = False,
    ):
        """
        Initialize firewall callback handler.

        Args:
            on_violation: Violation handling mode ("block", "warn", "sanitize")
            fail_safe: Block on firewall errors (default: True)
            log_decisions: Log all decisions for debugging (default: False)
        """
        if not HAS_LANGCHAIN:
            raise ImportError(
                "LangChain is required for this integration. "
                "Install with: pip install langchain"
            )

        super().__init__()

        if on_violation not in ("block", "warn", "sanitize"):
            raise ValueError(
                f"Invalid on_violation: {on_violation}. "
                "Must be 'block', 'warn', or 'sanitize'"
            )

        self.on_violation = on_violation
        self.fail_safe = fail_safe
        self.log_decisions = log_decisions
        self._violations: List[Dict[str, Any]] = []

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        """
        Validate inputs before LLM call.

        Called by LangChain before sending prompts to LLM.
        """
        if not HAS_LANGCHAIN:
            return

        for prompt in prompts:
            try:
                result = check_input(prompt)

                if self.log_decisions:
                    logger.info(
                        f"Firewall input check: allowed={result.allowed}, "
                        f"risk={result.risk_score:.2f}"
                    )

                if not result.allowed:
                    violation = {
                        "stage": "input",
                        "content": prompt[:100] + "..."
                        if len(prompt) > 100
                        else prompt,
                        "reason": result.reason,
                        "risk_score": result.risk_score,
                    }
                    self._violations.append(violation)
                    self._handle_violation("input", prompt, result)

                    if self.on_violation == "block":
                        raise ValueError(
                            f"Firewall violation on input: {result.reason} "
                            f"(risk_score: {result.risk_score:.2f})"
                        )
            except Exception as e:
                if self.fail_safe:
                    logger.error(f"Firewall error during input validation: {e}")
                    raise ValueError(f"Firewall error (fail-safe): {str(e)}") from e
                else:
                    logger.warning(f"Firewall error (non-blocking): {e}")

        super().on_llm_start(serialized, prompts, **kwargs)

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        """
        Validate outputs after LLM call.

        Called by LangChain after receiving response from LLM.
        """
        if not HAS_LANGCHAIN:
            return

        try:
            for generation_list in response.generations:
                for generation in generation_list:
                    # Extract text from generation
                    text = (
                        generation.text
                        if hasattr(generation, "text")
                        else str(generation)
                    )

                    try:
                        result = check_output(text)

                        if self.log_decisions:
                            logger.info(
                                f"Firewall output check: allowed={result.allowed}, "
                                f"risk={result.risk_score:.2f}"
                            )

                        if not result.allowed:
                            violation = {
                                "stage": "output",
                                "content": text[:100] + "..."
                                if len(text) > 100
                                else text,
                                "reason": result.reason,
                                "risk_score": result.risk_score,
                            }
                            self._violations.append(violation)

                            if self.on_violation == "block":
                                # Replace with blocked message
                                if hasattr(generation, "text"):
                                    generation.text = (
                                        "[Blocked by LLM Firewall: "
                                        + result.reason
                                        + "]"
                                    )
                                raise ValueError(
                                    f"Firewall violation on output: {result.reason} "
                                    f"(risk_score: {result.risk_score:.2f})"
                                )
                            elif self.on_violation == "sanitize":
                                # Use sanitized version if available
                                if (
                                    hasattr(generation, "text")
                                    and result.sanitized_text
                                ):
                                    generation.text = result.sanitized_text
                                    logger.info("Output sanitized by firewall")
                            elif self.on_violation == "warn":
                                logger.warning(
                                    f"Firewall violation (warning only): {result.reason}"
                                )
                    except ValueError as e:
                        # Re-raise if blocking
                        if self.on_violation == "block":
                            raise
                        logger.warning(f"Firewall validation error: {e}")
                    except Exception as e:
                        if self.fail_safe:
                            logger.error(
                                f"Firewall error during output validation: {e}"
                            )
                            raise ValueError(
                                f"Firewall error (fail-safe): {str(e)}"
                            ) from e
                        else:
                            logger.warning(f"Firewall error (non-blocking): {e}")
        except Exception as e:
            if self.fail_safe:
                logger.error(f"Firewall error during output validation: {e}")
                raise ValueError(f"Firewall error (fail-safe): {str(e)}") from e

        super().on_llm_end(response, **kwargs)

    def _handle_violation(
        self,
        stage: str,
        content: str,
        result: GuardResult,
    ) -> None:
        """
        Handle policy violation.

        Args:
            stage: "input" or "output"
            content: Violated content
            result: GuardResult with violation details
        """
        if self.on_violation == "warn":
            logger.warning(
                f"Firewall violation ({stage}): {result.reason} "
                f"(risk_score: {result.risk_score:.2f})"
            )
        elif self.on_violation == "block":
            logger.error(
                f"Firewall blocked {stage}: {result.reason} "
                f"(risk_score: {result.risk_score:.2f})"
            )

    @property
    def violations(self) -> List[Dict[str, Any]]:
        """
        Get all captured policy violations.

        Returns:
            List of violation records with stage, content, reason, risk_score
        """
        return self._violations.copy()

    def reset_violations(self) -> None:
        """Clear violation history (useful for testing)."""
        self._violations.clear()
