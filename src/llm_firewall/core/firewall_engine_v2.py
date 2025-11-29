"""
HAK_GAL Core Engine v2 - Protocol HEPHAESTUS Integration
========================================================

Clean, linear layer architecture for LLM security firewall.
Integrates Protocol HEPHAESTUS (Tool Security) for tool call validation.

Architecture:
- Layer 0: UnicodeSanitizer (Input sanitization)
- Layer 1: Input Analysis (Optional: Kids Policy, Semantic Guard)
- Layer 2: Tool Inspection (HEPHAESTUS - Tool Call Validation)
- Layer 3: Output Validation (Optional: Truth Preservation)

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-11-29
Status: Core Engine v2 - Protocol HEPHAESTUS
License: MIT
"""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

# Import UnicodeSanitizer and Kids Policy Engine from kids_policy
try:
    import sys
    from pathlib import Path

    # Add kids_policy to path
    kids_policy_path = Path(__file__).parent.parent.parent.parent / "kids_policy"
    if kids_policy_path.exists():
        sys.path.insert(0, str(kids_policy_path.parent))
        from kids_policy.unicode_sanitizer import UnicodeSanitizer
        from kids_policy.firewall_engine_v2 import HakGalFirewall_v2

        HAS_UNICODE_SANITIZER = True
        HAS_KIDS_POLICY = True
    else:
        HAS_UNICODE_SANITIZER = False
        HAS_KIDS_POLICY = False
        UnicodeSanitizer = None
        HakGalFirewall_v2 = None
except ImportError:
    HAS_UNICODE_SANITIZER = False
    HAS_KIDS_POLICY = False
    UnicodeSanitizer = None
    HakGalFirewall_v2 = None

# Import Protocol HEPHAESTUS components
from llm_firewall.detectors.tool_call_extractor import ToolCallExtractor
from llm_firewall.detectors.tool_call_validator import ToolCallValidator

logger = logging.getLogger(__name__)


@dataclass
class FirewallDecision:
    """
    Decision result from firewall processing.

    Attributes:
        allowed: Whether the request/response is allowed
        reason: Human-readable reason for allow/block decision
        sanitized_text: Sanitized text (if sanitization was applied)
        risk_score: Risk score [0.0, 1.0]
        detected_threats: List of detected threat patterns
        metadata: Additional metadata (tool calls, etc.)
    """

    allowed: bool
    reason: str
    sanitized_text: Optional[str] = None
    risk_score: float = 0.0
    detected_threats: List[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.detected_threats is None:
            self.detected_threats = []
        if self.metadata is None:
            self.metadata = {}


class FirewallEngineV2:
    """
    HAK_GAL Core Engine v2 - Clean Layer Architecture.

    Architecture:
    - Layer 0: UnicodeSanitizer (Input sanitization)
    - Layer 1: Input Analysis (Optional: Kids Policy, Semantic Guard)
    - Layer 2: Tool Inspection (HEPHAESTUS - Tool Call Validation)
    - Layer 3: Output Validation (Optional: Truth Preservation)

    Usage:
        engine = FirewallEngineV2()
        input_decision = engine.process_input(user_id="user123", text="user input")
        if input_decision.allowed:
            # Send to LLM
            llm_output = generate_llm_response(input_decision.sanitized_text)
            output_decision = engine.process_output(text=llm_output, user_id="user123")
            if output_decision.allowed:
                # Return to user
                return output_decision.sanitized_text
    """

    def __init__(
        self,
        allowed_tools: Optional[List[str]] = None,
        strict_mode: bool = True,
        enable_sanitization: bool = True,
    ):
        """
        Initialize Firewall Engine v2.

        Args:
            allowed_tools: List of allowed tool names for Protocol HEPHAESTUS
            strict_mode: If True, blocks on any detected threat. If False, sanitizes and warns.
            enable_sanitization: If True, attempts to sanitize dangerous arguments.
        """
        # Layer 0: UnicodeSanitizer
        if HAS_UNICODE_SANITIZER and UnicodeSanitizer is not None:
            self.sanitizer = UnicodeSanitizer(enable_emoji_demojize=True)
            logger.info("UnicodeSanitizer initialized (Layer 0)")
        else:
            self.sanitizer = None
            logger.warning(
                "UnicodeSanitizer not available. Input sanitization disabled."
            )

        # Protocol HEPHAESTUS: Tool Call Extractor
        self.extractor = ToolCallExtractor(strict_mode=False)
        logger.info("ToolCallExtractor initialized (Protocol HEPHAESTUS)")

        # Protocol HEPHAESTUS: Tool Call Validator
        self.validator = ToolCallValidator(
            allowed_tools=allowed_tools,
            strict_mode=strict_mode,
            enable_sanitization=enable_sanitization,
        )
        logger.info("ToolCallValidator initialized (Protocol HEPHAESTUS)")

        # Kids Policy Engine (v2.1.0-HYDRA) - Full Integration
        self.kids_policy = None
        if HAS_KIDS_POLICY and HakGalFirewall_v2 is not None:
            try:
                self.kids_policy = HakGalFirewall_v2()
                logger.info(
                    "Kids Policy Engine v2.1.0-HYDRA initialized (TAG-2 + HYDRA-13)"
                )
            except Exception as e:
                logger.warning(f"Kids Policy Engine initialization failed: {e}")
                self.kids_policy = None
        else:
            logger.warning(
                "Kids Policy Engine not available. Input/Output validation limited."
            )

    def process_input(
        self,
        user_id: str,
        text: str,
        **kwargs,
    ) -> FirewallDecision:
        """
        Process user input through firewall layers.

        Args:
            user_id: Unique user identifier
            text: Raw user input text
            **kwargs: Additional context (age_band, topic_id, etc.)

        Returns:
            FirewallDecision with allow/block decision and sanitized text
        """
        if not text or not text.strip():
            return FirewallDecision(
                allowed=True,
                reason="Empty input",
                sanitized_text="",
                risk_score=0.0,
            )

        # Layer 0: UnicodeSanitizer
        clean_text = text
        unicode_flags = {}
        if self.sanitizer:
            try:
                clean_text, unicode_flags = self.sanitizer.sanitize(text)
                if clean_text != text:
                    logger.debug(
                        f"[Layer 0] Unicode sanitization applied: {len(unicode_flags)} flags"
                    )
            except Exception as e:
                logger.warning(
                    f"[Layer 0] UnicodeSanitizer error: {e}. Using original text."
                )
                clean_text = text

        # Layer 1: Kids Policy Engine (v2.1.0-HYDRA) - Input Validation
        if self.kids_policy:
            try:
                # Call Kids Policy process_request (includes all layers: PersonaSkeptic, MetaExploitationGuard, TopicRouter, etc.)
                kids_result = self.kids_policy.process_request(
                    user_id=user_id,
                    raw_input=clean_text,
                    detected_topic=kwargs.get("topic_id"),
                )

                # Check if Kids Policy blocked the input
                if kids_result.get("status") == "BLOCK":
                    # Security First: Block immediately
                    logger.warning(
                        f"[Layer 1] BLOCKED by Kids Policy: {kids_result.get('reason', 'Unknown')}"
                    )
                    return FirewallDecision(
                        allowed=False,
                        reason=f"Kids Policy: {kids_result.get('reason', 'BLOCKED')}",
                        sanitized_text=None,
                        risk_score=kids_result.get("debug", {}).get("risk_score", 1.0),
                        detected_threats=[
                            kids_result.get("block_reason_code", "KIDS_POLICY_BLOCK")
                        ],
                        metadata={
                            "kids_policy_result": kids_result,
                            "unicode_flags": unicode_flags,
                        },
                    )

                # Kids Policy allowed - continue
                logger.debug("[Layer 1] Kids Policy: ALLOWED")
                # Update clean_text if Kids Policy modified it (though it usually doesn't)
                if "debug" in kids_result and "input" in kids_result["debug"]:
                    clean_text = kids_result["debug"]["input"]

            except Exception as e:
                logger.error(f"[Layer 1] Kids Policy Engine error: {e}", exc_info=True)
                # Fail-open: Continue if Kids Policy fails (could be made fail-closed)
                # For now, we continue to allow the input

        # Input is allowed (passed all layers)
        return FirewallDecision(
            allowed=True,
            reason="Input validated",
            sanitized_text=clean_text,
            risk_score=0.0,
            metadata={"unicode_flags": unicode_flags},
        )

    def process_output(
        self,
        text: str,
        user_id: Optional[str] = None,
        **kwargs,
    ) -> FirewallDecision:
        """
        Process LLM output through firewall layers (Protocol HEPHAESTUS).

        This is the core method for Protocol HEPHAESTUS integration.

        Args:
            text: Raw LLM output text (may contain tool calls)
            user_id: Optional user identifier for session tracking
            **kwargs: Additional context

        Returns:
            FirewallDecision with allow/block decision and sanitized text
        """
        if not text or not text.strip():
            return FirewallDecision(
                allowed=True,
                reason="Empty output",
                sanitized_text="",
                risk_score=0.0,
            )

        # Step A: Extract tool calls from LLM output
        tool_calls = self.extractor.extract_tool_calls(text)

        if not tool_calls:
            # No tool calls found - output is plain text
            # Layer 3: Kids Policy Truth Preservation (TAG-2)
            if self.kids_policy:
                try:
                    # Call Kids Policy validate_output for Truth Preservation
                    kids_output_result = self.kids_policy.validate_output(
                        user_id=user_id or "unknown",
                        user_input=kwargs.get("user_input", ""),
                        llm_response=text,
                        age_band=kwargs.get("age_band"),
                        topic_id=kwargs.get("topic_id"),
                        cultural_context=kwargs.get("cultural_context", "none"),
                    )

                    # Check if Kids Policy blocked the output (Truth Violation)
                    if kids_output_result.get("status") == "BLOCK":
                        logger.warning(
                            f"[Layer 3] BLOCKED by Kids Policy Truth Preservation: {kids_output_result.get('reason', 'Unknown')}"
                        )
                        return FirewallDecision(
                            allowed=False,
                            reason=f"Truth Preservation: {kids_output_result.get('reason', 'TRUTH_VIOLATION')}",
                            sanitized_text=None,
                            risk_score=kids_output_result.get("debug", {}).get(
                                "risk_score", 1.0
                            ),
                            detected_threats=["TRUTH_VIOLATION"],
                            metadata={
                                "kids_policy_output_result": kids_output_result,
                            },
                        )

                    # Kids Policy allowed - output is valid
                    logger.debug("[Layer 3] Kids Policy Truth Preservation: ALLOWED")

                except Exception as e:
                    logger.error(
                        f"[Layer 3] Kids Policy Truth Preservation error: {e}",
                        exc_info=True,
                    )
                    # Fail-open: Continue if Truth Preservation fails

            return FirewallDecision(
                allowed=True,
                reason="No tool calls detected, plain text output validated",
                sanitized_text=text,
                risk_score=0.0,
            )

        # Step B: Validate each tool call
        logger.info(f"[HEPHAESTUS] Found {len(tool_calls)} tool call(s) in output")
        detected_threats = []
        max_risk_score = 0.0
        sanitized_calls = []

        for call in tool_calls:
            tool_name = call["tool_name"]
            arguments = call["arguments"]

            # Step C: Validate tool call
            validation_result = self.validator.validate_tool_call(tool_name, arguments)

            if not validation_result.allowed:
                # Security First: Block entire response if any tool call is blocked
                logger.warning(
                    f"[HEPHAESTUS] BLOCKED: Tool '{tool_name}' rejected. Reason: {validation_result.reason}"
                )
                return FirewallDecision(
                    allowed=False,
                    reason=f"Tool call blocked: {validation_result.reason}",
                    sanitized_text=None,
                    risk_score=validation_result.risk_score,
                    detected_threats=validation_result.detected_threats,
                    metadata={
                        "blocked_tool": tool_name,
                        "blocked_arguments": arguments,
                        "validation_result": validation_result,
                    },
                )

            # Tool call is allowed, but may have sanitized arguments
            if validation_result.sanitized_args != arguments:
                # Arguments were sanitized - replace in tool call
                sanitized_call = {
                    "tool_name": tool_name,
                    "arguments": validation_result.sanitized_args,
                }
                sanitized_calls.append(sanitized_call)
                logger.info(
                    f"[HEPHAESTUS] Sanitized arguments for tool '{tool_name}': {len(validation_result.detected_threats)} threats removed"
                )
            else:
                # No sanitization needed
                sanitized_calls.append(call)

            # Track threats and risk
            if validation_result.detected_threats:
                detected_threats.extend(validation_result.detected_threats)
            max_risk_score = max(max_risk_score, validation_result.risk_score)

        # Step D: Rebuild text with sanitized tool calls (if any were sanitized)
        sanitized_text = text
        if any(
            call.get("arguments") != tool_calls[i]["arguments"]
            for i, call in enumerate(sanitized_calls)
        ):
            # At least one tool call was sanitized - rebuild text
            sanitized_text = self._rebuild_text_with_sanitized_calls(
                text, tool_calls, sanitized_calls
            )
            logger.info("[HEPHAESTUS] Rebuilt text with sanitized tool calls")

        # All tool calls validated and allowed
        return FirewallDecision(
            allowed=True,
            reason=f"All {len(tool_calls)} tool call(s) validated successfully",
            sanitized_text=sanitized_text,
            risk_score=max_risk_score,
            detected_threats=detected_threats,
            metadata={
                "tool_calls": sanitized_calls,
                "original_tool_calls": tool_calls,
            },
        )

    def _rebuild_text_with_sanitized_calls(
        self,
        original_text: str,
        original_calls: List[Dict[str, Any]],
        sanitized_calls: List[Dict[str, Any]],
    ) -> str:
        """
        Rebuild text with sanitized tool calls.

        This is a simple implementation that replaces JSON objects in the text.
        For v1, this is sufficient. Future versions may need more sophisticated
        text reconstruction.

        Args:
            original_text: Original LLM output text
            original_calls: Original tool calls (before sanitization)
            sanitized_calls: Sanitized tool calls (after validation)

        Returns:
            Text with sanitized tool calls
        """
        import json

        result = original_text

        # Simple approach: Replace each original tool call JSON with sanitized version
        for original, sanitized in zip(original_calls, sanitized_calls):
            # Try to find the original JSON in the text
            # This is a simple heuristic - may not work for all cases
            try:
                # Convert sanitized call back to JSON
                sanitized_json = json.dumps(sanitized, ensure_ascii=False)

                # Try to find and replace the original JSON
                # We'll search for the tool name as a marker
                tool_name = original["tool_name"]
                # Simple replacement: find JSON containing tool_name and replace
                # This is a basic implementation - can be improved
                import re

                pattern = rf'\{{[^}}]*["\']?tool["\']?\s*:\s*["\']?{re.escape(tool_name)}["\']?[^}}]*\}}'
                matches = list(re.finditer(pattern, result, re.IGNORECASE | re.DOTALL))
                if matches:
                    # Replace first match
                    result = (
                        result[: matches[0].start()]
                        + sanitized_json
                        + result[matches[0].end() :]
                    )
            except Exception as e:
                logger.warning(
                    f"[HEPHAESTUS] Failed to rebuild text for tool '{original.get('tool_name')}': {e}"
                )
                # If rebuilding fails, return original text (security: we already validated)
                continue

        return result
