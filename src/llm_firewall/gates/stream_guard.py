"""
Streaming Token-Level Guard
============================

Real-time per-token safety monitoring during LLM generation.

Based on: Qwen3Guard-Stream approach (2025)
Target: <1ms per token latency

Creator: Joerg Bollwahn
Date: 2025-10-30
License: MIT
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Protocol, Tuple

from llm_firewall.core.types import ModelContext, Severity

# Safe replacement templates for REWRITE action
SAFE_TEMPLATES = {
    Severity.LOW: "[content filtered]",
    Severity.MEDIUM: "[potentially sensitive content removed]",
    Severity.HIGH: "[unsafe content blocked]",
    Severity.CRITICAL: "[critical safety violation prevented]",
}


class StreamAction(Enum):
    """Action to take on token."""

    CONTINUE = "continue"  # Pass token through
    REWRITE = "rewrite"  # Replace with safe alternative
    ABORT = "abort"  # Stop generation immediately


@dataclass
class StreamState:
    """State tracking during streaming generation."""

    step: int  # Token index
    cumulative_risk: float  # Running risk accumulator
    last_severity: Severity  # Most recent severity
    window_text: str  # Sliding window of recent tokens

    # Critical-Leak@n tracking
    critical_tokens: List[str] = field(
        default_factory=list
    )  # Tokens with severity >= HIGH
    leak_positions: List[int] = field(default_factory=list)  # Token positions of leaks
    first_n_checked: int = 20  # Check first N tokens for critical leaks

    extras: Dict[str, Any] = field(default_factory=dict)


class StreamGuard(Protocol):
    """
    Protocol for streaming token-level guards.

    Must be O(1) per token for production use.
    """

    def start(self, ctx: ModelContext) -> StreamState:
        """Initialize stream state."""
        ...

    def on_token(
        self, token: str, state: StreamState
    ) -> Tuple[StreamAction, StreamState]:
        """
        Evaluate single token for safety.

        Three-tiered severity:
        - NONE/LOW (0-1): continue
        - MEDIUM (2): rewrite or soft-prune
        - HIGH/CRITICAL (3-4): abort stream

        Args:
            token: Current token
            state: Current stream state

        Returns:
            (action, updated_state)
        """
        ...

    def finish(self, state: StreamState) -> None:
        """Cleanup after stream complete."""
        ...


class RollingWindowStreamGuard:
    """
    Streaming guard with rolling window severity detection.

    Uses sliding window of last N tokens to compute cumulative risk.
    """

    def __init__(
        self,
        window_size: int = 64,
        abort_severity: Severity = Severity.HIGH,
        rewrite_severity: Severity = Severity.LOW,
        risk_decay: float = 0.9,
    ):
        """
        Initialize stream guard.

        Args:
            window_size: Tokens to keep in sliding window
            abort_severity: Severity threshold for abort
            rewrite_severity: Severity threshold for rewrite
            risk_decay: Decay factor for cumulative risk (0-1)
        """
        self.window_size = window_size
        self.abort_severity = abort_severity
        self.rewrite_severity = rewrite_severity
        self.risk_decay = risk_decay

        # Simple pattern-based severity detector (can be replaced with ML)
        self.high_risk_patterns = [
            "step",
            "1:",
            "2:",
            "first",
            "then",
            "finally",  # Instructional (no spaces, token-level)
            "recipe",
            "howto",
            "ingredients",  # Procedural
            "password",
            "key",
            "token",
            "credential",  # Sensitive data
        ]

    def start(self, ctx: ModelContext) -> StreamState:
        """Initialize stream state."""
        return StreamState(
            step=0,
            cumulative_risk=0.0,
            last_severity=Severity.NONE,
            window_text="",
            critical_tokens=[],
            leak_positions=[],
            first_n_checked=20,
            extras={"ctx": ctx},
        )

    def on_token(
        self, token: str, state: StreamState
    ) -> Tuple[StreamAction, StreamState]:
        """
        Evaluate token and update state.

        Simple implementation - can be replaced with ML model.
        """
        # Update window
        state.window_text += token
        if len(state.window_text) > self.window_size * 10:  # Approx token length
            state.window_text = state.window_text[-self.window_size * 10 :]

        # Compute severity (simple pattern-based)
        severity = self._compute_severity(token, state.window_text)

        # Update cumulative risk (use severity.value for numeric calculation)
        state.cumulative_risk = (state.cumulative_risk * self.risk_decay) + float(
            severity.value
        ) / 10.0
        state.last_severity = severity

        # Track critical leaks in first N tokens
        if state.step < state.first_n_checked and severity >= Severity.HIGH:
            state.critical_tokens.append(token)
            state.leak_positions.append(state.step)

        state.step += 1

        # Decide action (prefer REWRITE over ABORT when possible)
        if severity >= self.abort_severity:
            # Check if we can rewrite instead of abort
            if state.step > state.first_n_checked and severity < Severity.CRITICAL:
                action = StreamAction.REWRITE
            else:
                action = StreamAction.ABORT
        elif severity >= self.rewrite_severity:
            action = StreamAction.REWRITE
        else:
            action = StreamAction.CONTINUE

        return action, state

    def _compute_severity(self, token: str, window: str) -> Severity:
        """
        Compute severity for current token + window.

        Simple pattern-based implementation.
        Production should use ML model (e.g., Qwen3Guard-Stream).
        """
        text_lower = (window + token).lower()

        # Check for high-risk patterns
        for pattern in self.high_risk_patterns:
            if pattern in text_lower:
                return Severity.MEDIUM

        # Default: safe
        return Severity.NONE

    def finish(self, state: StreamState) -> None:
        """Cleanup after stream."""
        # Log final state if needed
        pass
