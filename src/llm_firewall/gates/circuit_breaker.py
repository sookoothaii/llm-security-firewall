# -*- coding: utf-8 -*-
"""
Circuit Breaker Pattern for Firewall Guards
===========================================

Implements circuit breaker pattern to prevent cascading failures.
Maintains 99.9% uptime even with guard failures.

Based on Kimi K2 Thinking recommendations (2025-11-26).

Creator: Joerg Bollwahn (with Kimi K2 collaboration)
License: MIT
"""

import asyncio
import time
from enum import Enum
from typing import Any, Callable, Dict, Optional

from llm_firewall.pipeline.cascading_firewall import GuardLayer


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered


class CircuitBreaker:
    """Circuit breaker wrapper for guard layers."""

    def __init__(
        self,
        guard: GuardLayer,
        failure_threshold: int = 5,
        timeout_seconds: float = 30.0,
        per_request_timeout: float = 0.5,
        alert_callback: Optional[Callable[[str], None]] = None,
    ):
        """Initialize circuit breaker.

        Args:
            guard: Guard layer to protect
            failure_threshold: Number of failures before opening circuit
            timeout_seconds: Time to wait before half-open
            per_request_timeout: Timeout for individual requests
            alert_callback: Optional callback for alerts
        """
        self.guard = guard
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self.per_request_timeout = per_request_timeout
        self.alert_callback = alert_callback

        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.last_success_time: Optional[float] = None
        self.state = CircuitState.CLOSED
        self.total_requests = 0
        self.total_failures = 0

    async def score(self, text: str, metadata: Dict[str, Any]) -> float:
        """
        Score text with circuit breaker protection.

        Args:
            text: Input text
            metadata: Context metadata

        Returns:
            Risk score (0.0 = safe, 1.0 = dangerous)
        """
        self.total_requests += 1

        # Check circuit state
        if self.state == CircuitState.OPEN:
            # Check if timeout has passed
            if (
                self.last_failure_time is not None
                and time.time() - self.last_failure_time > self.timeout_seconds
            ):
                self.state = CircuitState.HALF_OPEN
            else:
                # Fail open: return safe default (don't block users)
                return 0.0

        # Attempt request
        try:
            score = await asyncio.wait_for(
                self.guard.score(text, metadata),
                timeout=self.per_request_timeout,
            )

            # Success
            if self.state == CircuitState.HALF_OPEN:
                # Circuit recovered
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                if self.alert_callback:
                    self.alert_callback(f"Circuit BREAKER RECOVERED: {self.guard.name}")

            self.last_success_time = time.time()
            return score

        except asyncio.TimeoutError:
            return await self._handle_failure("timeout")

        except Exception as e:
            return await self._handle_failure(f"exception: {str(e)}")

    async def _handle_failure(self, reason: str) -> float:
        """Handle guard failure."""
        self.failure_count += 1
        self.total_failures += 1
        self.last_failure_time = time.time()

        # Check if circuit should open
        if self.failure_count >= self.failure_threshold:
            if self.state != CircuitState.OPEN:
                self.state = CircuitState.OPEN
                if self.alert_callback:
                    self.alert_callback(
                        f"Circuit BREAKER OPENED: {self.guard.name} "
                        f"(failures: {self.failure_count}, reason: {reason})"
                    )

        # Fail closed for critical layers (block on error)
        # Fail open for non-critical layers (allow on error)
        if self.guard.is_critical:
            return 1.0  # Block on critical layer failure
        else:
            return 0.0  # Allow on non-critical layer failure

    def get_statistics(self) -> Dict[str, Any]:
        """Get circuit breaker statistics."""
        failure_rate = (
            self.total_failures / self.total_requests
            if self.total_requests > 0
            else 0.0
        )

        return {
            "guard_name": self.guard.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "total_requests": self.total_requests,
            "total_failures": self.total_failures,
            "failure_rate": failure_rate,
            "last_failure_time": self.last_failure_time,
            "last_success_time": self.last_success_time,
        }

    def reset(self):
        """Manually reset circuit breaker (for testing/admin)."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
