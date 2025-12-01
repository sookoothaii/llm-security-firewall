"""
Adapter Health Monitoring & Circuit Breaker Pattern.

P0 Item from external architecture review.

Creator: Implementation for External Review P0 Requirements
Date: 2025-12-01
Status: P0 - Circuit Breaker Pattern
License: MIT
"""

import time
from typing import Optional, Dict, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "CLOSED"  # Normal operation
    OPEN = "OPEN"  # Adapter failing, fast-fail
    HALF_OPEN = "HALF_OPEN"  # Testing recovery


class AdapterHealth:
    """
    Health monitoring and circuit breaker for adapters.

    Tracks error rates, latency, and manages fail-open behavior.

    Usage:
        health = AdapterHealth("redis_cache", failure_threshold=3)

        if health.should_attempt():
            try:
                result = adapter_call()
                health.record_request(latency_ms=10.0, success=True)
            except Exception as e:
                health.record_request(latency_ms=5.0, success=False)
                # Fail-open: return None
    """

    def __init__(
        self,
        adapter_name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,  # seconds
        max_latency_ms: float = 1000.0,
        error_rate_threshold: float = 0.5,  # 50% errors
    ):
        """
        Initialize adapter health monitor.

        Args:
            adapter_name: Name of the adapter (e.g., "redis_cache")
            failure_threshold: Number of consecutive failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery (HALF_OPEN)
            max_latency_ms: Maximum acceptable P99 latency in milliseconds
            error_rate_threshold: Error rate threshold (0.0-1.0) before opening circuit
        """
        self.adapter_name = adapter_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.max_latency_ms = max_latency_ms
        self.error_rate_threshold = error_rate_threshold

        # State
        self.state = CircuitState.CLOSED
        self.consecutive_failures = 0
        self.total_requests = 0
        self.total_errors = 0
        self.last_failure_time: Optional[float] = None
        self.last_latency_ms: float = 0.0
        self.error_rate: float = 0.0

        # Metrics history (last 100 samples)
        self.latency_history: list[float] = []
        self.error_history: list[bool] = []

    def record_request(self, latency_ms: float, success: bool):
        """
        Record a request attempt.

        Args:
            latency_ms: Request latency in milliseconds
            success: Whether the request succeeded
        """
        self.total_requests += 1
        self.last_latency_ms = latency_ms
        self.latency_history.append(latency_ms)
        self.error_history.append(not success)

        # Keep only last 100 samples
        if len(self.latency_history) > 100:
            self.latency_history.pop(0)
            self.error_history.pop(0)

        # Update error rate
        if success:
            self.consecutive_failures = 0
        else:
            self.total_errors += 1
            self.consecutive_failures += 1
            self.last_failure_time = time.time()

        self.error_rate = self.total_errors / max(self.total_requests, 1)

        # Update circuit state
        self._update_state()

    def _update_state(self):
        """Update circuit breaker state based on health metrics."""
        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if (
                self.last_failure_time
                and time.time() - self.last_failure_time > self.recovery_timeout
            ):
                self.state = CircuitState.HALF_OPEN
                logger.info(
                    f"Adapter {self.adapter_name}: HALF_OPEN (testing recovery)"
                )

        elif self.state == CircuitState.HALF_OPEN:
            # Stay in HALF_OPEN until we have successful requests
            if self.consecutive_failures == 0:
                self.state = CircuitState.CLOSED
                logger.info(f"Adapter {self.adapter_name}: CLOSED (recovered)")

        elif self.state == CircuitState.CLOSED:
            # Check if we should open the circuit
            p99_latency = self._calculate_p99_latency()
            if (
                self.consecutive_failures >= self.failure_threshold
                or self.error_rate > self.error_rate_threshold
                or p99_latency > self.max_latency_ms
            ):
                self.state = CircuitState.OPEN
                logger.warning(
                    f"Adapter {self.adapter_name}: OPEN "
                    f"(failures: {self.consecutive_failures}, "
                    f"error_rate: {self.error_rate:.2f}, "
                    f"p99_latency: {p99_latency:.2f}ms)"
                )

    def _calculate_p99_latency(self) -> float:
        """Calculate P99 latency from history."""
        if not self.latency_history:
            return 0.0

        sorted_latencies = sorted(self.latency_history)
        index = int(len(sorted_latencies) * 0.99)
        return sorted_latencies[min(index, len(sorted_latencies) - 1)]

    def should_attempt(self) -> bool:
        """
        Check if we should attempt a request.

        Returns:
            True if circuit is CLOSED or HALF_OPEN, False if OPEN
        """
        return self.state != CircuitState.OPEN

    def get_health_metrics(self) -> Dict[str, Any]:
        """
        Get current health metrics.

        Returns:
            Dictionary with health metrics for monitoring.
        """
        return {
            "adapter_name": self.adapter_name,
            "state": self.state.value,
            "consecutive_failures": self.consecutive_failures,
            "total_requests": self.total_requests,
            "total_errors": self.total_errors,
            "error_rate": self.error_rate,
            "last_latency_ms": self.last_latency_ms,
            "p99_latency_ms": self._calculate_p99_latency(),
            "last_failure_time": self.last_failure_time,
        }

    def reset(self):
        """Reset health metrics (for testing)."""
        self.state = CircuitState.CLOSED
        self.consecutive_failures = 0
        self.total_requests = 0
        self.total_errors = 0
        self.last_failure_time = None
        self.latency_history.clear()
        self.error_history.clear()
