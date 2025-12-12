"""
Synchronous Circuit Breaker for ML Models
==========================================

Simple circuit breaker pattern for ML model adapters.
Prevents cascading failures when models are unavailable or slow.

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import logging
import time
from enum import Enum
from typing import Optional, Callable, Any

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered


class SimpleCircuitBreaker:
    """
    Simple synchronous circuit breaker for ML models.
    
    Features:
    - Failure threshold tracking
    - Recovery timeout
    - Half-open state for testing recovery
    """
    
    def __init__(
        self,
        name: str,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
        on_state_change: Optional[Callable[[str, CircuitState], None]] = None
    ):
        """
        Initialize circuit breaker.
        
        Args:
            name: Name of the circuit (for logging)
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Time to wait before half-open (seconds)
            on_state_change: Optional callback when state changes
        """
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.on_state_change = on_state_change
        
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.last_success_time: Optional[float] = None
        self.state = CircuitState.CLOSED
        
    def allow_request(self) -> bool:
        """
        Check if request should be allowed.
        
        Returns:
            True if request should be processed, False if circuit is open
        """
        if self.state == CircuitState.CLOSED:
            return True
        
        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if (
                self.last_failure_time is not None
                and time.time() - self.last_failure_time > self.recovery_timeout
            ):
                self._transition_to(CircuitState.HALF_OPEN)
                return True
            return False
        
        # HALF_OPEN: Allow limited requests to test recovery
        return True
    
    def on_success(self):
        """Record successful request."""
        if self.state == CircuitState.HALF_OPEN:
            # Circuit recovered
            self._transition_to(CircuitState.CLOSED)
            self.failure_count = 0
            logger.info(f"Circuit breaker {self.name} recovered (CLOSED)")
        
        self.last_success_time = time.time()
    
    def on_failure(self, error: Optional[Exception] = None):
        """
        Record failed request.
        
        Args:
            error: Optional exception that caused the failure
        """
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.HALF_OPEN:
            # Still failing, go back to OPEN
            self._transition_to(CircuitState.OPEN)
            logger.warning(
                f"Circuit breaker {self.name} failed in HALF_OPEN, "
                f"opening circuit (error: {error})"
            )
        elif self.failure_count >= self.failure_threshold:
            # Threshold reached, open circuit
            self._transition_to(CircuitState.OPEN)
            logger.warning(
                f"Circuit breaker {self.name} opened after {self.failure_count} failures "
                f"(error: {error})"
            )
    
    def _transition_to(self, new_state: CircuitState):
        """Transition to new state and notify callback."""
        if self.state != new_state:
            old_state = self.state
            self.state = new_state
            
            if self.on_state_change:
                self.on_state_change(self.name, new_state)
            
            logger.debug(
                f"Circuit breaker {self.name} transitioned: {old_state.value} -> {new_state.value}"
            )
    
    def reset(self):
        """Manually reset circuit breaker to CLOSED state."""
        self._transition_to(CircuitState.CLOSED)
        self.failure_count = 0
        self.last_failure_time = None
        logger.info(f"Circuit breaker {self.name} manually reset")

