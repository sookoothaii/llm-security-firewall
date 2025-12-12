"""
Circuit Breaker Manager for Detector Microservices
==================================================

Synchronous circuit breaker manager for detector microservices.
Manages circuit state per detector to prevent cascading failures.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
Status: Phase 1 - Foundation
License: MIT
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Optional
from enum import Enum

from llm_firewall.detectors.detector_registry import DetectorConfig, CircuitBreakerConfig

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class DetectorCircuitState:
    """Circuit state for a single detector."""
    detector_name: str
    state: CircuitState = CircuitState.CLOSED
    failures: int = 0
    last_failure: float = 0.0
    opened_at: float = 0.0
    half_open_calls: int = 0
    total_requests: int = 0
    total_failures: int = 0


class CircuitBreakerManager:
    """
    Manages circuit breakers for all detector microservices.
    
    Features:
    - Per-detector circuit state tracking
    - Configurable failure thresholds
    - Recovery timeout handling
    - Half-open state management
    """
    
    def __init__(self):
        """Initialize circuit breaker manager."""
        self.circuits: Dict[str, DetectorCircuitState] = {}
        logger.info("CircuitBreakerManager initialized")
    
    def get_circuit_state(
        self,
        detector_config: DetectorConfig
    ) -> DetectorCircuitState:
        """
        Get or create circuit state for detector.
        
        Args:
            detector_config: Detector configuration
            
        Returns:
            DetectorCircuitState for this detector
        """
        if detector_config.name not in self.circuits:
            self.circuits[detector_config.name] = DetectorCircuitState(
                detector_name=detector_config.name
            )
        return self.circuits[detector_config.name]
    
    def is_available(self, detector_config: DetectorConfig) -> bool:
        """
        Check if detector is available (circuit closed or half-open).
        
        Args:
            detector_config: Detector configuration
            
        Returns:
            True if detector can be called, False if circuit is open
        """
        state = self.get_circuit_state(detector_config)
        cb_config = detector_config.circuit_breaker
        
        # Check if circuit is open
        if state.state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            elapsed = time.time() - state.opened_at
            if elapsed > (cb_config.recovery_timeout_ms / 1000.0):
                # Transition to half-open
                state.state = CircuitState.HALF_OPEN
                state.half_open_calls = 0
                logger.info(
                    f"Circuit breaker for {detector_config.name} transitioning to HALF_OPEN"
                )
                return True
            else:
                # Still in open state
                return False
        
        # Circuit is closed or half-open - available
        return True
    
    def record_success(self, detector_config: DetectorConfig):
        """
        Record successful detector call.
        
        Args:
            detector_config: Detector configuration
        """
        state = self.get_circuit_state(detector_config)
        state.total_requests += 1
        
        if state.state == CircuitState.HALF_OPEN:
            # Circuit recovered
            state.state = CircuitState.CLOSED
            state.failures = 0
            state.half_open_calls = 0
            logger.info(
                f"Circuit breaker for {detector_config.name} recovered (CLOSED)"
            )
        elif state.state == CircuitState.OPEN:
            # Should not happen, but handle gracefully
            state.state = CircuitState.CLOSED
            state.failures = 0
    
    def record_failure(self, detector_config: DetectorConfig, error: Optional[str] = None):
        """
        Record failed detector call.
        
        Args:
            detector_config: Detector configuration
            error: Optional error message
        """
        state = self.get_circuit_state(detector_config)
        state.total_requests += 1
        state.total_failures += 1
        state.failures += 1
        state.last_failure = time.time()
        
        cb_config = detector_config.circuit_breaker
        
        # Check if circuit should open
        if state.state == CircuitState.HALF_OPEN:
            # Half-open call failed - reopen circuit
            state.state = CircuitState.OPEN
            state.opened_at = time.time()
            state.half_open_calls = 0
            logger.warning(
                f"Circuit breaker for {detector_config.name} reopened after half-open failure"
            )
        elif state.failures >= cb_config.failure_threshold:
            # Open circuit
            if state.state != CircuitState.OPEN:
                state.state = CircuitState.OPEN
                state.opened_at = time.time()
                logger.warning(
                    f"Circuit breaker for {detector_config.name} OPENED "
                    f"(failures: {state.failures}/{cb_config.failure_threshold})"
                )
    
    def get_statistics(self, detector_name: Optional[str] = None) -> Dict:
        """
        Get circuit breaker statistics.
        
        Args:
            detector_name: Optional detector name (if None, returns all)
            
        Returns:
            Statistics dictionary
        """
        if detector_name:
            if detector_name not in self.circuits:
                return {}
            state = self.circuits[detector_name]
            failure_rate = (
                state.total_failures / state.total_requests
                if state.total_requests > 0
                else 0.0
            )
            return {
                "detector_name": detector_name,
                "state": state.state.value,
                "failures": state.failures,
                "total_requests": state.total_requests,
                "total_failures": state.total_failures,
                "failure_rate": failure_rate,
                "last_failure": state.last_failure,
                "opened_at": state.opened_at,
            }
        else:
            # Return all statistics
            return {
                name: self.get_statistics(name)
                for name in self.circuits.keys()
            }
    
    def reset(self, detector_name: Optional[str] = None):
        """
        Manually reset circuit breaker (for testing/admin).
        
        Args:
            detector_name: Optional detector name (if None, resets all)
        """
        if detector_name:
            if detector_name in self.circuits:
                state = self.circuits[detector_name]
                state.state = CircuitState.CLOSED
                state.failures = 0
                state.last_failure = 0.0
                state.opened_at = 0.0
                state.half_open_calls = 0
                logger.info(f"Circuit breaker for {detector_name} manually reset")
        else:
            # Reset all
            for name in list(self.circuits.keys()):
                self.reset(name)
