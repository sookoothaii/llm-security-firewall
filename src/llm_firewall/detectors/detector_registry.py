"""
Detector Registry - LLM Firewall Battle Plan
============================================

Central registry for specialized detector microservices.
Implements Two-Ring Defense System architecture.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
Status: Phase 1 - Foundation
License: MIT
"""

import logging
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Protocol
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorPolicy(Enum):
    """Error handling policy for detector failures."""
    FAIL_OPEN = "fail_open"  # Allow request on error
    FAIL_CLOSED = "fail_closed"  # Block request on error
    FAIL_CLOSED_ON_HIGH_RISK = "fail_closed_on_high_risk"  # Block only if risk > threshold


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration for detector resilience."""
    failure_threshold: int = 5  # Open circuit after N failures
    recovery_timeout_ms: int = 30000  # Wait 30s before half-open
    half_open_max_calls: int = 3  # Max calls in half-open state


@dataclass
class DetectorConfig:
    """Configuration for a single detector microservice."""
    name: str
    version: str
    endpoint: str
    cost_class: str  # low, moderate, high
    timeout_ms: int
    categories: List[str]
    error_policy: ErrorPolicy
    circuit_breaker: CircuitBreakerConfig
    enabled: bool = False
    shadow_mode: bool = False  # Run in shadow mode (async, no blocking)
    description: str = ""


@dataclass
class DetectorResponse:
    """Response from a detector microservice."""
    detector_name: str
    risk_score: float  # [0.0, 1.0]
    category: Optional[str] = None
    confidence: float = 0.0
    matched_patterns: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    latency_ms: float = 0.0


class DetectorClient(Protocol):
    """Protocol for detector microservice clients."""
    
    def detect(self, text: str, context: Dict[str, Any]) -> DetectorResponse:
        """
        Call detector microservice.
        
        Args:
            text: Text to analyze
            context: Additional context (risk_score, categories, etc.)
            
        Returns:
            DetectorResponse with risk score and metadata
        """
        ...


class DetectorRegistry:
    """
    Central registry for detector microservices.
    
    Loads detector configurations from detectors.yml and manages
    detector clients, circuit breakers, and invocation logic.
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize detector registry.
        
        Args:
            config_path: Path to detectors.yml (default: config/detectors.yml)
        """
        if config_path is None:
            base_dir = Path(__file__).parent.parent.parent.parent
            config_path = base_dir / "config" / "detectors.yml"
        
        self.config_path = config_path
        self.detectors: Dict[str, DetectorConfig] = {}
        self.clients: Dict[str, DetectorClient] = {}
        
        # Initialize circuit breaker manager
        try:
            from llm_firewall.detectors.circuit_breaker_manager import CircuitBreakerManager
            self.circuit_breaker_manager = CircuitBreakerManager()
        except ImportError:
            self.circuit_breaker_manager = None
            logger.warning("CircuitBreakerManager not available")
        
        self._load_config()
        logger.info(f"DetectorRegistry initialized with {len(self.detectors)} detectors")
    
    def _load_config(self):
        """Load detector configurations from YAML file."""
        if not self.config_path.exists():
            logger.warning(f"Detector config not found: {self.config_path}. Using defaults.")
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            detectors_config = config.get('detectors', {})
            
            for name, detector_config in detectors_config.items():
                try:
                    detector = DetectorConfig(
                        name=name,
                        version=detector_config.get('version', '1.0.0'),
                        endpoint=detector_config.get('endpoint', ''),
                        cost_class=detector_config.get('cost_class', 'moderate'),
                        timeout_ms=detector_config.get('timeout_ms', 50),
                        categories=detector_config.get('categories', []),
                        error_policy=ErrorPolicy(detector_config.get('error_policy', 'fail_open')),
                        circuit_breaker=CircuitBreakerConfig(
                            **detector_config.get('circuit_breaker', {})
                        ),
                        enabled=detector_config.get('enabled', False),
                        shadow_mode=detector_config.get('shadow_mode', False),
                        description=detector_config.get('description', '')
                    )
                    self.detectors[name] = detector
                    logger.info(f"Loaded detector: {name} (enabled={detector.enabled})")
                except Exception as e:
                    logger.error(f"Failed to load detector {name}: {e}")
        
        except Exception as e:
            logger.error(f"Failed to load detector config: {e}")
    
    def get_detector(self, name: str) -> Optional[DetectorConfig]:
        """Get detector configuration by name."""
        return self.detectors.get(name)
    
    def get_detectors_for_category(self, category: str) -> List[DetectorConfig]:
        """Get all enabled detectors for a specific category."""
        return [
            detector for detector in self.detectors.values()
            if detector.enabled and category in detector.categories
        ]
    
    def get_detectors_for_categories(self, categories: List[str]) -> List[DetectorConfig]:
        """Get all enabled detectors for multiple categories."""
        detectors = []
        for category in categories:
            detectors.extend(self.get_detectors_for_category(category))
        # Remove duplicates
        seen = set()
        unique_detectors = []
        for detector in detectors:
            if detector.name not in seen:
                seen.add(detector.name)
                unique_detectors.append(detector)
        return unique_detectors
    
    def register_client(self, name: str, client: DetectorClient):
        """Register a detector client implementation."""
        if name not in self.detectors:
            logger.warning(f"Cannot register client for unknown detector: {name}")
            return
        self.clients[name] = client
        logger.info(f"Registered client for detector: {name}")
    
    def is_detector_available(self, name: str) -> bool:
        """Check if detector is enabled and has a registered client."""
        detector = self.detectors.get(name)
        if not detector:
            return False
        if not detector.enabled:
            return False
        
        # Check circuit breaker if available
        if self.circuit_breaker_manager:
            if not self.circuit_breaker_manager.is_available(detector):
                logger.debug(f"Detector {name} circuit breaker is OPEN")
                return False
        
        return name in self.clients
    
    def get_circuit_breaker_manager(self):
        """Get circuit breaker manager instance."""
        return self.circuit_breaker_manager
