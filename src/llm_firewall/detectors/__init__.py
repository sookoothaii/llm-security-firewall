"""Detector modules for LLM Firewall."""

from llm_firewall.detectors.bidi_locale import (
    bidi_controls_present,
    detect_bidi_locale,
    locale_label_hits,
)
from llm_firewall.detectors.encoding_base85 import detect_base85
from llm_firewall.detectors.transport_indicators import scan_transport_indicators

# Battle Plan Phase 1 - Detector Microservices
from llm_firewall.detectors.detector_registry import (
    DetectorRegistry,
    DetectorConfig,
    DetectorResponse,
    ErrorPolicy,
)
from llm_firewall.detectors.detector_orchestrator import (
    DetectorOrchestrator,
    InvocationContext,
    InvocationResult,
)
from llm_firewall.detectors.http_client import DetectorHTTPClient
from llm_firewall.detectors.circuit_breaker_manager import (
    CircuitBreakerManager,
    CircuitState,
    DetectorCircuitState,
)

__all__ = [
    # Legacy detectors
    "detect_base85",
    "bidi_controls_present",
    "detect_bidi_locale",
    "locale_label_hits",
    "scan_transport_indicators",
    # Battle Plan Phase 1 - Detector Microservices
    "DetectorRegistry",
    "DetectorConfig",
    "DetectorResponse",
    "ErrorPolicy",
    "DetectorOrchestrator",
    "InvocationContext",
    "InvocationResult",
    "DetectorHTTPClient",
    "CircuitBreakerManager",
    "CircuitState",
    "DetectorCircuitState",
]
