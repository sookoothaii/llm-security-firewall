"""
HTTP Client for Detector Microservices - LLM Firewall Battle Plan
=================================================================

Synchronous HTTP client for calling detector microservices.
Uses httpx (sync) to match FirewallEngineV3's synchronous architecture.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
Status: Phase 1 - Foundation
License: MIT
"""

import logging
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False
    logging.warning("httpx not installed. Install with: pip install httpx")

from llm_firewall.detectors.detector_registry import (
    DetectorConfig,
    DetectorResponse,
    ErrorPolicy,
)

logger = logging.getLogger(__name__)


@dataclass
class DetectorError:
    """Error information from detector call."""
    detector_name: str
    error_type: str
    message: str
    fallback_action: str


class DetectorHTTPClient:
    """
    Synchronous HTTP client for detector microservices.
    
    Features:
    - Timeout handling
    - Retry logic (optional)
    - Error policy enforcement (fail-open, fail-closed)
    - Circuit breaker integration (via external manager)
    """
    
    def __init__(
        self,
        timeout: float = 0.05,
        max_retries: int = 0,  # No retries by default (fail-fast)
        enable_retries: bool = False
    ):
        """
        Initialize HTTP client.
        
        Args:
            timeout: Request timeout in seconds (default: 50ms)
            max_retries: Maximum retry attempts (default: 0 = no retries)
            enable_retries: Whether to enable retries (default: False)
        """
        if not HAS_HTTPX:
            raise ImportError("httpx is required for DetectorHTTPClient. Install with: pip install httpx")
        
        self.timeout = timeout
        self.max_retries = max_retries if enable_retries else 0
        self.enable_retries = enable_retries
        self._client: Optional[httpx.Client] = None
        
        logger.info(
            f"DetectorHTTPClient initialized (timeout={timeout}s, retries={self.max_retries})"
        )
    
    def __enter__(self):
        """Context manager entry."""
        self._client = httpx.Client(
            timeout=httpx.Timeout(self.timeout, connect=5.0),
            follow_redirects=True
        )
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._client:
            self._client.close()
            self._client = None
    
    def call_detector(
        self,
        detector_config: DetectorConfig,
        request_data: Dict[str, Any],
        circuit_breaker_available: bool = True
    ) -> DetectorResponse:
        """
        Call detector microservice synchronously.
        
        Args:
            detector_config: Detector configuration
            request_data: Request payload (text, context, etc.)
            circuit_breaker_available: Whether circuit breaker allows call
            
        Returns:
            DetectorResponse with risk scores and verdict
        """
        if not circuit_breaker_available:
            logger.debug(f"Circuit breaker OPEN for {detector_config.name}, using fallback")
            return self._get_fallback_response(detector_config, "Circuit breaker OPEN")
        
        if not self._client:
            # Create temporary client if not in context manager
            self._client = httpx.Client(
                timeout=httpx.Timeout(self.timeout, connect=5.0),
                follow_redirects=True
            )
            should_close = True
        else:
            should_close = False
        
        try:
            start_time = time.time()
            
            # Prepare request (matching DetectorRequest format)
            request_payload = {
                "text": request_data.get("text", ""),
                "context": request_data.get("context", {}),
                "risk_score": request_data.get("risk_score", 0.0),
                "categories": request_data.get("categories", []),
                "tools": request_data.get("tools", [])
            }
            
            # Use /v1/detect endpoint (standardized across all detectors)
            endpoint_url = detector_config.endpoint.rstrip('/')
            if not endpoint_url.endswith('/v1/detect'):
                # Ensure endpoint ends with /v1/detect
                if endpoint_url.endswith('/'):
                    endpoint_url = endpoint_url + "v1/detect"
                else:
                    endpoint_url = endpoint_url + "/v1/detect"
            
            # Call detector with retries
            last_exception = None
            for attempt in range(self.max_retries + 1):
                try:
                    
                    response = self._client.post(
                        endpoint_url,
                        json=request_payload,
                        timeout=self.timeout
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        latency_ms = (time.time() - start_time) * 1000
                        
                        # Parse response (match detector service API format)
                        return DetectorResponse(
                            detector_name=detector_config.name,
                            risk_score=data.get("risk_score", 0.0),
                            category=data.get("category"),
                            confidence=data.get("confidence", 0.0),
                            matched_patterns=data.get("matched_patterns", []),
                            metadata=data.get("metadata", {}),
                            error=data.get("error"),
                            latency_ms=latency_ms
                        )
                    else:
                        error_msg = f"HTTP {response.status_code}: {response.text[:200]}"
                        logger.warning(f"Detector {detector_config.name} returned {response.status_code}: {error_msg}")
                        last_exception = Exception(error_msg)
                        
                except (httpx.TimeoutException, httpx.ConnectError, httpx.RequestError) as e:
                    last_exception = e
                    if attempt < self.max_retries:
                        logger.debug(
                            f"Detector {detector_config.name} attempt {attempt + 1} failed: {e}, retrying..."
                        )
                        time.sleep(0.01 * (attempt + 1))  # Exponential backoff
                    else:
                        logger.warning(f"Detector {detector_config.name} failed after {attempt + 1} attempts: {e}")
            
            # All retries exhausted
            return self._get_fallback_response(detector_config, str(last_exception))
            
        except Exception as e:
            logger.error(f"Unexpected error calling detector {detector_config.name}: {e}", exc_info=True)
            return self._get_fallback_response(detector_config, str(e))
        
        finally:
            if should_close and self._client:
                self._client.close()
                self._client = None
    
    def _get_fallback_response(
        self,
        config: DetectorConfig,
        error: str
    ) -> DetectorResponse:
        """
        Generate fallback response based on error policy.
        
        Args:
            config: Detector configuration
            error: Error message
            
        Returns:
            DetectorResponse with fallback decision
        """
        if config.error_policy == ErrorPolicy.FAIL_CLOSED:
            # Block on error (conservative)
            logger.warning(
                f"Detector {config.name} failed (FAIL_CLOSED policy), blocking request: {error}"
            )
            return DetectorResponse(
                detector_name=config.name,
                risk_score=1.0,
                category=config.categories[0] if config.categories else None,
                confidence=1.0,
                matched_patterns=[],
                metadata={"error": error, "fallback": "fail_closed"},
                error=error,
                latency_ms=0.0
            )
        
        elif config.error_policy == ErrorPolicy.FAIL_CLOSED_ON_HIGH_RISK:
            # Block only if high risk (check context)
            # For now, we'll be conservative and block
            logger.warning(
                f"Detector {config.name} failed (FAIL_CLOSED_ON_HIGH_RISK policy), "
                f"blocking for high-risk categories: {error}"
            )
            return DetectorResponse(
                detector_name=config.name,
                risk_score=0.9,  # High but not absolute
                category=config.categories[0] if config.categories else None,
                confidence=0.8,
                matched_patterns=[],
                metadata={"error": error, "fallback": "fail_closed_on_high_risk"},
                error=error,
                latency_ms=0.0
            )
        
        else:  # FAIL_OPEN
            # Allow on error (permissive)
            logger.debug(
                f"Detector {config.name} failed (FAIL_OPEN policy), allowing request: {error}"
            )
            return DetectorResponse(
                detector_name=config.name,
                risk_score=0.0,
                category=None,
                confidence=0.0,
                matched_patterns=[],
                metadata={"error": error, "fallback": "fail_open"},
                error=error,
                latency_ms=0.0
            )
