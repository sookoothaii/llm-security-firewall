"""
Detector Orchestrator - LLM Firewall Battle Plan
================================================

Orchestrates calls to specialized detector microservices (Outer Ring).
Implements gating logic, parallel invocation, timeouts, and circuit breakers.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-07
Status: Phase 1 - Foundation
License: MIT
"""

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
import concurrent.futures
from threading import Thread

from llm_firewall.detectors.detector_registry import (
    DetectorRegistry,
    DetectorConfig,
    DetectorResponse,
    ErrorPolicy,
)
from llm_firewall.detectors.circuit_breaker_manager import CircuitBreakerManager
from llm_firewall.detectors.http_client import DetectorHTTPClient

logger = logging.getLogger(__name__)


@dataclass
class InvocationContext:
    """Context for detector invocation."""
    text: str
    risk_score: float
    detected_categories: List[str]
    detected_tools: List[str]
    metadata: Dict[str, Any]


@dataclass
class InvocationResult:
    """Result from detector orchestration."""
    responses: List[DetectorResponse]
    total_latency_ms: float
    errors: List[str]
    cache_hits: int = 0


class DetectorOrchestrator:
    """
    Orchestrates calls to detector microservices.
    
    Implements:
    - Gating logic (only call when inner ring flags risk)
    - Parallel invocation (up to max_parallel_detectors)
    - Timeouts and circuit breakers
    - Caching (optional)
    - Error handling policies
    """
    
    def __init__(
        self,
        registry: DetectorRegistry,
        policy_path: Optional[Path] = None,
        enable_cache: bool = True,
        max_parallel: int = 2
    ):
        """
        Initialize detector orchestrator.
        
        Args:
            registry: DetectorRegistry instance
            policy_path: Path to policy.yml (default: config/policy.yml)
            enable_cache: Enable response caching
            max_parallel: Maximum parallel detector calls
        """
        self.registry = registry
        self.enable_cache = enable_cache
        self.max_parallel = max_parallel
        self.cache: Dict[str, DetectorResponse] = {}  # Simple in-memory cache
        
        # Initialize circuit breaker manager
        self.circuit_manager = CircuitBreakerManager()
        
        # Initialize HTTP client (will be created per-call or via context manager)
        self.http_client: Optional[DetectorHTTPClient] = None
        
        if policy_path is None:
            base_dir = Path(__file__).parent.parent.parent.parent
            policy_path = base_dir / "config" / "policy.yml"
        
        self.policy_path = policy_path
        self.policy = self._load_policy()
        
        logger.info(
            f"DetectorOrchestrator initialized "
            f"(cache={enable_cache}, max_parallel={max_parallel})"
        )
    
    def _load_policy(self) -> Dict[str, Any]:
        """Load policy configuration from YAML file."""
        if not self.policy_path.exists():
            logger.warning(f"Policy config not found: {self.policy_path}. Using defaults.")
            return {}
        
        try:
            with open(self.policy_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load policy config: {e}")
            return {}
    
    def should_invoke_detectors(self, context: InvocationContext) -> bool:
        """
        Determine if detectors should be invoked (gating logic).
        
        CRITICAL FIX: Content-Safety should always run (for jailbreak detection).
        Code-Intent can be gated by risk score.
        
        Args:
            context: Invocation context
            
        Returns:
            True if detectors should be called
        """
        # CRITICAL FIX: Always invoke Content-Safety (jailbreak detection is critical)
        # Check if content_safety detector is enabled
        content_safety_detector = self.registry.get_detector("content_safety")
        if content_safety_detector and content_safety_detector.enabled:
            # Content-Safety should always run (no gating)
            return True
        
        # For other detectors, use risk-based gating
        # Check minimum risk threshold
        min_risk = self.policy.get('outer_ring', {}).get('gating_conditions', {}).get('min_risk_score', 0.4)
        if context.risk_score < min_risk:
            return False
        
        # Check if any detectors are available for detected categories
        available_detectors = self.registry.get_detectors_for_categories(context.detected_categories)
        if not available_detectors:
            return False
        
        return True
    
    def get_detectors_to_invoke(self, context: InvocationContext) -> List[DetectorConfig]:
        """
        Get list of detectors to invoke based on context.
        
        CRITICAL FIX: Always include Content-Safety for jailbreak detection.
        
        Args:
            context: Invocation context
            
        Returns:
            List of detector configs to invoke
        """
        detectors = []
        
        # CRITICAL FIX: Always include Content-Safety (jailbreak detection)
        content_safety_detector = self.registry.get_detector("content_safety")
        if content_safety_detector and content_safety_detector.enabled:
            detectors.append(content_safety_detector)
        
        # Get detectors for detected categories
        category_detectors = self.registry.get_detectors_for_categories(context.detected_categories)
        for detector in category_detectors:
            if detector not in detectors:
                detectors.append(detector)
        
        # Check tool risk profiles
        tool_profiles = self.policy.get('tool_risk_profiles', {})
        for tool in context.detected_tools:
            if tool in tool_profiles:
                required_detectors = tool_profiles[tool].get('require_detectors', [])
                for detector_name in required_detectors:
                    detector = self.registry.get_detector(detector_name)
                    if detector and detector.enabled and detector not in detectors:
                        detectors.append(detector)
        
        # CRITICAL FIX: Always include Code-Intent if enabled (for security)
        code_intent_detector = self.registry.get_detector("code_intent")
        if code_intent_detector and code_intent_detector.enabled and code_intent_detector not in detectors:
            detectors.append(code_intent_detector)
        
        # Limit to max_parallel (but ensure Content-Safety and Code-Intent are included)
        # Priority: Content-Safety, Code-Intent, then others
        priority_detectors = []
        other_detectors = []
        
        for detector in detectors:
            if detector.name in ["content_safety", "code_intent"]:
                priority_detectors.append(detector)
            else:
                other_detectors.append(detector)
        
        # Combine: priority first, then others up to max_parallel
        result = priority_detectors[:]
        remaining_slots = self.max_parallel - len(result)
        result.extend(other_detectors[:remaining_slots])
        
        return result
    
    def invoke_detectors(
        self,
        context: InvocationContext,
        sync: bool = True
    ) -> InvocationResult:
        """
        Invoke detectors based on context.
        
        Args:
            context: Invocation context
            sync: Whether to wait for responses (True) or run async (False)
            
        Returns:
            InvocationResult with responses and metadata
        """
        start_time = time.time()
        responses: List[DetectorResponse] = []
        errors: List[str] = []
        cache_hits = 0
        
        # Check gating logic
        if not self.should_invoke_detectors(context):
            logger.debug("Detector gating: skipping invocation (risk too low or no detectors)")
            return InvocationResult(
                responses=[],
                total_latency_ms=0.0,
                errors=[],
                cache_hits=0
            )
        
        # Get detectors to invoke
        detectors = self.get_detectors_to_invoke(context)
        if not detectors:
            logger.debug("No detectors to invoke")
            return InvocationResult(
                responses=[],
                total_latency_ms=0.0,
                errors=[],
                cache_hits=0
            )
        
        logger.info(f"Invoking {len(detectors)} detector(s) for categories: {context.detected_categories}")
        
        # Create HTTP client if not exists
        if not self.http_client:
            self.http_client = DetectorHTTPClient(timeout=0.05, max_retries=0)
        
        # Check if parallel execution is enabled and we have multiple detectors
        use_parallel = len(detectors) > 1 and self.max_parallel > 1
        
        if use_parallel:
            # PARALLEL EXECUTION: Invoke detectors concurrently
            responses = self._invoke_detectors_parallel(detectors, context, errors)
        else:
            # SEQUENTIAL EXECUTION: Invoke detectors one by one
            responses = self._invoke_detectors_sequential(detectors, context, errors, cache_hits)
        
        # Calculate total latency
        total_latency_ms = (time.time() - start_time) * 1000
        
        return InvocationResult(
            responses=responses,
            total_latency_ms=total_latency_ms,
            errors=errors,
            cache_hits=cache_hits
        )
    
    def _invoke_detectors_parallel(
        self,
        detectors: List[DetectorConfig],
        context: InvocationContext,
        errors: List[str]
    ) -> List[DetectorResponse]:
        """Invoke detectors in parallel using ThreadPoolExecutor."""
        responses: List[DetectorResponse] = []
        
        def invoke_single_detector(detector: DetectorConfig) -> Optional[DetectorResponse]:
            """Invoke a single detector (for parallel execution)."""
            try:
                # Check cache
                cache_key = self._get_cache_key(detector.name, context.text)
                if self.enable_cache and cache_key in self.cache:
                    cached_response = self.cache[cache_key]
                    logger.debug(f"Cache hit for detector: {detector.name}")
                    return cached_response
                
                # Check circuit breaker
                circuit_available = self.circuit_manager.is_available(detector)
                
                # Create HTTP client for this thread
                with DetectorHTTPClient(timeout=detector.timeout_ms / 1000.0, max_retries=0) as client:
                    # Invoke detector using HTTP client
                    request_data = {
                        "text": context.text,
                        "context": {
                            "risk_score": context.risk_score,
                            "categories": context.detected_categories,
                            "tools": context.detected_tools,
                            **context.metadata
                        }
                    }
                    response = client.call_detector(detector, request_data, circuit_available)
                    
                    if response:
                        # Record success/failure in circuit breaker
                        if response.error:
                            self.circuit_manager.record_failure(detector, response.error)
                        else:
                            self.circuit_manager.record_success(detector)
                        
                        # Cache response (only if successful)
                        if self.enable_cache and not response.error:
                            self.cache[cache_key] = response
                    
                    return response
            except Exception as e:
                error_msg = f"Detector {detector.name} failed: {e}"
                logger.error(error_msg, exc_info=True)
                errors.append(error_msg)
                
                # Record failure in circuit breaker
                self.circuit_manager.record_failure(detector, str(e))
                
                # Handle error based on policy
                if detector.error_policy == ErrorPolicy.FAIL_CLOSED:
                    return DetectorResponse(
                        detector_name=detector.name,
                        risk_score=1.0,
                        error=str(e)
                    )
                elif detector.error_policy == ErrorPolicy.FAIL_CLOSED_ON_HIGH_RISK:
                    if context.risk_score > 0.7:
                        return DetectorResponse(
                            detector_name=detector.name,
                            risk_score=1.0,
                            error=str(e)
                        )
                # FAIL_OPEN: return None (no blocking response)
                return None
        
        # Execute detectors in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(detectors), self.max_parallel)) as executor:
            future_to_detector = {
                executor.submit(invoke_single_detector, detector): detector
                for detector in detectors
            }
            
            for future in concurrent.futures.as_completed(future_to_detector):
                detector = future_to_detector[future]
                try:
                    response = future.result()
                    if response:
                        responses.append(response)
                except Exception as e:
                    logger.error(f"Detector {detector.name} execution failed: {e}", exc_info=True)
                    errors.append(f"Detector {detector.name} execution failed: {e}")
        
        return responses
    
    def _invoke_detectors_sequential(
        self,
        detectors: List[DetectorConfig],
        context: InvocationContext,
        errors: List[str],
        cache_hits: int
    ) -> List[DetectorResponse]:
        """Invoke detectors sequentially (original implementation)."""
        responses: List[DetectorResponse] = []
        
        for detector in detectors:
            try:
                # Check cache
                cache_key = self._get_cache_key(detector.name, context.text)
                if self.enable_cache and cache_key in self.cache:
                    cached_response = self.cache[cache_key]
                    responses.append(cached_response)
                    cache_hits += 1
                    logger.debug(f"Cache hit for detector: {detector.name}")
                    continue
                
                # Check circuit breaker
                circuit_available = self.circuit_manager.is_available(detector)
                
                # Invoke detector
                response = self._invoke_detector(detector, context, circuit_available)
                if response:
                    responses.append(response)
                    
                    # Record success/failure in circuit breaker
                    if response.error:
                        self.circuit_manager.record_failure(detector, response.error)
                    else:
                        self.circuit_manager.record_success(detector)
                    
                    # Cache response (only if successful)
                    if self.enable_cache and not response.error:
                        self.cache[cache_key] = response
            except Exception as e:
                error_msg = f"Detector {detector.name} failed: {e}"
                logger.error(error_msg, exc_info=True)
                errors.append(error_msg)
                
                # Record failure in circuit breaker
                self.circuit_manager.record_failure(detector, str(e))
                
                # Handle error based on policy
                if detector.error_policy == ErrorPolicy.FAIL_CLOSED:
                    # Create blocking response
                    blocking_response = DetectorResponse(
                        detector_name=detector.name,
                        risk_score=1.0,
                        error=str(e)
                    )
                    responses.append(blocking_response)
                elif detector.error_policy == ErrorPolicy.FAIL_CLOSED_ON_HIGH_RISK:
                    if context.risk_score > 0.7:
                        blocking_response = DetectorResponse(
                            detector_name=detector.name,
                            risk_score=1.0,
                            error=str(e)
                        )
                        responses.append(blocking_response)
                # FAIL_OPEN: Do nothing, continue
        
        total_latency = (time.time() - start_time) * 1000  # Convert to ms
        
        return InvocationResult(
            responses=responses,
            total_latency_ms=total_latency,
            errors=errors,
            cache_hits=cache_hits
        )
    
    def _invoke_detector(
        self,
        detector: DetectorConfig,
        context: InvocationContext,
        circuit_available: bool = True
    ) -> Optional[DetectorResponse]:
        """
        Invoke a single detector.
        
        Args:
            detector: Detector configuration
            context: Invocation context
            circuit_available: Whether circuit breaker allows call
            
        Returns:
            DetectorResponse or None on error
        """
        if not self.registry.is_detector_available(detector.name):
            logger.warning(f"Detector {detector.name} is not available")
            return None
        
        # Check if we have a registered client (for future extensibility)
        # For now, use HTTP client directly
        if not self.http_client:
            logger.warning(f"No HTTP client available for detector: {detector.name}")
            return None
        
        start_time = time.time()
        
        try:
            # Prepare request data
            request_data = {
                'text': context.text,
                'context': context.metadata,
                'risk_score': context.risk_score,
                'categories': context.detected_categories,
                'tools': context.detected_tools
            }
            
            # Call detector via HTTP client
            response = self.http_client.call_detector(
                detector_config=detector,
                request_data=request_data,
                circuit_breaker_available=circuit_available
            )
            
            # Check timeout
            if response.latency_ms > detector.timeout_ms:
                logger.warning(
                    f"Detector {detector.name} exceeded timeout "
                    f"({response.latency_ms:.1f}ms > {detector.timeout_ms}ms)"
                )
            
            return response
            
        except Exception as e:
            logger.error(f"Detector {detector.name} invocation failed: {e}", exc_info=True)
            return DetectorResponse(
                detector_name=detector.name,
                risk_score=0.0,
                error=str(e),
                latency_ms=(time.time() - start_time) * 1000
            )
    
    def _get_cache_key(self, detector_name: str, text: str) -> str:
        """Generate cache key for detector response."""
        # Simple hash-based key (can be improved)
        import hashlib
        text_hash = hashlib.md5(text.encode()).hexdigest()
        return f"{detector_name}:{text_hash}"
    
    def aggregate_responses(self, responses: List[DetectorResponse]) -> Dict[str, Any]:
        """
        Aggregate detector responses into final risk score.
        
        Args:
            responses: List of detector responses
            
        Returns:
            Aggregated risk score and metadata
        """
        if not responses:
            return {
                'risk_score': 0.0,
                'detector_count': 0,
                'max_risk': 0.0,
                'categories': []
            }
        
        # Use maximum risk score from all detectors
        max_risk = max(r.risk_score for r in responses if r.error is None)
        
        # Collect categories
        categories = [r.category for r in responses if r.category]
        
        return {
            'risk_score': max_risk,
            'detector_count': len(responses),
            'max_risk': max_risk,
            'categories': list(set(categories)),
            'responses': [
                {
                    'detector': r.detector_name,
                    'risk': r.risk_score,
                    'category': r.category,
                    'latency_ms': r.latency_ms
                }
                for r in responses
            ]
        }
