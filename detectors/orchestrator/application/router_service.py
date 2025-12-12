"""
Basic Router Service

Implementierung des Router Service für intelligente Detektor-Orchestrierung.
"""
import asyncio
import aiohttp
import time
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List

# Add orchestrator to path for imports
service_dir = Path(__file__).parent.parent
if str(service_dir) not in sys.path:
    sys.path.insert(0, str(service_dir))

from domain.ports import (
    DetectorRouterPort, RoutingDecision, DetectorConfig, DetectorResult, AggregatedResult
)

logger = logging.getLogger(__name__)


class BasicRouterService(DetectorRouterPort):
    """Implementierung des Router Service."""
    
    def __init__(self, policy_engine, detector_endpoints: Dict[str, str]):
        """
        Initialize router service.
        
        Args:
            policy_engine: Policy Engine instance (SimplePolicyEngine)
            detector_endpoints: Dictionary mapping detector names to base URLs
        """
        self.policy_engine = policy_engine
        self.detector_endpoints = detector_endpoints
        logger.info(
            f"BasicRouterService initialized with {len(detector_endpoints)} detector endpoints"
        )
        
    def analyze_and_route(self, text: str, context: Dict[str, Any]) -> RoutingDecision:
        """
        Trifft Routing-Entscheidung basierend auf Kontext.
        
        Args:
            text: Text zu analysieren
            context: Kontext-Dictionary (source_tool, user_risk_tier, etc.)
            
        Returns:
            RoutingDecision mit DetectorConfigs und Execution-Strategy
        """
        # Analysiere Text auf Code-Muster (einfache Heuristik)
        has_code_patterns = self._detect_code_patterns(text)
        enhanced_context = {**context, "has_code_patterns": has_code_patterns}
        
        # Finde passende Policy
        policy = self.policy_engine.evaluate(enhanced_context)
        
        # Konvertiere zu DetectorConfigs
        detector_configs = [
            DetectorConfig(
                name=det["name"],
                mode=det["mode"],
                timeout_ms=det["timeout_ms"],
                priority=1 if det["mode"] == "required" else 2
            )
            for det in policy["detectors"]
        ]
        
        return RoutingDecision(
            detector_configs=detector_configs,
            execution_strategy=policy["strategy"],
            total_timeout_ms=policy["max_latency"],
            decision_reason=f"Policy: {policy['name']}",
            router_metadata={"policy_name": policy.get("name", "unknown")}
        )
    
    async def execute_detectors(
        self, 
        decision: RoutingDecision, 
        text: str, 
        context: Dict[str, Any]
    ) -> AggregatedResult:
        """
        Führt Detektoren parallel/sequentiell aus.
        
        Args:
            decision: RoutingDecision mit DetectorConfigs
            text: Text zu analysieren
            context: Kontext-Dictionary
            
        Returns:
            AggregatedResult mit allen Detektor-Ergebnissen
        """
        start_time = time.time()
        detector_results = {}
        
        if decision.execution_strategy == "parallel":
            detector_results = await self._execute_parallel(decision, text, context)
        else:
            detector_results = await self._execute_sequential(decision, text, context)
        
        total_time = (time.time() - start_time) * 1000
        
        # Aggregiere Ergebnisse (einfache OR-Logik: blockieren wenn einer blockiert)
        final_decision = any(
            result.blocked 
            for result in detector_results.values() 
            if result.success
        )
        
        # Berechne finalen Score (Maximum der erfolgreichen Detektoren)
        successful_scores = [
            result.score 
            for result in detector_results.values() 
            if result.success and result.score is not None
        ]
        final_score = max(successful_scores) if successful_scores else 0.0
        
        # Berechne Confidence (Anzahl erfolgreicher Detektoren / Gesamt)
        successful_count = sum(1 for r in detector_results.values() if r.success)
        total_count = len(detector_results)
        confidence = successful_count / total_count if total_count > 0 else 0.0
        
        logger.info(
            f"Detector execution completed: {successful_count}/{total_count} successful, "
            f"final_score={final_score:.3f}, blocked={final_decision}, "
            f"total_time={total_time:.1f}ms"
        )
        
        return AggregatedResult(
            detector_results=detector_results,
            final_decision=final_decision,
            final_score=final_score,
            confidence=confidence,
            router_metadata={
                "strategy": decision.execution_strategy,
                "reason": decision.decision_reason,
                "detectors_called": list(detector_results.keys()),
                "total_time_ms": total_time
            }
        )
    
    async def _execute_parallel(
        self, 
        decision: RoutingDecision, 
        text: str, 
        context: Dict[str, Any]
    ) -> Dict[str, DetectorResult]:
        """Parallele Ausführung mit Timeouts."""
        tasks = []
        for config in decision.detector_configs:
            task = self._call_detector_with_timeout(config, text, context)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verarbeite Ergebnisse
        detector_results = {}
        for config, result in zip(decision.detector_configs, results):
            if isinstance(result, Exception):
                logger.error(f"Detector {config.name} failed: {result}")
                detector_results[config.name] = DetectorResult(
                    detector_name=config.name,
                    success=False,
                    score=None,
                    blocked=False,
                    metadata={"error": str(result)},
                    processing_time_ms=0.0,
                    error=f"Detector failed: {result}"
                )
            else:
                detector_results[config.name] = result
        
        return detector_results
    
    async def _execute_sequential(
        self, 
        decision: RoutingDecision, 
        text: str, 
        context: Dict[str, Any]
    ) -> Dict[str, DetectorResult]:
        """Sequentielle Ausführung."""
        detector_results = {}
        
        for config in decision.detector_configs:
            result = await self._call_detector_with_timeout(config, text, context)
            detector_results[config.name] = result
            
            # Early exit: Wenn required Detector blockiert, können wir optional Detektoren überspringen
            if result.success and result.blocked and config.mode == "required":
                logger.info(f"Required detector {config.name} blocked, skipping remaining detectors")
                break
        
        return detector_results
    
    async def _call_detector_with_timeout(
        self, 
        config: DetectorConfig, 
        text: str, 
        context: Dict[str, Any]
    ) -> DetectorResult:
        """Ruft einen Detektor mit Timeout auf."""
        start_time = time.time()
        endpoint = self.detector_endpoints.get(config.name)
        
        if not endpoint:
            return DetectorResult(
                detector_name=config.name,
                success=False,
                score=None,
                blocked=False,
                metadata={"error": "endpoint_not_configured"},
                processing_time_ms=0.0,
                error=f"Detector endpoint not configured for {config.name}"
            )
        
        try:
            # Code Intent Service verwendet /api/v1/detect, andere /v1/detect
            detect_path = "/api/v1/detect" if config.name == "code_intent" else "/v1/detect"
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{endpoint}{detect_path}",
                    json={"text": text, "context": context},
                    timeout=aiohttp.ClientTimeout(total=config.timeout_ms / 1000.0)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        processing_time = (time.time() - start_time) * 1000
                        
                        # Extrahiere Daten aus Response (konsistent mit Shared Models)
                        # Response kann sein: {"success": true, "data": {...}} oder direkt {...}
                        if isinstance(data, dict) and "data" in data and data.get("success"):
                            result_data = data.get("data", {})
                        else:
                            result_data = data
                        
                        # Unterstütze verschiedene Feldnamen (blocked, is_blocked)
                        blocked = result_data.get("blocked") or result_data.get("is_blocked", False)
                        risk_score = result_data.get("risk_score", 0.0)
                        metadata = result_data.get("metadata", {})
                        
                        # Wenn metadata leer ist, aber andere Felder vorhanden sind, nutze diese
                        if not metadata and isinstance(result_data, dict):
                            metadata = {k: v for k, v in result_data.items() 
                                      if k not in ["blocked", "is_blocked", "risk_score", "success", "data", "error"]}
                        
                        return DetectorResult(
                            detector_name=config.name,
                            success=True,
                            score=risk_score,
                            blocked=blocked,
                            metadata=metadata,
                            processing_time_ms=processing_time
                        )
                    else:
                        error_text = await response.text()
                        return DetectorResult(
                            detector_name=config.name,
                            success=False,
                            score=None,
                            blocked=False,
                            metadata={"error": f"http_{response.status}"},
                            processing_time_ms=(time.time() - start_time) * 1000,
                            error=f"HTTP {response.status}: {error_text[:100]}"
                        )
                    
        except asyncio.TimeoutError:
            logger.warning(f"Detector {config.name} timed out after {config.timeout_ms}ms")
            return DetectorResult(
                detector_name=config.name,
                success=False,
                score=None,
                blocked=False,
                metadata={"error": "timeout"},
                processing_time_ms=config.timeout_ms,
                error=f"Timeout after {config.timeout_ms}ms"
            )
        except Exception as e:
            logger.error(f"Detector {config.name} request failed: {e}")
            return DetectorResult(
                detector_name=config.name,
                success=False,
                score=None,
                blocked=False,
                metadata={"error": str(e)},
                processing_time_ms=(time.time() - start_time) * 1000,
                error=f"Request failed: {e}"
            )
    
    def _detect_code_patterns(self, text: str) -> bool:
        """Einfache Heuristik für Code-ähnliche Muster."""
        code_indicators = [
            'def ', 'class ', 'import ', 'from ', 
            'if __name__', 'try:', 'except ',
            'for ', 'while ', 'print(', 'return ',
            '&&', '||', ';', '{', '}',
            'function ', 'var ', 'const ', 'let ',
            'SELECT ', 'INSERT ', 'DELETE ', 'UPDATE ',
            '#!/bin/', '#!/usr/bin/'
        ]
        text_lower = text.lower()
        return any(indicator.lower() in text_lower for indicator in code_indicators)

