"""
Intelligent Router Service

Intelligenter Router Service mit erweiterter Kontextanalyse und dynamischen Policies.
"""
import asyncio
import aiohttp
import time
import logging
import sys
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Add orchestrator to path for imports
service_dir = Path(__file__).parent.parent
if str(service_dir) not in sys.path:
    sys.path.insert(0, str(service_dir))

from domain.ports import (
    DetectorRouterPort, RoutingDecision, DetectorConfig, DetectorResult, AggregatedResult
)
from domain.context.context_analyzer import AdvancedContextAnalyzer, TextAnalysisResult
from domain.security.pattern_detector import SecurityPatternDetector
from domain.adversarial.adversarial_detector import AdversarialInputDetector
from infrastructure.dynamic_policy_engine import DynamicPolicyEngine

logger = logging.getLogger(__name__)


class IntelligentRouterService(DetectorRouterPort):
    """Intelligenter Router Service mit erweiterter Kontextanalyse und dynamischen Policies."""
    
    def __init__(
        self, 
        policy_engine: DynamicPolicyEngine,
        detector_endpoints: Dict[str, str],
        enable_adaptive_learning: bool = False
    ):
        """
        Initialize intelligent router service.
        
        Args:
            policy_engine: DynamicPolicyEngine instance
            detector_endpoints: Dictionary mapping detector names to base URLs
            enable_adaptive_learning: If True, enable adaptive learning (Phase 5.3)
        """
        self.policy_engine = policy_engine
        self.detector_endpoints = detector_endpoints
        self.context_analyzer = AdvancedContextAnalyzer()
        self.security_pattern_detector = SecurityPatternDetector()
        self.adversarial_detector = AdversarialInputDetector()
        self.enable_adaptive_learning = enable_adaptive_learning
        
        # Adaptive Learning State
        self.learning_data = {
            'decisions': [],
            'outcomes': [],
            'false_positives': [],
            'false_negatives': []
        }
        
        # Performance Tracking
        self.performance_metrics = {
            'total_requests': 0,
            'avg_processing_time': 0.0,
            'policy_distribution': {},
            'error_rate': 0.0
        }
        
        logger.info(
            f"IntelligentRouterService initialized "
            f"(adaptive_learning={enable_adaptive_learning})"
        )
    
    def analyze_and_route(self, text: str, context: Dict[str, Any]) -> RoutingDecision:
        """Intelligente Routing-Entscheidung mit erweiterter Kontextanalyse."""
        start_time = time.time()
        self.performance_metrics['total_requests'] += 1
        
        try:
            # Debug-Mode prüfen
            debug_mode = context.get("debug", False) or context.get("_debug", False)
            
            # 0. Security Pattern Pre-Filter (schnelle Erkennung klassischer Angriffe)
            is_malicious, pattern_risk_score, matched_patterns, pattern_metadata = \
                self.security_pattern_detector.detect(text)
            
            if debug_mode:
                logger.debug(
                    f"[DEBUG] SecurityPatternDetector (Layer 0): "
                    f"detected={is_malicious}, risk_score={pattern_risk_score:.3f}, "
                    f"patterns={matched_patterns}"
                )
            
            if is_malicious:
                logger.warning(
                    f"Security pattern detected: {matched_patterns} "
                    f"(risk_score={pattern_risk_score:.2f})"
                )
                # Erstelle sofort eine Blocking-Entscheidung
                return RoutingDecision(
                    decision_reason=f"Security pattern detected: {', '.join(matched_patterns[:3])}",
                    detector_configs=[
                        DetectorConfig(
                            name="security_pattern",
                            mode="required",
                            timeout_ms=0,
                            priority=0
                        )
                    ],
                    execution_strategy="immediate_block",
                    total_timeout_ms=0,
                    router_metadata={
                        "pattern_detection": True,
                        "pattern_risk_score": pattern_risk_score,
                        "matched_patterns": matched_patterns,
                        **pattern_metadata
                    }
                )
            
            # 0.5. Adversarial Input Detection (NEW - Phase 2)
            is_adversarial, adversarial_score, adversarial_metadata = \
                self.adversarial_detector.detect(text)
            
            # Debug-Logging für Adversarial Detection
            debug_mode = context.get("debug", False) or context.get("_debug", False)
            if debug_mode:
                logger.debug(
                    f"[DEBUG] AdversarialInputDetector: "
                    f"detected={is_adversarial}, score={adversarial_score:.3f}, "
                    f"patterns={adversarial_metadata.get('matched_patterns', [])}, "
                    f"threshold_0.5_flag={adversarial_score >= 0.5}, "
                    f"threshold_0.7_block={adversarial_score >= 0.7}"
                )
            
            if is_adversarial:
                logger.warning(
                    f"Adversarial input detected: score={adversarial_score:.2f}, "
                    f"patterns={adversarial_metadata.get('matched_patterns', [])[:3]}, "
                    f"processing_time={adversarial_metadata.get('processing_time_ms', 0):.2f}ms"
                )
                # Block or flag for additional scrutiny
                if adversarial_score >= 0.7:
                    return RoutingDecision(
                        decision_reason=f"Adversarial input detected: {adversarial_score:.2f}",
                        detector_configs=[
                            DetectorConfig(
                                name="adversarial_detector",
                                mode="required",
                                timeout_ms=0,
                                priority=0
                            )
                        ],
                        execution_strategy="immediate_block",
                        total_timeout_ms=0,
                        router_metadata={
                            "adversarial_detection": True,
                            "adversarial_score": adversarial_score,
                            **adversarial_metadata
                        }
                    )
            
            # 1. Umfassende Kontextanalyse
            enhanced_context = self.context_analyzer.analyze_context(text, context)
            
            # Füge Text zum Context hinzu (für Policy-Pattern-Matching benötigt)
            enhanced_context["text"] = text
            
            # Füge Pattern-Detection-Info zum Context hinzu (auch wenn nicht blockiert)
            if matched_patterns:
                enhanced_context["security_patterns"] = {
                    "detected": True,
                    "risk_score": pattern_risk_score,
                    "patterns": matched_patterns
                }
            
            # Füge Adversarial-Analysis-Info zum Context hinzu
            enhanced_context["adversarial_analysis"] = {
                "detected": is_adversarial,
                "score": adversarial_score,
                "metadata": adversarial_metadata
            }
            
            # 2. Policy-basierte Detektor-Auswahl
            detector_configs_raw = self.policy_engine.get_matching_detectors(
                enhanced_context, 
                debug=debug_mode
            )
            
            if debug_mode:
                logger.debug(
                    f"[DEBUG] Policy Engine: Selected {len(detector_configs_raw)} detectors: "
                    f"{[d.get('name') for d in detector_configs_raw]}"
                )
                logger.debug(
                    f"[DEBUG] Enhanced Context Keys: {list(enhanced_context.keys())}"
                )
                logger.debug(
                    f"[DEBUG] Adversarial Analysis in Context: "
                    f"{enhanced_context.get('adversarial_analysis', {})}"
                )
                logger.debug(
                    f"[DEBUG] Security Patterns in Context: "
                    f"{enhanced_context.get('security_patterns', {})}"
                )
            
            # 3. Konvertiere zu DetectorConfigs
            detector_configs = []
            for det_config in detector_configs_raw:
                config = DetectorConfig(
                    name=det_config["name"],
                    mode=det_config["mode"],
                    timeout_ms=det_config["timeout_ms"],
                    priority=det_config.get("priority", 1)
                )
                detector_configs.append(config)
            
            # 4. Wähle Ausführungsstrategie basierend auf Kontext
            execution_strategy = self._select_execution_strategy(
                detector_configs, 
                enhanced_context
            )
            
            # 5. Berechne Gesamt-Timeout
            total_timeout = self._calculate_total_timeout(detector_configs, execution_strategy)
            
            decision = RoutingDecision(
                detector_configs=detector_configs,
                execution_strategy=execution_strategy,
                total_timeout_ms=total_timeout,
                decision_reason=self._generate_decision_reason(enhanced_context, detector_configs),
                router_metadata={
                    "context_risk_score": enhanced_context.get("context_risk_score", 0.0),
                    "security_patterns": enhanced_context.get("security_patterns", {}),
                    "policy_matched": enhanced_context.get("matched_policy", "unknown")
                }
            )
            
            # 6. Tracke Entscheidung für Learning
            if self.enable_adaptive_learning:
                self._track_decision(decision, enhanced_context)
            
            processing_time = (time.time() - start_time) * 1000
            logger.info(f"Routing decision made in {processing_time:.2f}ms: {decision.decision_reason}")
            
            return decision
            
        except Exception as e:
            logger.error(f"Error in routing decision: {e}", exc_info=True)
            # Fallback auf sichere Default-Entscheidung
            return self._create_fallback_decision()
    
    async def execute_detectors(
        self, 
        decision: RoutingDecision, 
        text: str, 
        context: Dict[str, Any]
    ) -> AggregatedResult:
        """Führt Detektoren mit intelligentem Timeout- und Fehler-Management aus."""
        start_time = time.time()
        
        try:
            # Immediate Block: Pattern-Detection oder Adversarial-Detection hat bereits blockiert
            if decision.execution_strategy == "immediate_block":
                # Check if it's security pattern or adversarial detection
                if decision.router_metadata.get("pattern_detection"):
                    # Security Pattern Detection
                    pattern_risk_score = decision.router_metadata.get("pattern_risk_score", 0.9)
                    matched_patterns = decision.router_metadata.get("matched_patterns", [])
                    pattern_metadata = {
                        k: v for k, v in decision.router_metadata.items() 
                        if k not in ["pattern_detection", "pattern_risk_score", "matched_patterns", "adversarial_detection", "adversarial_score"]
                    }
                    
                    detector_results = {
                        "security_pattern": DetectorResult(
                            detector_name="security_pattern",
                            success=True,
                            score=pattern_risk_score,
                            blocked=True,
                            metadata={
                                "pattern_detection": True,
                                "matched_patterns": matched_patterns,
                                **pattern_metadata
                            },
                            processing_time_ms=(time.time() - start_time) * 1000
                        )
                    }
                    final_score = pattern_risk_score
                    reason_type = "pattern_detection"
                    
                elif decision.router_metadata.get("adversarial_detection"):
                    # Adversarial Detection
                    adversarial_score = decision.router_metadata.get("adversarial_score", 0.9)
                    adversarial_metadata = {
                        k: v for k, v in decision.router_metadata.items() 
                        if k not in ["adversarial_detection", "adversarial_score", "pattern_detection", "pattern_risk_score", "matched_patterns"]
                    }
                    
                    detector_results = {
                        "adversarial_detector": DetectorResult(
                            detector_name="adversarial_detector",
                            success=True,
                            score=adversarial_score,
                            blocked=True,
                            metadata={
                                "adversarial_detection": True,
                                **adversarial_metadata
                            },
                            processing_time_ms=(time.time() - start_time) * 1000
                        )
                    }
                    final_score = adversarial_score
                    reason_type = "adversarial_detection"
                else:
                    # Fallback (should not happen)
                    logger.warning("Immediate block without pattern or adversarial detection metadata")
                    final_score = 0.9
                    reason_type = "unknown"
                    detector_results = {
                        "immediate_block": DetectorResult(
                            detector_name="immediate_block",
                            success=True,
                            score=final_score,
                            blocked=True,
                            metadata={"reason": "immediate_block"},
                            processing_time_ms=(time.time() - start_time) * 1000
                        )
                    }
                
                processing_time = (time.time() - start_time) * 1000
                return AggregatedResult(
                    detector_results=detector_results,
                    final_decision=True,
                    final_score=final_score,
                    confidence=1.0,
                    router_metadata={
                        "strategy": "immediate_block",
                        "reason": decision.decision_reason,
                        "reason_type": reason_type,
                        **decision.router_metadata,
                        "processing_time_ms": processing_time,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                )
            
            detector_results = {}
            
            if decision.execution_strategy == "parallel":
                detector_results = await self._execute_parallel_optimized(decision, text, context)
            else:
                detector_results = await self._execute_sequential_with_fallback(decision, text, context)
            
            # Aggregiere Ergebnisse mit Confidence-Weighting
            final_decision, final_score, confidence = self._aggregate_results_intelligently(detector_results)
            
            # Adaptive Learning: Bewerte Entscheidung
            if self.enable_adaptive_learning:
                await self._evaluate_and_learn(detector_results, final_decision, context)
            
            processing_time = (time.time() - start_time) * 1000
            
            return AggregatedResult(
                detector_results=detector_results,
                final_decision=final_decision,
                final_score=final_score,
                confidence=confidence,
                router_metadata={
                    "strategy": decision.execution_strategy,
                    "reason": decision.decision_reason,
                    "detectors_called": list(detector_results.keys()),
                    "processing_time_ms": processing_time,
                    "successful_detectors": sum(1 for r in detector_results.values() if r.success),
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
        except Exception as e:
            logger.error(f"Error executing detectors: {e}", exc_info=True)
            return self._create_error_result(str(e))
    
    async def _execute_parallel_optimized(
        self, 
        decision: RoutingDecision, 
        text: str, 
        context: Dict[str, Any]
    ) -> Dict[str, DetectorResult]:
        """Optimierte parallele Ausführung mit Prioritäts-basiertem Scheduling."""
        # Gruppiere Detektoren nach Priorität
        high_priority = [c for c in decision.detector_configs if c.priority == 1]
        medium_priority = [c for c in decision.detector_configs if c.priority == 2]
        low_priority = [c for c in decision.detector_configs if c.priority >= 3]
        
        results = {}
        
        # Führe zuerst High-Priority parallel aus
        if high_priority:
            high_results = await self._execute_detector_group(high_priority, text, context)
            results.update(high_results)
        
        # Wenn noch Zeit, führe Medium-Priority aus
        # Für Phase 5.2: Führe Medium-Priority immer aus (später kann Zeit-Tracking hinzugefügt werden)
        time_remaining = decision.total_timeout_ms  # Simplified for Phase 5.2
        if medium_priority and time_remaining > 50:  # Mindestens 50ms übrig
            # Passe Timeouts für Medium-Priority an
            adjusted_configs = [
                DetectorConfig(
                    name=c.name,
                    mode=c.mode,
                    timeout_ms=min(c.timeout_ms, int(time_remaining * 0.7)),
                    priority=c.priority
                )
                for c in medium_priority
            ]
            medium_results = await self._execute_detector_group(adjusted_configs, text, context)
            results.update(medium_results)
        
        return results
    
    async def _execute_sequential_with_fallback(
        self, 
        decision: RoutingDecision, 
        text: str, 
        context: Dict[str, Any]
    ) -> Dict[str, DetectorResult]:
        """Sequentielle Ausführung mit Fallback-Logik."""
        detector_results = {}
        
        for config in decision.detector_configs:
            result = await self._call_detector_with_circuit_breaker(config, text, context)
            detector_results[config.name] = result
            
            # Early exit: Wenn required Detector blockiert, können wir optional Detektoren überspringen
            if result.success and result.blocked and config.mode == "required":
                logger.info(f"Required detector {config.name} blocked, skipping remaining detectors")
                break
        
        return detector_results
    
    async def _execute_detector_group(
        self, 
        configs: List[DetectorConfig], 
        text: str, 
        context: Dict[str, Any]
    ) -> Dict[str, DetectorResult]:
        """Führt eine Gruppe von Detektoren parallel aus."""
        tasks = []
        for config in configs:
            task = self._call_detector_with_circuit_breaker(config, text, context)
            tasks.append(task)
        
        group_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        results = {}
        for config, result in zip(configs, group_results):
            if isinstance(result, Exception):
                results[config.name] = DetectorResult(
                    detector_name=config.name,
                    success=False,
                    score=None,
                    blocked=False,
                    metadata={"error": str(result), "config": config.mode},
                    processing_time_ms=0.0,
                    error=f"Detector failed: {result}"
                )
            else:
                results[config.name] = result
        
        return results
    
    async def _call_detector_with_circuit_breaker(
        self, 
        config: DetectorConfig, 
        text: str, 
        context: Dict[str, Any]
    ) -> DetectorResult:
        """Ruft Detektor mit Circuit Breaker Pattern auf."""
        # Einfache Retry-Logik (vollständiger Circuit Breaker in Phase 5.3)
        max_retries = 2 if config.mode == "required" else 1
        
        for attempt in range(max_retries):
            try:
                return await self._call_detector_single(config, text, context)
            except Exception as e:
                if attempt == max_retries - 1:
                    raise e
                # Kurze Pause vor Retry
                await asyncio.sleep(0.1 * (attempt + 1))
    
    async def _call_detector_single(
        self, 
        config: DetectorConfig, 
        text: str, 
        context: Dict[str, Any]
    ) -> DetectorResult:
        """Einzelner Detektor-Aufruf."""
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
                    json={
                        "text": text,
                        "context": {
                            **context,
                            "routing_info": {
                                "mode": config.mode,
                                "priority": config.priority
                            }
                        }
                    },
                    timeout=aiohttp.ClientTimeout(total=config.timeout_ms / 1000.0)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        processing_time = (time.time() - start_time) * 1000
                        
                        # Extrahiere Ergebnis (unterstützt verschiedene Response-Formate)
                        if data.get("success", False):
                            result_data = data.get("data", {})
                            score = result_data.get("risk_score", result_data.get("score", 0.0))
                            # Code Intent verwendet should_block, andere verwenden blocked/is_blocked/is_malicious
                            blocked = (result_data.get("blocked") or 
                                      result_data.get("should_block") or 
                                      result_data.get("is_blocked") or 
                                      result_data.get("is_malicious") or 
                                      False)
                        else:
                            # Fallback für direkte Responses
                            score = data.get("risk_score", data.get("score", 0.0))
                            blocked = (data.get("blocked") or 
                                      data.get("should_block") or 
                                      data.get("is_blocked") or 
                                      data.get("is_malicious") or 
                                      False)
                        
                        return DetectorResult(
                            detector_name=config.name,
                            success=True,
                            score=float(score) if score is not None else None,
                            blocked=bool(blocked),
                            metadata=data.get("metadata", {}),
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
            processing_time = (time.time() - start_time) * 1000
            return DetectorResult(
                detector_name=config.name,
                success=False,
                score=None,
                blocked=False,
                metadata={"error": "timeout", "timeout_ms": config.timeout_ms},
                processing_time_ms=processing_time,
                error=f"Timeout after {config.timeout_ms}ms"
            )
        except Exception as e:
            processing_time = (time.time() - start_time) * 1000
            return DetectorResult(
                detector_name=config.name,
                success=False,
                score=None,
                blocked=False,
                metadata={"error": str(e)},
                processing_time_ms=processing_time,
                error=f"Request failed: {e}"
            )
    
    def _select_execution_strategy(
        self, 
        detectors: List[DetectorConfig], 
        context: Dict[str, Any]
    ) -> str:
        """Wählt optimale Ausführungsstrategie basierend auf Kontext."""
        # Hohes Risiko → Sequential für maximale Sicherheit
        if context.get('context_risk_score', 0) > 0.7:
            return "sequential"
        
        # Viele Detektoren → Parallel für Geschwindigkeit
        if len(detectors) > 2:
            return "parallel"
        
        # Default
        return "parallel"
    
    def _calculate_total_timeout(
        self, 
        detectors: List[DetectorConfig], 
        strategy: str
    ) -> int:
        """Berechnet Gesamt-Timeout basierend auf Strategie."""
        if strategy == "sequential":
            # Summe aller Timeouts + Puffer
            return sum(d.timeout_ms for d in detectors) + 100
        else:
            # Parallel: Maximum + Puffer
            return max((d.timeout_ms for d in detectors), default=200) + 50
    
    def _generate_decision_reason(
        self, 
        context: Dict[str, Any], 
        detectors: List[DetectorConfig]
    ) -> str:
        """Generiert menschenlesbare Begründung für Routing-Entscheidung."""
        reasons = []
        
        text_analysis = context.get('text_analysis')
        if isinstance(text_analysis, TextAnalysisResult):
            if text_analysis.contains_code_patterns:
                reasons.append("code patterns detected")
            if text_analysis.contains_multilingual_patterns:
                reasons.append("multilingual content")
            if text_analysis.text_complexity > 0.6:
                reasons.append("high complexity")
        
        risk_score = context.get('context_risk_score', 0)
        if risk_score > 0.7:
            reasons.append(f"high risk score ({risk_score:.2f})")
        
        tool = context.get('source_tool')
        if tool and tool != 'general':
            reasons.append(f"tool: {tool}")
        
        detector_names = [d.name for d in detectors]
        
        if reasons:
            return f"Detectors {detector_names}: {', '.join(reasons)}"
        else:
            return f"Default routing with {detector_names}"
    
    def _aggregate_results_intelligently(
        self, 
        results: Dict[str, DetectorResult]
    ) -> tuple:
        """Intelligente Aggregation mit Confidence-Weighting."""
        successful_results = [
            r for r in results.values() 
            if r.success and r.score is not None
        ]
        
        if not successful_results:
            return False, 0.0, 0.0
        
        # Basis-OR-Logik: Ein Block → Gesamtblock
        blocked = any(r.blocked for r in successful_results)
        
        # Confidence-basierter Score
        total_confidence = 0.0
        weighted_score = 0.0
        
        for result in successful_results:
            # Vereinfachte Confidence-Berechnung basierend auf Detektor-Art
            if result.detector_name == "code_intent":
                confidence = 0.9  # Hohes Vertrauen in Code-Intent
            elif result.detector_name == "content_safety":
                confidence = 0.8
            else:
                confidence = 0.7
            
            weighted_score += result.score * confidence
            total_confidence += confidence
        
        final_score = weighted_score / total_confidence if total_confidence > 0 else 0.0
        avg_confidence = total_confidence / len(successful_results)
        
        return blocked, final_score, avg_confidence
    
    def _create_fallback_decision(self) -> RoutingDecision:
        """Erstellt eine sichere Fallback-Entscheidung."""
        return RoutingDecision(
            detector_configs=[
                DetectorConfig(
                    name="content_safety",
                    mode="required",
                    timeout_ms=500,
                    priority=1
                )
            ],
            execution_strategy="sequential",
            total_timeout_ms=600,
            decision_reason="Fallback due to error",
            router_metadata={"fallback": True, "error": "routing_error"}
        )
    
    def _create_error_result(self, error: str) -> AggregatedResult:
        """Erstellt ein Fehler-Result."""
        return AggregatedResult(
            detector_results={},
            final_decision=False,  # Im Zweifel erlauben
            final_score=0.0,
            confidence=0.0,
            router_metadata={
                "error": error,
                "strategy": "error_fallback",
                "reason": f"Router error: {error}",
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def _track_decision(self, decision: RoutingDecision, context: Dict[str, Any]):
        """Trackt Entscheidung für Adaptive Learning."""
        self.learning_data['decisions'].append({
            'timestamp': datetime.utcnow(),
            'decision': decision,
            'context_summary': {
                'risk_score': context.get('context_risk_score', 0),
                'tool': context.get('source_tool'),
                'complexity': getattr(context.get('text_analysis'), 'text_complexity', 0) if context.get('text_analysis') else 0
            }
        })
        
        # Halte Datenmenge überschaubar
        if len(self.learning_data['decisions']) > 1000:
            self.learning_data['decisions'] = self.learning_data['decisions'][-500:]
    
    async def _evaluate_and_learn(
        self, 
        results: Dict[str, DetectorResult],
        final_decision: bool,
        context: Dict[str, Any]
    ):
        """Bewertet Ergebnisse und passt Learning an."""
        # Platzhalter für Adaptive Learning Logik
        # In Phase 5.3 implementieren
        pass
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Gibt Performance-Metriken zurück."""
        policy_metrics = self.policy_engine.get_metrics()
        
        return {
            **self.performance_metrics,
            'policy_engine': policy_metrics,
            'learning_enabled': self.enable_adaptive_learning,
            'learning_data_size': len(self.learning_data['decisions'])
        }

