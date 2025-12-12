"""
Monitored Router Service - Phase 5.4

Überwachter Router Service mit vollständiger Observability.
Integriert MetricsCollector, TraceCollector und AlertManager.
"""

import asyncio
import time
from typing import Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import asdict
import logging
from contextlib import contextmanager

from application.learning_router_service import LearningRouterService
from domain.ports import RoutingDecision, AggregatedResult
from domain.monitoring.metrics_collector import MetricsCollector, MetricType, MetricDefinition
from domain.monitoring.tracing import TraceCollector, trace_context
from domain.monitoring.alert_manager import AlertManager, AlertSeverity

logger = logging.getLogger(__name__)


class MonitoredRouterService(LearningRouterService):
    """Überwachter Router Service mit vollständiger Observability."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Monitoring-Komponenten
        self.metrics_collector = MetricsCollector()
        self.trace_collector = TraceCollector(export_to_console=True)
        self.alert_manager = AlertManager(self.metrics_collector)
        
        # Starte asyncio-Tasks (wenn Event Loop läuft)
        try:
            self.metrics_collector._ensure_cleanup_task()
            self.alert_manager._ensure_monitoring_loop()
        except Exception as e:
            logger.warning(f"Could not start monitoring tasks immediately: {e}")

        # Definiere zusätzliche Metriken für Router-Operationen
        self._define_router_metrics()

        # Füge Console Handler für Alerts hinzu
        self.alert_manager.add_console_handler()

        # Metriken für Learning-Integration
        self._setup_monitoring_integration()

        logger.info("Monitoring system initialized")
    
    def _define_router_metrics(self):
        """Definiert zusätzliche Metriken für Router-Operationen."""
        router_metrics = [
            MetricDefinition(
                name="router_analyze_and_route_total",
                type=MetricType.COUNTER,
                description="Total analyze and route operations",
                labels=["source_tool", "text_length"]
            ),
            MetricDefinition(
                name="router_analyze_and_route_latency_seconds",
                type=MetricType.HISTOGRAM,
                description="Analyze and route latency",
                labels=["source_tool", "text_length"],
                buckets=[0.01, 0.05, 0.1, 0.2, 0.5, 1.0]
            ),
            MetricDefinition(
                name="router_execute_detectors_total",
                type=MetricType.COUNTER,
                description="Total execute detectors operations",
                labels=["strategy", "detector_count"]
            ),
            MetricDefinition(
                name="router_execute_detectors_latency_seconds",
                type=MetricType.HISTOGRAM,
                description="Execute detectors latency",
                labels=["strategy", "detector_count"],
                buckets=[0.1, 0.2, 0.5, 1.0, 2.0, 5.0]
            )
        ]
        
        for metric in router_metrics:
            self.metrics_collector.register_metric(metric)

    def _setup_monitoring_integration(self):
        """Richtet Monitoring-Integration ein."""
        # Tracke Learning-Performance
        if self.enable_adaptive_learning:
            # Periodische Metriken-Erfassung für Learning
            # Versuche Task zu erstellen, wenn Event Loop läuft
            try:
                loop = asyncio.get_running_loop()
                asyncio.create_task(self._collect_learning_metrics())
                logger.debug("Learning metrics collection task created in running event loop")
            except RuntimeError:
                # Kein laufender Event Loop - Task wird später gestartet
                logger.debug("No running event loop, learning metrics collection will start later")

    async def _collect_learning_metrics(self):
        """Sammelt regelmäßig Learning-Metriken."""
        while True:
            try:
                # Sammle Learning-Performance
                if hasattr(self, 'get_learning_metrics'):
                    metrics = self.get_learning_metrics()
                    
                    # Tracke Impact
                    impact = metrics.get('total_false_positives', 0) + metrics.get('total_false_negatives', 0)
                    self.metrics_collector.gauge(
                        "adaptive_learning_impact",
                        impact,
                        {"metric": "overall_improvement"}
                    )
                    
                    # Tracke Optimierungen
                    if self.policy_optimizer and self.policy_optimizer.last_optimization:
                        self.metrics_collector.inc(
                            "learning_optimizations_total",
                            {"optimization_type": "auto", "result": "success"},
                            amount=1
                        )

            except Exception as e:
                logger.error(f"Error collecting learning metrics: {e}")

            await asyncio.sleep(300)  # Alle 5 Minuten

    @contextmanager
    def _monitored_operation(self, operation_name: str, labels: Dict[str, str] = None):
        """Context Manager für überwachte Operationen."""
        span_id = None
        start_time = time.time()

        try:
            # Starte Trace-Span
            span_id = self.trace_collector.start_span(operation_name, labels)

            # Metriken
            self.metrics_collector.inc(
                f"{operation_name}_total",
                labels or {},
                amount=1
            )

            yield

            # Erfolgreich beendet
            duration = time.time() - start_time
            self.metrics_collector.observe(
                f"{operation_name}_latency_seconds",
                duration,
                labels or {}
            )

            self.trace_collector.end_span(span_id, "success")

        except Exception as e:
            # Fehler aufgetreten
            duration = time.time() - start_time

            # Error-Metriken
            self.metrics_collector.gauge(
                "error_rate",
                1.0,
                {"component": "router", "error_type": type(e).__name__}
            )

            self.metrics_collector.observe(
                f"{operation_name}_latency_seconds",
                duration,
                labels or {}
            )

            if span_id:
                self.trace_collector.end_span(span_id, "error", str(e))

            raise

    def analyze_and_route(self, text: str, context: Dict[str, Any]) -> RoutingDecision:
        """Überwachte Routing-Entscheidung."""
        with self._monitored_operation(
            "router_analyze_and_route",
            {
                "source_tool": context.get('source_tool', 'unknown'),
                "text_length": str(len(text))
            }
        ):
            # Starte Trace
            trace_id = self.trace_collector.start_trace(
                "router_request",
                {
                    "text_preview": text[:50],
                    "source_tool": context.get('source_tool', 'unknown'),
                    "user_risk_tier": str(context.get('user_risk_tier', 1))
                }
            )

            try:
                result = super().analyze_and_route(text, context)

                # Tracke Metriken
                self.metrics_collector.inc(
                    "router_requests_total",
                    {
                        "source_tool": context.get('source_tool', 'unknown'),
                        "outcome": "success"
                    }
                )

                # Risk-Score Verteilung
                if hasattr(self, 'context_analyzer'):
                    enhanced_context = self.context_analyzer.analyze_context(text, context)
                    risk_score = enhanced_context.get('context_risk_score', 0)
                    self.metrics_collector.observe("risk_score_distribution", risk_score)

                return result

            finally:
                self.trace_collector.end_trace(trace_id)

    async def execute_detectors(
        self,
        decision: RoutingDecision,
        text: str,
        context: Dict[str, Any]
    ) -> AggregatedResult:
        """Überwachte Detektor-Ausführung."""
        start_time = time.time()

        with self._monitored_operation(
            "router_execute_detectors",
            {
                "strategy": decision.execution_strategy,
                "detector_count": str(len(decision.detector_configs))
            }
        ):
            # Füge Trace-Kontext zu Context hinzu
            trace_context_data = self.trace_collector.get_current_context()
            if trace_context_data:
                context = context.copy()
                context["trace_context"] = trace_context_data

            result = await super().execute_detectors(decision, text, context)

            # Tracke Gesamt-Latenz
            total_duration = time.time() - start_time
            self.metrics_collector.observe(
                "router_latency_seconds",
                total_duration,
                {
                    "source_tool": context.get('source_tool', 'unknown'),
                    "strategy": decision.execution_strategy
                }
            )

            # Tracke Detektor-Performance
            for detector_name, detector_result in result.detector_results.items():
                status = "success" if detector_result.success else "failure"
                mode = next((d.mode for d in decision.detector_configs
                           if d.name == detector_name), "unknown")

                self.metrics_collector.inc(
                    "detector_calls_total",
                    {
                        "detector_name": detector_name,
                        "status": status,
                        "mode": mode
                    }
                )

                if detector_result.success and detector_result.processing_time_ms:
                    self.metrics_collector.observe(
                        "detector_latency_seconds",
                        detector_result.processing_time_ms / 1000,
                        {"detector_name": detector_name}
                    )

            # Tracke Policy-Evaluierungen
            if hasattr(self, 'policy_engine'):
                self.metrics_collector.inc(
                    "policy_evaluations_total",
                    {"policy_name": "dynamic", "matched": "true"},
                    amount=1
                )

            return result

    def get_monitoring_metrics(self) -> Dict[str, Any]:
        """Gibt alle Monitoring-Metriken zurück."""
        return {
            "metrics": {
                "prometheus": self.metrics_collector.get_prometheus_format(),
                "summary": self.metrics_collector.get_system_summary()
            },
            "health": self.metrics_collector.get_health_status(),
            "alerts": {
                "active": [asdict(a) for a in self.alert_manager.get_active_alerts()],
                "recent": [asdict(a) for a in self.alert_manager.get_alert_history(10)]
            },
            "traces": {
                "active": len(self.trace_collector.active_spans),
                "total": len(self.trace_collector.traces)
            }
        }

    async def trigger_health_check(self) -> Dict[str, Any]:
        """Führt eine vollständige Health-Check durch."""
        health_result = {
            "timestamp": datetime.utcnow().isoformat(),
            "components": {},
            "overall_status": "healthy"
        }

        # Prüfe Router
        try:
            test_decision = self.analyze_and_route("test", {"source_tool": "general"})
            health_result["components"]["router"] = {
                "status": "healthy",
                "response_time": "normal"
            }
        except Exception as e:
            health_result["components"]["router"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            health_result["overall_status"] = "degraded"

        # Prüfe Detektoren
        detector_status = {}
        for detector_name, endpoint in self.detector_endpoints.items():
            try:
                # Versuche einfachen HTTP-Call
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{endpoint}/health",
                        timeout=aiohttp.ClientTimeout(total=2)
                    ) as response:
                        detector_status[detector_name] = {
                            "status": "healthy" if response.status == 200 else "unhealthy",
                            "status_code": response.status
                        }
            except Exception as e:
                detector_status[detector_name] = {
                    "status": "unhealthy",
                    "error": str(e)
                }

        health_result["components"]["detectors"] = detector_status

        # Prüfe Storage (wenn Feedback Repository vorhanden)
        if hasattr(self, 'feedback_collector') and self.feedback_collector:
            try:
                # Teste Repository-Verbindung
                metrics = self.get_learning_metrics()
                health_result["components"]["storage"] = {"status": "healthy"}
            except Exception as e:
                health_result["components"]["storage"] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                health_result["overall_status"] = "degraded"

        # System-Metriken
        system_metrics = self.metrics_collector.get_system_summary()
        health_result["metrics"] = system_metrics

        # Alerts
        active_alerts = self.alert_manager.get_active_alerts()
        if active_alerts:
            critical_alerts = [a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]
            if critical_alerts:
                health_result["overall_status"] = "critical"
            else:
                health_result["overall_status"] = "degraded"

            health_result["active_alerts"] = len(active_alerts)

        return health_result

