"""
Learning Router Service - Phase 5.3

Erweiterter Router Service mit Lernfähigkeiten.
Integriert FeedbackCollector und PolicyOptimizer.
"""

import asyncio
import time
from typing import Dict, Any, List
from datetime import datetime
import logging

from application.intelligent_router_service import IntelligentRouterService
from domain.ports import (
    RoutingDecision, AggregatedResult
)
from domain.learning.feedback_collector import (
    FeedbackCollector, FeedbackType, FeedbackSource
)
from domain.learning.policy_optimizer import AdaptivePolicyOptimizer

logger = logging.getLogger(__name__)


class LearningRouterService(IntelligentRouterService):
    """Erweiterter Router Service mit Lernfähigkeiten."""

    def __init__(
        self,
        policy_engine,
        detector_endpoints: Dict[str, str],
        enable_adaptive_learning: bool = True,
        feedback_collector: FeedbackCollector = None,
        policy_optimizer: AdaptivePolicyOptimizer = None
    ):
        super().__init__(
            policy_engine=policy_engine,
            detector_endpoints=detector_endpoints,
            enable_adaptive_learning=enable_adaptive_learning
        )

        # Learning Komponenten
        self.feedback_collector = feedback_collector
        self.policy_optimizer = policy_optimizer

        # Auto-Optimierung Task
        self.auto_optimize_task = None
        if enable_adaptive_learning and self.feedback_collector:
            self._start_auto_optimization()

        logger.info("LearningRouterService initialized with adaptive learning")

    async def execute_detectors(
        self,
        decision: RoutingDecision,
        text: str,
        context: Dict[str, Any]
    ) -> AggregatedResult:
        """Führt Detektoren aus und sammelt Feedback."""
        start_time = time.time()

        try:
            # Führe normale Detektor-Ausführung durch
            result = await super().execute_detectors(decision, text, context)

            # Sammle Performance-Feedback
            if self.feedback_collector:
                await self._collect_performance_feedback(result)

            # Prüfe auf Feedback-Trigger
            if self.feedback_collector:
                await self._check_for_feedback_triggers(result, text, context)

            # Führe periodische Optimierung durch
            if self.enable_adaptive_learning and self.policy_optimizer:
                self.policy_optimizer.auto_optimize(interval_hours=1)

            return result

        except Exception as e:
            logger.error(f"Error in learning router execution: {e}", exc_info=True)

            # Sammle auch Fehler-Feedback
            if self.feedback_collector:
                await self.feedback_collector.add_feedback(
                    feedback_type=FeedbackType.AUTO_CORRECTION,
                    source=FeedbackSource.SYSTEM,
                    data={
                        "error": str(e),
                        "stage": "execution",
                        "text_preview": text[:100]
                    },
                    context=context,
                    confidence=0.8
                )

            raise

    async def _collect_performance_feedback(self, result: AggregatedResult):
        """Sammelt Performance-Feedback von Detektor-Ergebnissen."""
        for detector_name, detector_result in result.detector_results.items():
            if detector_result.success:
                await self.feedback_collector.add_detector_performance(
                    detector_name=detector_name,
                    success=True,
                    response_time=detector_result.processing_time_ms,
                    metadata=detector_result.metadata
                )
            else:
                await self.feedback_collector.add_detector_performance(
                    detector_name=detector_name,
                    success=False,
                    response_time=detector_result.processing_time_ms,
                    metadata={
                        "error": detector_result.error,
                        **detector_result.metadata
                    }
                )

    async def _check_for_feedback_triggers(
        self,
        result: AggregatedResult,
        text: str,
        context: Dict[str, Any]
    ):
        """Prüft auf Bedingungen die Feedback auslösen sollten."""
        # Trigger 1: Sehr niedrige Confidence bei Block-Entscheidung
        if result.final_decision and result.confidence < 0.3:
            await self.feedback_collector.add_feedback(
                feedback_type=FeedbackType.FALSE_POSITIVE,
                source=FeedbackSource.SYSTEM,
                data={
                    "reason": "low_confidence_block",
                    "confidence": result.confidence,
                    "final_score": result.final_score,
                    "detector_results": {
                        name: {
                            "score": r.score,
                            "blocked": r.blocked,
                            "success": r.success
                        }
                        for name, r in result.detector_results.items()
                    }
                },
                context=context,
                confidence=0.7  # System ist sich zu 70% sicher, dass es ein FP ist
            )

        # Trigger 2: Widersprüchliche Detektor-Ergebnisse
        detector_scores = [
            r.score for r in result.detector_results.values()
            if r.success and r.score is not None
        ]

        if len(detector_scores) >= 2:
            score_range = max(detector_scores) - min(detector_scores)
            if score_range > 0.5:  # Große Diskrepanz zwischen Detektoren
                await self.feedback_collector.add_feedback(
                    feedback_type=FeedbackType.AUTO_CORRECTION,
                    source=FeedbackSource.SYSTEM,
                    data={
                        "reason": "high_score_discrepancy",
                        "score_range": score_range,
                        "detector_scores": detector_scores,
                        "final_decision": result.final_decision
                    },
                    context=context,
                    confidence=0.6
                )

    def submit_human_feedback(
        self,
        request_id: str,
        correct_decision: bool,
        human_notes: str = "",
        confidence: float = 1.0
    ):
        """Ermöglicht manuelles Feedback von Administratoren."""
        if not self.feedback_collector:
            logger.warning("Feedback collector not available")
            return

        feedback_type = (
            FeedbackType.FALSE_POSITIVE if not correct_decision else
            FeedbackType.FALSE_NEGATIVE if correct_decision else
            FeedbackType.HUMAN_REVIEW
        )

        # Asynchrone Verarbeitung
        asyncio.create_task(
            self.feedback_collector.add_feedback(
                feedback_type=feedback_type,
                source=FeedbackSource.ADMIN,
                data={
                    "request_id": request_id,
                    "human_notes": human_notes,
                    "submitted_by": "admin"  # In Produktion: aktueller Benutzer
                },
                context={"request_id": request_id},
                confidence=confidence
            )
        )

        logger.info(f"Human feedback submitted for request {request_id}")

    def _start_auto_optimization(self):
        """Startet automatische Optimierung im Hintergrund."""
        async def auto_optimize_loop():
            while True:
                try:
                    await asyncio.sleep(3600)  # Jede Stunde

                    if self.policy_optimizer:
                        self.policy_optimizer.auto_optimize()

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Auto-optimization error: {e}", exc_info=True)
                    await asyncio.sleep(300)  # Bei Fehler 5 Minuten warten

        if self.enable_adaptive_learning and self.policy_optimizer:
            # Versuche Task zu erstellen, nur wenn Event Loop läuft
            try:
                loop = asyncio.get_running_loop()
                self.auto_optimize_task = asyncio.create_task(auto_optimize_loop())
                logger.debug("Auto-optimization task created in running event loop")
            except RuntimeError:
                # Kein laufender Event Loop - Task wird später gestartet
                logger.debug("No running event loop, auto-optimization will start later")
                self.auto_optimize_task = None

    def get_learning_metrics(self) -> Dict[str, Any]:
        """Gibt Lern-Metriken zurück."""
        if not self.feedback_collector:
            return {
                "error": "Feedback collector not available",
                "auto_optimization_enabled": False
            }

        feedback_summary = self.feedback_collector.get_feedback_summary(hours=24)
        detector_metrics = self.feedback_collector.get_all_metrics()

        # Berechne Gesamt-Performance
        total_false_positives = sum(
            m.false_positives for m in detector_metrics.values()
        )
        total_false_negatives = sum(
            m.false_negatives for m in detector_metrics.values()
        )

        return {
            "feedback_last_24h": feedback_summary,
            "detector_performance": {
                name: {
                    "total_calls": m.total_calls,
                    "error_rate": m.error_rate,
                    "avg_response_time_ms": m.avg_response_time,
                    "precision": m.get_precision(),
                    "recall": m.get_recall(),
                    "f1_score": m.get_f1_score(),
                    "false_positives": m.false_positives,
                    "false_negatives": m.false_negatives
                }
                for name, m in detector_metrics.items()
            },
            "total_false_positives": total_false_positives,
            "total_false_negatives": total_false_negatives,
            "auto_optimization_enabled": self.enable_adaptive_learning,
            "last_auto_optimization": (
                self.policy_optimizer.last_optimization.isoformat()
                if self.policy_optimizer and self.policy_optimizer.last_optimization
                else None
            )
        }

    async def shutdown(self):
        """Stoppt den Learning Router sauber."""
        if self.auto_optimize_task:
            self.auto_optimize_task.cancel()
            try:
                await self.auto_optimize_task
            except asyncio.CancelledError:
                pass

        if self.feedback_collector:
            await self.feedback_collector.shutdown()

        logger.info("LearningRouterService shutdown complete")

