"""
Learning API Routes - Phase 5.3

API-Endpoints für Learning-Metriken, Feedback und Policy-Optimierung.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
import os

from infrastructure.app.composition_root import OrchestratorCompositionRoot

router = APIRouter(prefix="/api/v1/learning", tags=["learning"])
logger = logging.getLogger(__name__)


def get_composition_root() -> OrchestratorCompositionRoot:
    """Get composition root with learning enabled."""
    # Settings aus Environment Variables lesen
    settings = {
        "FEEDBACK_REPOSITORY_TYPE": os.getenv("FEEDBACK_REPOSITORY_TYPE", "postgres"),
        "POSTGRES_CONNECTION_STRING": os.getenv("POSTGRES_CONNECTION_STRING"),
        "ENABLE_ADAPTIVE_LEARNING": os.getenv("ENABLE_ADAPTIVE_LEARNING", "true").lower() == "true"
    }
    
    return OrchestratorCompositionRoot(
        enable_adaptive_learning=True,
        use_intelligent_router=True,
        settings=settings
    )


@router.get("/metrics")
async def get_learning_metrics(
    composition: OrchestratorCompositionRoot = Depends(get_composition_root)
) -> Dict[str, Any]:
    """Gibt Lern-Metriken zurück."""
    try:
        router_service = composition.create_router_service()
        
        # Prüfe ob LearningRouterService
        if hasattr(router_service, 'get_learning_metrics'):
            return router_service.get_learning_metrics()
        else:
            return {
                "error": "Learning not enabled",
                "router_type": type(router_service).__name__
            }
    except Exception as e:
        logger.error(f"Failed to get learning metrics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/optimization-history")
async def get_optimization_history(
    policy_name: Optional[str] = None,
    limit: int = 10,
    composition: OrchestratorCompositionRoot = Depends(get_composition_root)
) -> List[Dict[str, Any]]:
    """Gibt Optimierungsverlauf zurück."""
    try:
        optimizer = composition.create_policy_optimizer()
        history = optimizer.get_optimization_history(policy_name, limit)

        # Konvertiere Dataclasses zu Dicts
        return [
            {
                "policy_name": result.policy_name,
                "changes_applied": result.changes_applied,
                "performance_before": result.performance_before,
                "performance_after": result.performance_after,
                "improvement": result.improvement,
                "timestamp": result.timestamp.isoformat()
            }
            for result in history
        ]
    except Exception as e:
        logger.error(f"Failed to get optimization history: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/submit-feedback")
async def submit_feedback(
    feedback_data: Dict[str, Any],
    composition: OrchestratorCompositionRoot = Depends(get_composition_root)
) -> Dict[str, Any]:
    """Ermöglicht manuelles Feedback-Einreichen."""
    try:
        router_service = composition.create_router_service()

        # Prüfe ob LearningRouterService
        if not hasattr(router_service, 'submit_human_feedback'):
            raise HTTPException(
                status_code=400,
                detail="Learning router service not available"
            )

        # Extrahiere Daten
        request_id = feedback_data.get("request_id")
        correct_decision = feedback_data.get("correct_decision", True)
        human_notes = feedback_data.get("notes", "")
        confidence = feedback_data.get("confidence", 1.0)

        if not request_id:
            raise HTTPException(status_code=400, detail="request_id is required")

        router_service.submit_human_feedback(
            request_id=request_id,
            correct_decision=correct_decision,
            human_notes=human_notes,
            confidence=confidence
        )

        return {"status": "feedback_submitted", "request_id": request_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit feedback: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/trigger-optimization")
async def trigger_optimization(
    composition: OrchestratorCompositionRoot = Depends(get_composition_root)
) -> Dict[str, Any]:
    """Löst manuelle Optimierung aus."""
    try:
        optimizer = composition.create_policy_optimizer()
        results = optimizer.optimize_policies()

        return {
            "status": "optimization_completed",
            "policies_optimized": len(results),
            "results": [
                {
                    "policy_name": result.policy_name,
                    "changes": result.changes_applied,
                    "improvement": result.improvement
                }
                for result in results
            ]
        }
    except Exception as e:
        logger.error(f"Failed to trigger optimization: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/detector-performance")
async def get_detector_performance(
    detector_name: Optional[str] = None,
    composition: OrchestratorCompositionRoot = Depends(get_composition_root)
) -> Dict[str, Any]:
    """Gibt detaillierte Performance-Metriken für Detektoren zurück."""
    try:
        feedback_collector = composition.create_feedback_collector()

        if detector_name:
            metrics = feedback_collector.get_detector_metrics(detector_name)
            if not metrics:
                raise HTTPException(status_code=404, detail="Detector not found")

            return {
                detector_name: {
                    "total_calls": metrics.total_calls,
                    "successful_calls": metrics.successful_calls,
                    "error_rate": metrics.error_rate,
                    "avg_response_time": metrics.avg_response_time,
                    "precision": metrics.get_precision(),
                    "recall": metrics.get_recall(),
                    "f1_score": metrics.get_f1_score(),
                    "false_positives": metrics.false_positives,
                    "false_negatives": metrics.false_negatives
                }
            }
        else:
            all_metrics = feedback_collector.get_all_metrics()
            return {
                name: {
                    "total_calls": m.total_calls,
                    "error_rate": m.error_rate,
                    "avg_response_time": m.avg_response_time,
                    "f1_score": m.get_f1_score()
                }
                for name, m in all_metrics.items()
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get detector performance: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

