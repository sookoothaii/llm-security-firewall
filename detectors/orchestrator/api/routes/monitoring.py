"""
Monitoring API Routes - Phase 5.4

API-Endpoints für Monitoring, Metriken, Alerts und Health-Checks.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import PlainTextResponse
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import asdict
import logging
import os

from infrastructure.app.composition_root import OrchestratorCompositionRoot

router = APIRouter(prefix="/api/v1", tags=["monitoring"])
logger = logging.getLogger(__name__)

# Global composition root instance (singleton pattern)
_composition_root = None


def get_monitored_service():
    """Dependency Injection für Monitoring Service."""
    global _composition_root
    
    try:
        # Use environment variables if available
        enable_adaptive_learning = os.getenv("ENABLE_ADAPTIVE_LEARNING", "true").lower() == "true"
        enable_monitoring = os.getenv("ENABLE_MONITORING", "true").lower() == "true"
        use_intelligent_router = os.getenv("USE_INTELLIGENT_ROUTER", "true").lower() == "true"
        
        # Settings from environment
        settings = {
            "FEEDBACK_REPOSITORY_TYPE": os.getenv("FEEDBACK_REPOSITORY_TYPE", "memory"),
            "REDIS_CLOUD_HOST": os.getenv("REDIS_CLOUD_HOST"),
            "REDIS_CLOUD_PORT": os.getenv("REDIS_CLOUD_PORT"),
            "REDIS_CLOUD_USERNAME": os.getenv("REDIS_CLOUD_USERNAME"),
            "REDIS_CLOUD_PASSWORD": os.getenv("REDIS_CLOUD_PASSWORD"),
            "POSTGRES_CONNECTION_STRING": os.getenv("POSTGRES_CONNECTION_STRING"),
            "ENABLE_MONITORING": enable_monitoring
        }
        
        if _composition_root is None:
            logger.info(
                f"Creating OrchestratorCompositionRoot "
                f"(adaptive_learning={enable_adaptive_learning}, "
                f"monitoring={enable_monitoring}, "
                f"intelligent_router={use_intelligent_router})"
            )
            _composition_root = OrchestratorCompositionRoot(
                enable_adaptive_learning=enable_adaptive_learning,
                use_intelligent_router=use_intelligent_router,
                enable_monitoring=enable_monitoring,
                settings=settings
            )
        
        logger.debug("Creating MonitoredRouterService...")
        service = _composition_root.create_monitored_router_service()
        logger.debug("MonitoredRouterService created successfully")
        return service
        
    except Exception as e:
        logger.error(f"Failed to create monitored service: {e}", exc_info=True)
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to initialize monitoring service: {str(e)}"
        )


@router.get("/health")
async def health_check(service = Depends(get_monitored_service)):
    """Vollständiger Health-Check Endpoint."""
    try:
        if service is None:
            raise HTTPException(status_code=503, detail="Service not initialized")
        
        health = await service.trigger_health_check()
        status_code = 200 if health["overall_status"] in ["healthy", "degraded"] else 503

        return {
            "status": health["overall_status"],
            "timestamp": health["timestamp"],
            "components": health.get("components", {}),
            "active_alerts": health.get("active_alerts", 0)
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Health check failed: {str(e)}")


@router.get("/metrics")
async def get_metrics(service = Depends(get_monitored_service)):
    """Gibt Metriken im Prometheus-Format zurück."""
    try:
        if service is None:
            raise HTTPException(status_code=503, detail="Service not initialized")
        
        metrics_data = service.get_monitoring_metrics()

        # Content-Type für Prometheus
        return PlainTextResponse(
            content=metrics_data["metrics"]["prometheus"],
            media_type="text/plain"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics/summary")
async def get_metrics_summary(service = Depends(get_monitored_service)):
    """Gibt eine Zusammenfassung der Metriken zurück."""
    try:
        if service is None:
            raise HTTPException(status_code=503, detail="Service not initialized")
        
        metrics_data = service.get_monitoring_metrics()
        return {
            "summary": metrics_data["metrics"]["summary"],
            "health": metrics_data["health"],
            "timestamp": datetime.utcnow().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get metrics summary: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def get_alerts(
    active_only: bool = Query(True, description="Only return active alerts"),
    service = Depends(get_monitored_service)
):
    """Gibt aktive Alerts zurück."""
    try:
        if service is None:
            raise HTTPException(status_code=503, detail="Service not initialized")
        
        if active_only:
            alerts = service.alert_manager.get_active_alerts()
        else:
            alerts = service.alert_manager.get_alert_history(50)

        return {
            "alerts": [asdict(alert) for alert in alerts],
            "count": len(alerts),
            "timestamp": datetime.utcnow().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get alerts: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    user: str = Query("api", description="User who acknowledges the alert"),
    service = Depends(get_monitored_service)
):
    """Bestätigt einen Alert."""
    try:
        if service is None:
            raise HTTPException(status_code=503, detail="Service not initialized")
        
        success = service.alert_manager.acknowledge_alert(alert_id, user)

        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")

        return {"status": "acknowledged", "alert_id": alert_id, "user": user}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to acknowledge alert: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/traces/{trace_id}")
async def get_trace(
    trace_id: str,
    service = Depends(get_monitored_service)
):
    """Gibt einen Trace zurück."""
    try:
        if service is None:
            raise HTTPException(status_code=503, detail="Service not initialized")
        
        trace = service.trace_collector.get_trace(trace_id)

        if not trace:
            raise HTTPException(status_code=404, detail="Trace not found")

        return trace

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get trace: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dashboard")
async def get_dashboard(service = Depends(get_monitored_service)):
    """Gibt Dashboard-Daten zurück."""
    try:
        if service is None:
            raise HTTPException(status_code=503, detail="Service not initialized")
        
        # Sammle alle Daten für Dashboard
        metrics_data = service.get_monitoring_metrics()

        # Performance Trends (letzte Stunde)
        now = datetime.utcnow()
        one_hour_ago = now - timedelta(hours=1)

        router_latency = service.metrics_collector.get_summary(
            "router_latency_seconds",
            start_time=one_hour_ago
        )

        detector_calls = service.metrics_collector.get_summary(
            "detector_calls_total",
            start_time=one_hour_ago
        )

        error_rate = service.metrics_collector.get_summary(
            "error_rate",
            start_time=one_hour_ago
        )

        return {
            "overview": {
                "status": metrics_data["health"]["status"],
                "total_requests": metrics_data["metrics"]["summary"]["router"]["5min_requests"],
                "active_alerts": len(metrics_data["alerts"]["active"])
            },
            "performance": {
                "router_latency_ms": router_latency.get("avg", 0) * 1000,
                "detector_calls": detector_calls.get("count", 0),
                "error_rate": error_rate.get("avg", 0)
            },
            "components": metrics_data["health"]["components"],
            "recent_alerts": metrics_data["alerts"]["recent"][:5]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get dashboard data: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

