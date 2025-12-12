"""
Monitoring Routes

Routes for service status, alerts, and history.
"""
from fastapi import APIRouter, Query
from typing import Dict

# Import shared components
import sys
from pathlib import Path

service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from infrastructure.app.composition_root import LearningMonitorCompositionRoot

router = APIRouter(tags=["monitoring"])

# Create composition root and service (singleton pattern)
_composition_root: LearningMonitorCompositionRoot | None = None
_monitor_service = None

def get_monitor_service():
    """Get or create monitor service instance"""
    global _composition_root, _monitor_service
    
    if _monitor_service is None:
        # Create composition root
        _composition_root = LearningMonitorCompositionRoot(
            history_max_size=1000,
            http_timeout=2.0
        )
        
        # Create monitor service
        _monitor_service = _composition_root.create_monitor_service()
    
    return _monitor_service

# Monitored services configuration (from original main.py)
MONITORED_SERVICES = {
    "orchestrator": {
        "name": "Orchestrator Service",
        "url": "http://localhost:8001",
        "enabled": True,
        "learning_endpoint": "/api/v1/learning/metrics"  # Orchestrator hat Learning-Metrics
    },
    "code_intent": {
        "name": "Code-Intent Detector",
        "url": "http://localhost:8000",  # Updated to new port
        "enabled": True
    },
    "persuasion": {
        "name": "Persuasion Detector",
        "url": "http://localhost:8002",
        "enabled": True
    },
    "content_safety": {
        "name": "Content-Safety Detector",
        "url": "http://localhost:8003",
        "enabled": True
    }
}


@router.get("/status")
async def get_status():
    """Status aller überwachten Services."""
    monitor_service = get_monitor_service()
    service_statuses, alerts = await monitor_service.collect_status_and_alerts(MONITORED_SERVICES)
    
    return {
        "timestamp": service_statuses[list(service_statuses.keys())[0]].last_checked.isoformat() if service_statuses else None,
        "services": {
            sid: {
                "service_id": status.service_id,
                "service_name": status.service_name,
                "status": "healthy" if status.is_healthy else "unhealthy",
                "feedback_enabled": status.feedback_enabled,
                "buffer_size": status.buffer_size,
                "max_size": status.max_size,
                "online_learning": status.online_learning,
                "statistics": status.statistics,
                "error": status.error,
            }
            for sid, status in service_statuses.items()
        },
        "alerts": [
            {
                "severity": alert.severity,
                "service": alert.service_id,
                "type": alert.alert_type,
                "message": alert.message,
                "value": alert.value,
                "timestamp": alert.timestamp.isoformat(),
            }
            for alert in alerts
        ],
        "alert_count": len(alerts)
    }


@router.get("/alerts")
async def get_alerts():
    """Aktuelle Alerts."""
    monitor_service = get_monitor_service()
    service_statuses, alerts = await monitor_service.collect_status_and_alerts(MONITORED_SERVICES)
    
    return {
        "timestamp": alerts[0].timestamp.isoformat() if alerts else None,
        "alerts": [
            {
                "severity": alert.severity,
                "service": alert.service_id,
                "type": alert.alert_type,
                "message": alert.message,
                "value": alert.value,
                "timestamp": alert.timestamp.isoformat(),
            }
            for alert in alerts
        ],
        "count": len(alerts),
        "critical": len([a for a in alerts if a.severity == "critical"]),
        "warning": len([a for a in alerts if a.severity == "warning"])
    }


@router.get("/history")
async def get_history(limit: int = Query(100, ge=1, le=1000)):
    """Learning-History."""
    monitor_service = get_monitor_service()
    history = monitor_service.history_repository.get_history(limit=limit)
    
    return {
        "timestamp": history[-1]["timestamp"] if history else None,
        "history": history,
        "total": len(monitor_service.history_repository.history)
    }

