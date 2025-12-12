"""
WebSocket Routes

WebSocket endpoint for live updates.
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import logging

# Import shared components
import sys
from pathlib import Path

service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from infrastructure.app.composition_root import LearningMonitorCompositionRoot

router = APIRouter(tags=["websocket"])
logger = logging.getLogger(__name__)

# Monitored services configuration
MONITORED_SERVICES = {
    "code_intent": {
        "name": "Code-Intent Detector",
        "url": "http://localhost:8000",
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

# Create composition root and service (singleton pattern)
_composition_root: LearningMonitorCompositionRoot | None = None
_monitor_service = None

def get_monitor_service():
    """Get or create monitor service instance"""
    global _composition_root, _monitor_service
    
    if _monitor_service is None:
        _composition_root = LearningMonitorCompositionRoot(
            history_max_size=1000,
            http_timeout=2.0
        )
        _monitor_service = _composition_root.create_monitor_service()
    
    return _monitor_service


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket für Live-Updates."""
    await websocket.accept()
    
    monitor_service = get_monitor_service()
    websocket_manager = monitor_service.websocket_manager
    
    # Add connection
    websocket_manager.add_connection(websocket)
    
    try:
        while True:
            # Broadcast updates every 5 seconds
            await monitor_service.broadcast_update(MONITORED_SERVICES)
            await asyncio.sleep(5)
    
    except WebSocketDisconnect:
        websocket_manager.remove_connection(websocket)
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        websocket_manager.remove_connection(websocket)

