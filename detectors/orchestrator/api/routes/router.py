"""
Router Routes

FastAPI routes for orchestrator endpoints.
"""
import sys
import logging
import aiohttp
from pathlib import Path
from fastapi import APIRouter, HTTPException
from typing import Dict

# Add paths for imports
# This needs to be done before importing local modules
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))
if str(service_dir) not in sys.path:
    sys.path.insert(0, str(service_dir))

from api.models.router_models import RouterRequest, RouterResponse, DetectorResultResponse
from infrastructure.app.composition_root import OrchestratorCompositionRoot

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["orchestrator"])


@router.post("/route-and-detect", response_model=RouterResponse)
async def route_and_detect(request: RouterRequest):
    """
    Hauptendpunkt: Router analysiert und orchestriert Detektoren.
    
    Phase 5.2: Uses IntelligentRouterService by default with advanced context analysis.
    Can be overridden via environment variable USE_INTELLIGENT_ROUTER=false.
    
    Args:
        request: RouterRequest mit text, context, source_tool, etc.
        
    Returns:
        RouterResponse mit aggregierten Detektor-Ergebnissen
    """
    try:
        # Phase 5.2: Use intelligent router by default
        # Can be overridden via environment variable USE_INTELLIGENT_ROUTER=false
        import os
        use_intelligent = os.getenv("USE_INTELLIGENT_ROUTER", "true").lower() == "true"
        
        composition = OrchestratorCompositionRoot(
            use_intelligent_router=use_intelligent,
            enable_adaptive_learning=False  # Phase 5.3
        )
        router_service = composition.create_router_service()
        
        # Kontext für Routing-Entscheidung
        # Debug-Mode aktivieren wenn im Request angegeben
        debug_mode = request.context.get("debug", False) if request.context else False
        context = {
            "source_tool": request.source_tool,
            "user_risk_tier": request.user_risk_tier,
            "session_risk_score": request.session_risk_score,
            "debug": debug_mode,  # Für Debug-Logging
            "_debug": debug_mode,  # Alternative Key für Debug
            **(request.context or {})
        }
        
        # Routing-Entscheidung treffen
        routing_decision = router_service.analyze_and_route(
            text=request.text,
            context=context
        )
        
        logger.info(
            f"Routing decision: {routing_decision.decision_reason}, "
            f"detectors: {[c.name for c in routing_decision.detector_configs]}, "
            f"strategy: {routing_decision.execution_strategy}"
        )
        
        # Detektoren ausführen
        result = await router_service.execute_detectors(
            decision=routing_decision,
            text=request.text,
            context=context
        )
        
        # Response erstellen
        return RouterResponse(
            success=True,
            data={
                "blocked": result.final_decision,
                "risk_score": result.final_score,
                "confidence": result.confidence,
                "detector_results": {
                    name: DetectorResultResponse(
                        success=res.success,
                        score=res.score,
                        blocked=res.blocked,
                        processing_time_ms=res.processing_time_ms,
                        error=res.error
                    ).model_dump()
                    for name, res in result.detector_results.items()
                },
                "routing_metadata": result.router_metadata if isinstance(result.router_metadata, dict) else {}
            }
        )
        
    except Exception as e:
        logger.error(f"Routing failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Routing failed: {str(e)}")


@router.get("/router-health")
async def router_health():
    """
    Health Check für Router Service.
    
    Prüft Verbindung zu allen konfigurierten Detektor-Services.
    """
    try:
        composition = OrchestratorCompositionRoot()
        router_service = composition.create_router_service()
        
        # Prüfe Verbindung zu Detektoren
        detector_status = {}
        for name, endpoint in router_service.detector_endpoints.items():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"{endpoint}/health", timeout=aiohttp.ClientTimeout(total=2)) as resp:
                        detector_status[name] = {
                            "status": "healthy" if resp.status == 200 else "unhealthy",
                            "status_code": resp.status,
                            "endpoint": endpoint
                        }
            except Exception as e:
                detector_status[name] = {
                    "status": "unreachable",
                    "error": str(e),
                    "endpoint": endpoint
                }
        
        # Gesamt-Status: healthy wenn mindestens ein Detektor erreichbar ist
        healthy_count = sum(1 for s in detector_status.values() if s.get("status") == "healthy")
        overall_status = "healthy" if healthy_count > 0 else "degraded"
        
        return {
            "status": overall_status,
            "detectors": detector_status,
            "router_version": "1.0.0-alpha",
            "healthy_detectors": healthy_count,
            "total_detectors": len(detector_status)
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return {
            "status": "unhealthy",
            "error": str(e)
        }

