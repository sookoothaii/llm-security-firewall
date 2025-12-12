"""
Code Intent Detection API Controller
=====================================

FastAPI controller for code intent detection using the new Application Service.

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import logging
import uuid
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends

from api.models.request_models import DetectionRequest
from api.models.response_models import DetectionResponse, HealthResponse
from domain.services.ports import DetectionServicePort
from infrastructure.app.composition_root import CodeIntentCompositionRoot

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["detection"])


# Singleton instance for dependency injection
_detection_service: Optional[DetectionServicePort] = None


def get_detection_service() -> DetectionServicePort:
    """
    Factory für Detection Service (singleton pattern).
    
    Returns:
        DetectionServicePort instance
    """
    global _detection_service
    
    if _detection_service is None:
        logger.info("Creating Detection Service instance...")
        composition = CodeIntentCompositionRoot()
        _detection_service = composition.create_detection_service()
        logger.info("Detection Service created successfully")
    
    return _detection_service


@router.post("/detect", response_model=DetectionResponse)
async def detect_code_intent(
    request: DetectionRequest,
    detection_service: DetectionServicePort = Depends(get_detection_service)
):
    """
    Analysiert Text auf bösartige Code-Intents.
    
    - **text**: Zu analysierender Text (1-10.000 Zeichen)
    - **context**: Optionaler Kontext (Tool-Auswahl, Session-Daten)
    - **session_id**: Session-ID für Tracking (optional, wird automatisch generiert wenn nicht übergeben)
    - **user_id**: User-ID für personalisierte Modelle (optional)
    
    Returns:
        - risk_score: 0.0-1.0
        - blocked: True/False
        - matched_patterns: Liste erkannten Patterns
        - metadata.session_id: Session-ID (auto-generiert oder übergeben)
    """
    try:
        # Auto-generate session_id if not provided
        session_id = request.session_id
        if not session_id:
            session_id = str(uuid.uuid4())
            logger.debug(f"Auto-generated session_id: {session_id}")
        
        # Logging
        logger.info(
            f"Detection request: session_id={session_id}, "
            f"user_id={request.user_id}, text: {request.text[:50]}..."
        )
        
        # Context zusammenbauen
        context = request.context or {}
        context["session_id"] = session_id  # Immer setzen (auto-generiert oder übergeben)
        if request.user_id:
            context["user_id"] = request.user_id
        
        # Detection durchführen
        result = detection_service.detect(request.text, context)
        
        # Response erstellen (Session-ID in Metadaten aufnehmen)
        response_metadata = result.metadata.copy() if result.metadata else {}
        response_metadata["session_id"] = session_id
        if request.user_id:
            response_metadata["user_id"] = request.user_id
        
        return DetectionResponse(
            success=True,
            data={
                "is_malicious": result.blocked,
                "risk_score": result.risk_score.value,
                "confidence": result.risk_score.confidence or 0.0,
                "method": result.risk_score.source or "unknown",
                "matched_patterns": result.matched_patterns,
                "should_block": result.blocked,
                "metadata": response_metadata
            }
        )
        
    except Exception as e:
        logger.error(f"Detection failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Detection failed: {str(e)}"
        )


@router.get("/health", response_model=HealthResponse)
async def health_check(
    detection_service: DetectionServicePort = Depends(get_detection_service)
):
    """
    Health Check Endpoint.
    
    Testet alle Komponenten des Detection Service.
    """
    try:
        # Teste mit benignem Text
        result = detection_service.detect("Hello, how are you?")
        
        # Prüfe Komponenten-Status
        ml_available = result.metadata.get("ml_method") is not None
        
        return HealthResponse(
            status="healthy",
            components={
                "detection_service": "operational",
                "benign_validator": "operational",
                "ml_classifier": "available" if ml_available else "unavailable",
                "rule_engine": "operational" if result.metadata.get("rule_score") is not None else "unavailable"
            },
            version="1.0.0"
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=503,
            detail=f"Service unhealthy: {str(e)}"
        )


@router.get("/info")
async def service_info():
    """
    Service Information Endpoint.
    
    Gibt Informationen über den Service zurück.
    """
    return {
        "service": "LLM Firewall Code Intent Detection API",
        "version": "1.0.0",
        "architecture": "Hexagonal Architecture",
        "endpoints": {
            "detect": "POST /api/v1/detect",
            "health": "GET /api/v1/health",
            "info": "GET /api/v1/info"
        },
        "features": [
            "Benign Validator (10 validators)",
            "ML Model Adapter (QuantumCNN, CodeBERT, Rule-based)",
            "Rule Engine (pattern matching)",
            "Feedback Collection",
            "GPU Acceleration (RTX 3080Ti)"
        ]
    }

