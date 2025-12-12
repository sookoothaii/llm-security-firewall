"""
FastAPI Main Application
========================

Main FastAPI application for Code Intent Detection Service.
Uses the new Hexagonal Architecture with Application Service.

Creator: Hexagonal Architecture Migration
Date: 2025-12-10
License: MIT
"""

import sys
import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Add project root src directory to path
service_dir = Path(__file__).parent.parent
project_root = service_dir.parent.parent
detectors_dir = service_dir.parent  # detectors/ directory
src_path = project_root / "src"
sys.path.insert(0, str(src_path))
sys.path.insert(0, str(detectors_dir))  # Add detectors/ to path for shared imports
sys.path.insert(0, str(service_dir))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import controllers
from api.controllers import code_intent_controller

# Import routes
from api.routes import health, feedback

# Import shared middleware
from shared.api.middleware import LoggingMiddleware, ErrorHandlerMiddleware
from fastapi.exceptions import RequestValidationError

# FastAPI App
app = FastAPI(
    title="LLM Firewall Code Intent Detection API",
    description="Real-time detection of malicious code intents in LLM interactions using Hexagonal Architecture",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In Produktion einschränken!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared Logging Middleware
app.add_middleware(LoggingMiddleware)

# Shared Error Handlers
app.add_exception_handler(
    RequestValidationError,
    ErrorHandlerMiddleware.validation_exception_handler
)
app.add_exception_handler(
    Exception,
    ErrorHandlerMiddleware.general_exception_handler
)

# Include routers
app.include_router(code_intent_controller.router)
app.include_router(health.router)
app.include_router(feedback.router)


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "LLM Firewall Code Intent Detection",
        "version": "1.0.0",
        "architecture": "Hexagonal Architecture",
        "endpoints": {
            "detect": "POST /api/v1/detect",
            "health": "GET /api/v1/health",
            "health_repositories": "GET /api/v1/health/repositories",
            "health_redis": "GET /api/v1/health/redis",
            "health_postgres": "GET /api/v1/health/postgres",
            "feedback_stats": "GET /api/v1/feedback/stats",
            "feedback_high_risk": "GET /api/v1/feedback/high-risk",
            "feedback_false_positives": "GET /api/v1/feedback/false-positives",
            "feedback_false_negatives": "GET /api/v1/feedback/false-negatives",
            "feedback_samples": "GET /api/v1/feedback/samples",
            "info": "GET /api/v1/info",
            "docs": "GET /docs",
            "redoc": "GET /redoc"
        },
        "status": "operational"
    }


@app.on_event("startup")
async def startup_event():
    """Initialize service on startup."""
    logger.info("=" * 60)
    logger.info("LLM Firewall Code Intent Detection API")
    logger.info("Version: 1.0.0")
    logger.info("Architecture: Hexagonal Architecture")
    logger.info("=" * 60)
    logger.info("Service starting up...")
    
    # Pre-initialize detection service (warm-up)
    try:
        from api.controllers.code_intent_controller import get_detection_service
        from infrastructure.app.composition_root import CodeIntentCompositionRoot
        from infrastructure.config.settings import DetectionSettings
        import threading
        
        service = get_detection_service()
        logger.info("✓ Detection Service initialized")
        
        # Warm-up test
        result = service.detect("Hello, how are you?")
        logger.info(f"✓ Warm-up test successful (method: {result.risk_score.source})")
        
        # Initialize Online Learning if enabled
        try:
            settings = DetectionSettings()
            if settings.enable_online_learning and settings.enable_feedback_collection:
                composition = CodeIntentCompositionRoot(settings=settings)
                background_learner = composition.create_background_learner()
                
                if background_learner:
                    # Start background learning in separate thread
                    learning_thread = threading.Thread(
                        target=background_learner.start,
                        daemon=True,
                        name="OnlineLearningThread"
                    )
                    learning_thread.start()
                    logger.info("✓ Online learning background thread started")
                else:
                    logger.info("Online learning not available (model or repository not ready)")
        except Exception as e:
            logger.warning(f"Failed to start online learning: {e}")
            # Don't fail startup if online learning fails
        
    except Exception as e:
        logger.error(f"⚠️  Service initialization warning: {e}")
    
    logger.info("✓ API ready to accept requests")
    logger.info("=" * 60)


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Service shutting down...")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

