"""
Content Safety Detector Service - FastAPI Main
===============================================

Detects content safety violations, jailbreak attempts, and policy circumvention.
FastAPI microservice using Hexagonal Architecture with Shared Components.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-11
Status: Phase 4 - Migration to Shared Components
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

# Import routes
from api.routes import health, detection

# Import shared middleware
from shared.api.middleware import LoggingMiddleware, ErrorHandlerMiddleware
from fastapi.exceptions import RequestValidationError

# FastAPI App
app = FastAPI(
    title="Content Safety Detector Service",
    description="Detects content safety violations, jailbreak attempts, and policy circumvention using Hexagonal Architecture",
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
app.include_router(health.router)
app.include_router(detection.router)


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "Content Safety Detector",
        "version": "1.0.0",
        "architecture": "Hexagonal Architecture with Shared Components",
        "endpoints": {
            "detect": "POST /v1/detect",
            "health": "GET /health",
            "info": "GET /info"
        }
    }


@app.get("/info")
async def service_info():
    """Service information."""
    return {
        "name": "content_safety_detector",
        "version": "1.0.0",
        "description": "Detects content safety violations, jailbreak attempts, and policy circumvention",
        "categories": ["jailbreak", "content_violation", "roleplay_bypass"],
        "endpoints": {
            "detect": "POST /v1/detect",
            "health": "GET /health"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)

