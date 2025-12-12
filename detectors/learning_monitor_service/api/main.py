"""
Learning Monitor Service - FastAPI Main
===============================================

Optionaler Service für erweiterte Learning-Monitoring-Features.
FastAPI microservice using Hexagonal Architecture with Shared Components.

Creator: HAK_GAL (Joerg Bollwahn)
Date: 2025-12-11
Status: Phase 4 - Migration to Shared Components (Option A: Monitoring Service)
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
from api.routes import health, monitoring, websocket, dashboard

# Import shared middleware
from shared.api.middleware import LoggingMiddleware, ErrorHandlerMiddleware
from fastapi.exceptions import RequestValidationError

# FastAPI App
app = FastAPI(
    title="Learning Monitor Service",
    description="Optionaler Service für erweiterte Learning-Monitoring-Features using Hexagonal Architecture",
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
app.include_router(monitoring.router)
app.include_router(websocket.router)
app.include_router(dashboard.router)


@app.get("/")
async def root():
    """Root endpoint mit Service-Info."""
    return {
        "service": "learning_monitor",
        "version": "1.0.0",
        "description": "Optionaler Service für erweiterte Learning-Monitoring-Features",
        "architecture": "Hexagonal Architecture with Shared Components (Monitoring Service)",
        "endpoints": {
            "/health": "Health check",
            "/status": "Status aller überwachten Services",
            "/alerts": "Aktuelle Alerts",
            "/history": "Learning-History",
            "/dashboard": "HTML Dashboard",
            "/ws": "WebSocket für Live-Updates"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)

