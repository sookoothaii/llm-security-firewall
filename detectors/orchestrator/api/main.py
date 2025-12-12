"""
Orchestrator Service - FastAPI Main

Hierarchical Router for Detector Services.
"""
import sys
import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError

# Add project root src directory to path
service_dir = Path(__file__).parent.parent
project_root = service_dir.parent.parent.parent
detectors_dir = service_dir.parent.parent
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
from api.routes import router
from api.routes import learning
from api.routes import monitoring

# Import shared middleware
from shared.api.middleware.logging_middleware import LoggingMiddleware
from shared.api.middleware.error_handler import ErrorHandlerMiddleware

# FastAPI App
app = FastAPI(
    title="LLM Firewall Orchestrator",
    description="Hierarchical Router for Detector Services",
    version="1.0.0-alpha",
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
app.include_router(router.router)
app.include_router(learning.router)  # Phase 5.3: Learning endpoints
app.include_router(monitoring.router)  # Phase 5.4: Monitoring endpoints


@app.get("/")
async def root():
    """Root endpoint with service information."""
    return {
        "service": "LLM Firewall Orchestrator",
        "version": "1.0.0-alpha",
        "architecture": "Hexagonal Architecture with Shared Components",
        "endpoints": {
            "route_and_detect": "POST /api/v1/route-and-detect",
            "health": "GET /api/v1/health",
            "metrics": "GET /api/v1/metrics",
            "alerts": "GET /api/v1/alerts",
            "dashboard": "GET /api/v1/dashboard",
            "learning_metrics": "GET /api/v1/learning/metrics",
            "learning_optimization": "POST /api/v1/learning/trigger-optimization",
            "docs": "GET /docs"
        }
    }


@app.get("/health")
async def health():
    """Simple health check endpoint."""
    return {"status": "healthy", "service": "orchestrator"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

