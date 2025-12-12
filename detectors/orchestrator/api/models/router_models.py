"""
Router API Models

Request/Response models for orchestrator endpoints.
"""
import sys
from pathlib import Path
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any

# Add detectors directory to path for shared imports
# This needs to be done before importing shared modules
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

# Import shared models
from shared.api.models.base_request import BaseDetectionRequest


class RouterRequest(BaseDetectionRequest):
    """Erweiterter Request für den Router."""
    source_tool: Optional[str] = Field(
        default=None,
        description="Source tool identifier (e.g., 'code_interpreter', 'web_search')"
    )
    user_risk_tier: Optional[int] = Field(
        default=1,
        ge=1,
        le=3,
        description="User risk tier (1=low, 2=medium, 3=high)"
    )
    session_risk_score: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Cumulative session risk score"
    )


class DetectorResultResponse(BaseModel):
    """Response für einzelnes Detektor-Ergebnis."""
    success: bool
    score: Optional[float] = None
    blocked: bool
    processing_time_ms: float
    error: Optional[str] = None


class RouterResponse(BaseModel):
    """Response für Router-Endpoint."""
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None

