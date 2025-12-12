"""
Base Detection Response Model

Common response model for all detector services.
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List


class BaseDetectionResponse(BaseModel):
    """
    Base response model for detection endpoints.
    
    All detector services should use this or extend it.
    """
    
    success: bool = Field(..., description="Whether the request was successful")
    data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Detection result data"
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if success is False"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "data": {
                    "detector_name": "code_intent",
                    "is_malicious": False,
                    "risk_score": 0.0,
                    "confidence": 1.0,
                    "is_blocked": False,
                    "matched_patterns": [],
                    "metadata": {
                        "processing_time_ms": 5.2,
                        "method": "benign_validator"
                    }
                },
                "error": None
            }
        }


class DetectionData(BaseModel):
    """
    Standard detection data structure.
    """
    
    detector_name: str = Field(..., description="Name of the detector service")
    is_malicious: bool = Field(..., description="Whether the text is malicious")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Risk score (0.0-1.0)")
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence level (0.0-1.0)"
    )
    is_blocked: bool = Field(..., description="Whether the request should be blocked")
    category: Optional[str] = Field(
        default=None,
        description="Threat category (e.g., 'cybercrime', 'misinformation')"
    )
    matched_patterns: List[str] = Field(
        default_factory=list,
        description="List of matched pattern names"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional processing metadata"
    )

