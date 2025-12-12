"""
Base Detection Request Model

Common request model for all detector services.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any


class BaseDetectionRequest(BaseModel):
    """
    Base request model for detection endpoints.
    
    All detector services should use this or extend it.
    """
    
    text: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Text to analyze for malicious patterns"
    )
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional context (user_id, session_id, tools, etc.)"
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Optional session identifier"
    )
    user_id: Optional[str] = Field(
        default=None,
        description="Optional user identifier"
    )
    
    @field_validator('text')
    @classmethod
    def validate_text(cls, v: str) -> str:
        """Validate text is not empty"""
        if not v or not v.strip():
            raise ValueError("Text cannot be empty")
        return v.strip()
    
    class Config:
        json_schema_extra = {
            "example": {
                "text": "What does the ls command do?",
                "context": {
                    "user_id": "user123",
                    "session_id": "session456",
                    "tools": ["vm_shell"]
                }
            }
        }

