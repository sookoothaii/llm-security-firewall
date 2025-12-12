"""
Health Check Routes
"""
from fastapi import APIRouter
from datetime import datetime

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "learning_monitor",
        "timestamp": datetime.now().isoformat()
    }

