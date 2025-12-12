"""
Health Check Routes
"""
from fastapi import APIRouter

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "content_safety",
        "version": "1.0.0"
    }

