"""
Health Check Routes
===================

API endpoints for health checks and repository status monitoring.

Creator: Production Integration
Date: 2025-12-10
License: MIT
"""

import logging
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Depends

from infrastructure.app.composition_root import CodeIntentCompositionRoot
from domain.services.ports import FeedbackRepositoryPort

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/health", tags=["health"])


def get_feedback_repository() -> FeedbackRepositoryPort:
    """Get feedback repository from composition root."""
    composition = CodeIntentCompositionRoot()
    return composition.create_feedback_repository()


@router.get("/repositories")
async def check_repositories(
    feedback_repo: FeedbackRepositoryPort = Depends(get_feedback_repository)
) -> Dict[str, Any]:
    """
    Check health status of all feedback repositories.
    
    Returns:
        Dict with status of Redis, PostgreSQL, and Hybrid repository
    """
    try:
        status = {
            "redis": {"status": "unknown", "error": None},
            "postgres": {"status": "unknown", "error": None},
            "hybrid": {"status": "unknown", "error": None},
            "overall": "unknown"
        }
        
        # Check if it's a Hybrid repository
        from infrastructure.repositories.hybrid_feedback_repository import HybridFeedbackRepository
        
        if isinstance(feedback_repo, HybridFeedbackRepository):
            status["hybrid"]["status"] = "available"
            
            # Check Redis
            if feedback_repo.redis:
                try:
                    # Try to get statistics (tests connection)
                    stats = feedback_repo.redis.get_statistics()
                    status["redis"] = {
                        "status": "operational",
                        "host": stats.get("redis_host", "unknown"),
                        "port": stats.get("redis_port", "unknown"),
                        "samples": stats.get("total_samples", 0),
                        "memory_used": stats.get("redis_memory_used", "N/A")
                    }
                except Exception as e:
                    status["redis"] = {
                        "status": "error",
                        "error": str(e)
                    }
            else:
                status["redis"] = {"status": "not_configured"}
            
            # Check PostgreSQL
            if feedback_repo.postgres:
                try:
                    # Try to get statistics (tests connection)
                    stats = feedback_repo.postgres.get_statistics()
                    status["postgres"] = {
                        "status": "operational",
                        "samples": stats.get("total_samples", 0),
                        "database": stats.get("database", "PostgreSQL")
                    }
                except Exception as e:
                    status["postgres"] = {
                        "status": "error",
                        "error": str(e)
                    }
            else:
                status["postgres"] = {"status": "not_configured"}
            
            # Check Memory
            if feedback_repo.memory:
                try:
                    stats = feedback_repo.memory.get_statistics()
                    status["memory"] = {
                        "status": "operational",
                        "samples": stats.get("total_samples", 0)
                    }
                except Exception as e:
                    status["memory"] = {
                        "status": "error",
                        "error": str(e)
                    }
            else:
                status["memory"] = {"status": "not_configured"}
            
            # Overall status
            redis_ok = status["redis"]["status"] in ["operational", "not_configured"]
            postgres_ok = status["postgres"]["status"] in ["operational", "not_configured"]
            memory_ok = status.get("memory", {}).get("status") in ["operational", "not_configured"]
            
            if redis_ok and postgres_ok and memory_ok:
                status["overall"] = "healthy"
            elif redis_ok or postgres_ok or memory_ok:
                status["overall"] = "degraded"
            else:
                status["overall"] = "unhealthy"
        
        else:
            # Single repository
            repo_type = type(feedback_repo).__name__
            
            if "Redis" in repo_type:
                try:
                    stats = feedback_repo.get_statistics()
                    status["redis"] = {
                        "status": "operational",
                        "host": stats.get("redis_host", "unknown"),
                        "port": stats.get("redis_port", "unknown"),
                        "samples": stats.get("total_samples", 0)
                    }
                    status["overall"] = "healthy"
                except Exception as e:
                    status["redis"] = {"status": "error", "error": str(e)}
                    status["overall"] = "unhealthy"
            
            elif "Postgres" in repo_type:
                try:
                    stats = feedback_repo.get_statistics()
                    status["postgres"] = {
                        "status": "operational",
                        "samples": stats.get("total_samples", 0)
                    }
                    status["overall"] = "healthy"
                except Exception as e:
                    status["postgres"] = {"status": "error", "error": str(e)}
                    status["overall"] = "unhealthy"
            
            else:
                # Memory or other
                try:
                    stats = feedback_repo.get_statistics()
                    status["memory"] = {
                        "status": "operational",
                        "samples": stats.get("total_samples", 0)
                    }
                    status["overall"] = "healthy"
                except Exception as e:
                    status["memory"] = {"status": "error", "error": str(e)}
                    status["overall"] = "unhealthy"
        
        return status
        
    except Exception as e:
        logger.error(f"Repository health check failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=503,
            detail=f"Health check failed: {str(e)}"
        )


@router.get("/redis")
async def check_redis(
    feedback_repo: FeedbackRepositoryPort = Depends(get_feedback_repository)
) -> Dict[str, Any]:
    """
    Check Redis connection status.
    
    Returns:
        Dict with Redis connection status
    """
    try:
        from infrastructure.repositories.hybrid_feedback_repository import HybridFeedbackRepository
        from infrastructure.repositories.redis_feedback_repository import RedisFeedbackRepository
        
        redis_repo = None
        
        if isinstance(feedback_repo, HybridFeedbackRepository):
            redis_repo = feedback_repo.redis
        elif isinstance(feedback_repo, RedisFeedbackRepository):
            redis_repo = feedback_repo
        
        if not redis_repo:
            return {
                "status": "not_configured",
                "message": "Redis repository not configured"
            }
        
        # Test connection
        stats = redis_repo.get_statistics()
        
        return {
            "status": "operational",
            "host": stats.get("redis_host", "unknown"),
            "port": stats.get("redis_port", "unknown"),
            "samples": stats.get("total_samples", 0),
            "memory_used": stats.get("redis_memory_used", "N/A"),
            "block_rate": stats.get("block_rate", 0.0)
        }
        
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }


@router.get("/postgres")
async def check_postgres(
    feedback_repo: FeedbackRepositoryPort = Depends(get_feedback_repository)
) -> Dict[str, Any]:
    """
    Check PostgreSQL connection status.
    
    Returns:
        Dict with PostgreSQL connection status
    """
    try:
        from infrastructure.repositories.hybrid_feedback_repository import HybridFeedbackRepository
        from infrastructure.repositories.postgres_feedback_repository import PostgresFeedbackRepository
        
        postgres_repo = None
        
        if isinstance(feedback_repo, HybridFeedbackRepository):
            postgres_repo = feedback_repo.postgres
        elif isinstance(feedback_repo, PostgresFeedbackRepository):
            postgres_repo = feedback_repo
        
        if not postgres_repo:
            return {
                "status": "not_configured",
                "message": "PostgreSQL repository not configured"
            }
        
        # Test connection
        stats = postgres_repo.get_statistics()
        
        return {
            "status": "operational",
            "samples": stats.get("total_samples", 0),
            "block_rate": stats.get("block_rate", 0.0),
            "false_positives": stats.get("false_positives", 0),
            "false_negatives": stats.get("false_negatives", 0),
            "database": stats.get("database", "PostgreSQL")
        }
        
    except Exception as e:
        logger.error(f"PostgreSQL health check failed: {e}")
        return {
            "status": "error",
            "error": str(e)
        }

