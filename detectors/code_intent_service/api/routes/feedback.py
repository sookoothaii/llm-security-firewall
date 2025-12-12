"""
Feedback Analytics Routes
=========================

API endpoints for feedback statistics and analytics.

Creator: Production Integration
Date: 2025-12-10
License: MIT
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, Query

from infrastructure.app.composition_root import CodeIntentCompositionRoot
from domain.services.ports import FeedbackRepositoryPort

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/feedback", tags=["feedback"])


def get_feedback_repository() -> FeedbackRepositoryPort:
    """Get feedback repository from composition root."""
    composition = CodeIntentCompositionRoot()
    return composition.create_feedback_repository()


@router.get("/stats")
async def get_feedback_stats(
    feedback_repo: FeedbackRepositoryPort = Depends(get_feedback_repository)
) -> Dict[str, Any]:
    """
    Get overall feedback statistics.
    
    Returns:
        Dict with total samples, block rate, false positives/negatives, etc.
    """
    try:
        stats = feedback_repo.get_statistics()
        
        # Handle hybrid repository stats structure
        if isinstance(stats, dict) and "combined" in stats:
            combined = stats["combined"]
            return {
                "total_samples": combined.get("total_samples", 0),
                "blocked_samples": combined.get("blocked_samples", 0),
                "allowed_samples": combined.get("allowed_samples", 0),
                "block_rate": combined.get("block_rate", 0.0),
                "avg_score": combined.get("avg_score", 0.0),
                "false_positives": combined.get("false_positives", 0),
                "false_negatives": combined.get("false_negatives", 0),
                "repositories": {
                    "redis": stats.get("redis", {}),
                    "postgres": stats.get("postgres", {}),
                    "memory": stats.get("memory", {})
                }
            }
        else:
            # Single repository stats
            return {
                "total_samples": stats.get("total_samples", 0),
                "blocked_samples": stats.get("blocked_samples", 0),
                "allowed_samples": stats.get("allowed_samples", 0),
                "block_rate": stats.get("block_rate", 0.0),
                "avg_score": stats.get("avg_score", 0.0),
                "false_positives": stats.get("false_positives", 0),
                "false_negatives": stats.get("false_negatives", 0),
                "repository_type": type(feedback_repo).__name__
            }
        
    except Exception as e:
        logger.error(f"Failed to get feedback stats: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get statistics: {str(e)}"
        )


@router.get("/high-risk")
async def get_high_risk_samples(
    threshold: float = Query(0.7, ge=0.0, le=1.0, description="Minimum risk score"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of samples"),
    feedback_repo: FeedbackRepositoryPort = Depends(get_feedback_repository)
) -> Dict[str, Any]:
    """
    Get high-risk feedback samples.
    
    Args:
        threshold: Minimum risk score (0.0-1.0)
        limit: Maximum number of samples to return (1-1000)
    
    Returns:
        Dict with high-risk samples
    """
    try:
        from infrastructure.repositories.hybrid_feedback_repository import HybridFeedbackRepository
        
        if isinstance(feedback_repo, HybridFeedbackRepository):
            samples = feedback_repo.get_high_risk_samples(threshold, limit)
        elif hasattr(feedback_repo, "get_high_risk_samples"):
            samples = feedback_repo.get_high_risk_samples(threshold, limit)
        else:
            # Fallback: filter from all samples
            all_samples = feedback_repo.get_samples(limit * 2)
            samples = [
                s for s in all_samples 
                if s.get("final_score", 0.0) >= threshold
            ][:limit]
        
        return {
            "count": len(samples),
            "threshold": threshold,
            "samples": samples
        }
        
    except Exception as e:
        logger.error(f"Failed to get high-risk samples: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get high-risk samples: {str(e)}"
        )


@router.get("/false-positives")
async def get_false_positives(
    limit: int = Query(1000, ge=1, le=10000, description="Maximum number of samples"),
    feedback_repo: FeedbackRepositoryPort = Depends(get_feedback_repository)
) -> Dict[str, Any]:
    """
    Get false positive samples for model retraining.
    
    Args:
        limit: Maximum number of samples to return (1-10000)
    
    Returns:
        Dict with false positive samples
    """
    try:
        from infrastructure.repositories.hybrid_feedback_repository import HybridFeedbackRepository
        
        if isinstance(feedback_repo, HybridFeedbackRepository):
            samples = feedback_repo.get_false_positives(limit)
        elif hasattr(feedback_repo, "get_false_positives"):
            samples = feedback_repo.get_false_positives(limit)
        else:
            # Fallback: filter from all samples
            all_samples = feedback_repo.get_samples(limit * 2)
            samples = [
                s for s in all_samples 
                if s.get("is_false_positive", False)
            ][:limit]
        
        return {
            "count": len(samples),
            "samples": samples
        }
        
    except Exception as e:
        logger.error(f"Failed to get false positives: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get false positives: {str(e)}"
        )


@router.get("/false-negatives")
async def get_false_negatives(
    limit: int = Query(1000, ge=1, le=10000, description="Maximum number of samples"),
    feedback_repo: FeedbackRepositoryPort = Depends(get_feedback_repository)
) -> Dict[str, Any]:
    """
    Get false negative samples for model retraining.
    
    Args:
        limit: Maximum number of samples to return (1-10000)
    
    Returns:
        Dict with false negative samples
    """
    try:
        from infrastructure.repositories.hybrid_feedback_repository import HybridFeedbackRepository
        
        if isinstance(feedback_repo, HybridFeedbackRepository):
            samples = feedback_repo.get_false_negatives(limit)
        elif hasattr(feedback_repo, "get_false_negatives"):
            samples = feedback_repo.get_false_negatives(limit)
        else:
            # Fallback: filter from all samples
            all_samples = feedback_repo.get_samples(limit * 2)
            samples = [
                s for s in all_samples 
                if s.get("is_false_negative", False)
            ][:limit]
        
        return {
            "count": len(samples),
            "samples": samples
        }
        
    except Exception as e:
        logger.error(f"Failed to get false negatives: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get false negatives: {str(e)}"
        )


@router.get("/samples")
async def get_samples(
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of samples"),
    feedback_repo: FeedbackRepositoryPort = Depends(get_feedback_repository)
) -> Dict[str, Any]:
    """
    Get recent feedback samples.
    
    Args:
        limit: Maximum number of samples to return (1-1000)
    
    Returns:
        Dict with recent samples
    """
    try:
        samples = feedback_repo.get_samples(limit)
        
        return {
            "count": len(samples),
            "samples": samples
        }
        
    except Exception as e:
        logger.error(f"Failed to get samples: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get samples: {str(e)}"
        )


@router.post("/submit")
async def submit_feedback(
    feedback_data: Dict[str, Any],
    feedback_repo: FeedbackRepositoryPort = Depends(get_feedback_repository)
) -> Dict[str, Any]:
    """
    Submit feedback sample for learning.
    
    Args:
        feedback_data: Feedback sample with:
            - text: Input text
            - correct_label: Correct label (0=benign, 1=malicious)
            - original_prediction: Original prediction score
            - feedback_type: "false_positive", "false_negative", or "correction"
            - metadata: Optional metadata dict
    
    Returns:
        Dict with submission status
    """
    try:
        # Extrahiere Daten
        text = feedback_data.get("text", "")
        correct_label = feedback_data.get("correct_label", 0)
        original_prediction = feedback_data.get("original_prediction", 0.0)
        feedback_type = feedback_data.get("feedback_type", "correction")
        metadata = feedback_data.get("metadata", {})
        
        if not text:
            raise HTTPException(status_code=400, detail="text is required")
        
        # Erstelle Feedback Sample
        sample = {
            "text": text[:1000],  # Limit text length
            "correct_label": correct_label,
            "original_prediction": original_prediction,
            "feedback_type": feedback_type,
            "is_false_positive": feedback_type == "false_positive",
            "is_false_negative": feedback_type == "false_negative",
            "blocked": correct_label == 1,  # 1 = malicious = should be blocked
            "final_score": 1.0 if correct_label == 1 else 0.0,  # Set score based on correct label
            "rule_score": 1.0 if correct_label == 1 else 0.0,
            "ml_score": 1.0 if correct_label == 1 else 0.0,
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                **metadata,
                "source": "manual_feedback",
                "submitted_at": datetime.now().isoformat()
            }
        }
        
        # Füge Sample hinzu
        feedback_repo.add(sample)
        
        logger.info(f"Feedback submitted: type={feedback_type}, text={text[:50]}...")
        
        return {
            "status": "success",
            "message": "Feedback submitted successfully",
            "feedback_type": feedback_type,
            "text_preview": text[:50]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit feedback: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to submit feedback: {str(e)}"
        )
