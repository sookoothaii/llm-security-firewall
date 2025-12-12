"""
Memory Feedback Repository - Orchestrator

Einfache In-Memory Implementierung für FeedbackRepositoryPort.
Für Tests und Fallback, wenn Redis/PostgreSQL nicht verfügbar sind.
"""

import logging
from collections import deque
from typing import Dict, Any, List, Optional
from datetime import datetime

# Import shared FeedbackRepositoryPort
import sys
from pathlib import Path
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

from shared.domain.ports import FeedbackRepositoryPort

logger = logging.getLogger(__name__)


class MemoryFeedbackRepository(FeedbackRepositoryPort):
    """
    In-memory Feedback Repository mit Ring Buffer.
    
    Einfache Implementierung für Tests und Fallback.
    """

    def __init__(self, max_size: int = 10000):
        """
        Initialize memory feedback repository.
        
        Args:
            max_size: Maximum number of samples to store
        """
        self.buffer = deque(maxlen=max_size)
        logger.info(f"MemoryFeedbackRepository initialized (max_size={max_size})")

    def add(self, sample: Dict[str, Any]) -> None:
        """
        Add feedback sample to repository.
        
        Args:
            sample: Feedback sample dict with text, scores, etc.
        """
        try:
            # Ensure ID and timestamp
            if "id" not in sample:
                import uuid
                sample["id"] = str(uuid.uuid4())
            
            if "timestamp" not in sample:
                sample["timestamp"] = datetime.utcnow().isoformat()
            
            self.buffer.append(sample)
            logger.debug(f"Feedback sample added: {sample.get('id', 'unknown')}")
        except Exception as e:
            logger.error(f"Failed to add feedback sample: {e}")

    def get_samples(
        self,
        detector_name: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get feedback samples for training.
        
        Args:
            detector_name: Optional filter by detector name
            limit: Maximum number of samples to return
            
        Returns:
            List of feedback sample dicts
        """
        try:
            samples = list(self.buffer)
            
            # Filter by detector_name if specified
            if detector_name:
                samples = [
                    s for s in samples
                    if s.get("detector_name") == detector_name or
                       s.get("context", {}).get("detector_name") == detector_name
                ]
            
            # Sort by timestamp (newest first) and limit
            samples.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            return samples[:limit]
        except Exception as e:
            logger.error(f"Failed to get samples: {e}")
            return []

