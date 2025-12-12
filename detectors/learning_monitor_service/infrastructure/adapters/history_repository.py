"""
History Repository Adapter

Implements HistoryRepositoryPort for storing monitoring history.
"""
import logging
from typing import Dict, List

from domain.ports import HistoryRepositoryPort

logger = logging.getLogger(__name__)


class InMemoryHistoryRepository(HistoryRepositoryPort):
    """
    In-memory history repository.
    
    Stores monitoring history in memory with size limit.
    This is a stateful adapter - history is stored in memory.
    """
    
    def __init__(self, max_size: int = 1000):
        """
        Initialize history repository.
        
        Args:
            max_size: Maximum number of history entries to keep
        """
        self.history: List[Dict] = []
        self.max_size = max_size
        logger.info(f"InMemoryHistoryRepository initialized (max_size: {max_size})")
    
    def add_entry(self, entry: Dict) -> None:
        """Add an entry to history"""
        self.history.append(entry)
        
        # Trim history if exceeds max size
        if len(self.history) > self.max_size:
            self.history = self.history[-self.max_size:]
            logger.debug(f"History trimmed to {self.max_size} entries")
    
    def get_history(self, limit: int = 100) -> List[Dict]:
        """
        Get recent history entries.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of history entries (most recent first)
        """
        return self.history[-limit:]
    
    def clear_history(self) -> None:
        """Clear all history"""
        self.history.clear()
        logger.info("History cleared")

