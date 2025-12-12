"""
WebSocket Manager Adapter

Implements WebSocketManagerPort for managing WebSocket connections.
"""
import logging
from typing import Dict, List
from fastapi import WebSocket

from domain.ports import WebSocketManagerPort

logger = logging.getLogger(__name__)


class InMemoryWebSocketManager(WebSocketManagerPort):
    """
    In-memory WebSocket manager.
    
    Manages WebSocket connections and broadcasts updates.
    This is a stateful adapter - connections are stored in memory.
    """
    
    def __init__(self):
        """Initialize WebSocket manager"""
        self.connections: List[WebSocket] = []
        logger.info("InMemoryWebSocketManager initialized")
    
    def add_connection(self, websocket: WebSocket) -> None:
        """Add a WebSocket connection"""
        if websocket not in self.connections:
            self.connections.append(websocket)
            logger.info(f"WebSocket connection added (total: {len(self.connections)})")
    
    def remove_connection(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection"""
        if websocket in self.connections:
            self.connections.remove(websocket)
            logger.info(f"WebSocket connection removed (total: {len(self.connections)})")
    
    async def broadcast(self, data: Dict) -> None:
        """
        Broadcast data to all connected WebSockets.
        
        Args:
            data: Dictionary to send as JSON
        """
        disconnected = []
        
        for connection in self.connections:
            try:
                await connection.send_json(data)
            except Exception as e:
                logger.warning(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(connection)
        
        # Remove disconnected connections
        for connection in disconnected:
            self.remove_connection(connection)
    
    def get_connection_count(self) -> int:
        """Get number of active connections"""
        return len(self.connections)

