"""
Learning Monitor Service Domain Ports

Service-specific ports for monitoring and alerting.
These are NOT detector ports - this is a monitoring service.
"""
from typing import Protocol, runtime_checkable, Dict, List, Optional
from datetime import datetime

# Import domain value objects
from .value_objects import ServiceStatus, Alert, LearningMetrics


@runtime_checkable
class ServiceMonitorPort(Protocol):
    """
    Port for checking the health and status of other services.
    
    This is the core abstraction for monitoring external services.
    """
    
    async def check_service_health(
        self,
        service_id: str,
        service_url: str
    ) -> Optional[ServiceStatus]:
        """
        Check the health and status of a service.
        
        Args:
            service_id: Identifier for the service
            service_url: Base URL of the service (e.g., "http://localhost:8001")
            
        Returns:
            ServiceStatus if service is reachable, None otherwise
        """
        ...


@runtime_checkable
class AlertAnalyzerPort(Protocol):
    """
    Port for analyzing metrics and generating alerts.
    
    Encapsulates alert evaluation logic.
    """
    
    def evaluate_alerts(
        self,
        service_statuses: Dict[str, ServiceStatus]
    ) -> List[Alert]:
        """
        Evaluate service statuses and generate alerts.
        
        Args:
            service_statuses: Dictionary of service_id -> ServiceStatus
            
        Returns:
            List of Alert objects for any alert conditions
        """
        ...


@runtime_checkable
class WebSocketManagerPort(Protocol):
    """
    Port for managing WebSocket connections and broadcasting updates.
    
    Handles stateful WebSocket connections.
    """
    
    def add_connection(self, websocket) -> None:
        """Add a WebSocket connection"""
        ...
    
    def remove_connection(self, websocket) -> None:
        """Remove a WebSocket connection"""
        ...
    
    async def broadcast(self, data: Dict) -> None:
        """Broadcast data to all connected WebSockets"""
        ...
    
    def get_connection_count(self) -> int:
        """Get number of active connections"""
        ...


@runtime_checkable
class HistoryRepositoryPort(Protocol):
    """
    Port for storing and retrieving monitoring history.
    
    Handles stateful history tracking.
    """
    
    def add_entry(self, entry: Dict) -> None:
        """Add an entry to history"""
        ...
    
    def get_history(self, limit: int = 100) -> List[Dict]:
        """Get recent history entries"""
        ...
    
    def clear_history(self) -> None:
        """Clear all history"""
        ...

