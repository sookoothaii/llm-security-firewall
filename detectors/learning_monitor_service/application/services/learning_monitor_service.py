"""
Learning Monitor Service Implementation

Application service that orchestrates monitoring of multiple services.
"""
import logging
from typing import Dict, List, Optional
from datetime import datetime

# Import domain ports
from domain.ports import (
    ServiceMonitorPort,
    AlertAnalyzerPort,
    WebSocketManagerPort,
    HistoryRepositoryPort
)
from domain.value_objects import ServiceStatus, Alert

logger = logging.getLogger(__name__)


class LearningMonitorService:
    """
    Learning monitor service implementation.
    
    Orchestrates:
    1. Health checks for multiple services
    2. Alert generation based on metrics
    3. WebSocket broadcasting
    4. History tracking
    """
    
    def __init__(
        self,
        service_monitor: ServiceMonitorPort,
        alert_analyzer: AlertAnalyzerPort,
        websocket_manager: WebSocketManagerPort,
        history_repository: HistoryRepositoryPort,
    ):
        """
        Initialize learning monitor service.
        
        Args:
            service_monitor: Port for checking service health
            alert_analyzer: Port for generating alerts
            websocket_manager: Port for managing WebSocket connections
            history_repository: Port for storing history
        """
        self.service_monitor = service_monitor
        self.alert_analyzer = alert_analyzer
        self.websocket_manager = websocket_manager
        self.history_repository = history_repository
        logger.info("LearningMonitorService initialized")
    
    async def check_all_services(
        self,
        monitored_services: Dict[str, Dict]
    ) -> Dict[str, ServiceStatus]:
        """
        Check health and status of all monitored services.
        
        Args:
            monitored_services: Dictionary of service_id -> service_config
                Each config should have: "name", "url", "enabled"
            
        Returns:
            Dictionary of service_id -> ServiceStatus
        """
        results = {}
        
        for service_id, service_config in monitored_services.items():
            if not service_config.get("enabled", False):
                continue
            
            service_url = service_config["url"]
            service_name = service_config.get("name", service_id)
            
            try:
                status = await self.service_monitor.check_service_health(
                    service_id=service_id,
                    service_url=service_url
                )
                
                if status:
                    results[service_id] = status
                else:
                    # Service unreachable - create unhealthy status
                    results[service_id] = ServiceStatus(
                        service_id=service_id,
                        service_name=service_name,
                        is_healthy=False,
                        feedback_enabled=False,
                        error="Service unreachable"
                    )
                    
            except Exception as e:
                logger.error(f"Error checking service {service_id}: {e}")
                results[service_id] = ServiceStatus(
                    service_id=service_id,
                    service_name=service_name,
                    is_healthy=False,
                    feedback_enabled=False,
                    error=str(e)
                )
        
        return results
    
    async def collect_status_and_alerts(
        self,
        monitored_services: Dict[str, Dict]
    ) -> tuple[Dict[str, ServiceStatus], List[Alert]]:
        """
        Collect service statuses and generate alerts.
        
        Args:
            monitored_services: Dictionary of service_id -> service_config
            
        Returns:
            Tuple of (service_statuses_dict, alerts_list)
        """
        # Check all services
        service_statuses = await self.check_all_services(monitored_services)
        
        # Generate alerts
        alerts = self.alert_analyzer.evaluate_alerts(service_statuses)
        
        # Store in history
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "services": {
                sid: {
                    "status": status.is_healthy,
                    "feedback_enabled": status.feedback_enabled,
                    "buffer_size": status.buffer_size,
                    "max_size": status.max_size,
                }
                for sid, status in service_statuses.items()
            },
            "alerts": [
                {
                    "severity": alert.severity,
                    "type": alert.alert_type,
                    "message": alert.message,
                }
                for alert in alerts
            ],
            "alert_count": len(alerts)
        }
        self.history_repository.add_entry(history_entry)
        
        return service_statuses, alerts
    
    async def broadcast_update(
        self,
        monitored_services: Dict[str, Dict]
    ) -> None:
        """
        Collect status, generate alerts, and broadcast via WebSocket.
        
        Args:
            monitored_services: Dictionary of service_id -> service_config
        """
        service_statuses, alerts = await self.collect_status_and_alerts(monitored_services)
        
        # Prepare update data
        update_data = {
            "timestamp": datetime.now().isoformat(),
            "services": {
                sid: {
                    "service_id": status.service_id,
                    "service_name": status.service_name,
                    "status": "healthy" if status.is_healthy else "unhealthy",
                    "feedback_enabled": status.feedback_enabled,
                    "buffer_size": status.buffer_size,
                    "max_size": status.max_size,
                    "online_learning": status.online_learning,
                    "statistics": status.statistics,
                    "error": status.error,
                }
                for sid, status in service_statuses.items()
            },
            "alerts": [
                {
                    "severity": alert.severity,
                    "service": alert.service_id,
                    "type": alert.alert_type,
                    "message": alert.message,
                    "value": alert.value,
                    "timestamp": alert.timestamp.isoformat(),
                }
                for alert in alerts
            ]
        }
        
        # Broadcast to all WebSocket connections
        await self.websocket_manager.broadcast(update_data)

