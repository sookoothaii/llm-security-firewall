"""
Learning Monitor Service Composition Root

Central place where all adapters are composed and injected.
Extends BaseCompositionRoot for shared infrastructure (logging, error handling).
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

import sys
from pathlib import Path

# Add detectors directory to path for shared imports
service_dir = Path(__file__).parent.parent.parent
detectors_dir = service_dir.parent
if str(detectors_dir) not in sys.path:
    sys.path.insert(0, str(detectors_dir))

# Import Base Composition Root (for shared infrastructure)
from shared.infrastructure.composition import BaseCompositionRoot

# Import domain ports
from domain.ports import (
    ServiceMonitorPort,
    AlertAnalyzerPort,
    WebSocketManagerPort,
    HistoryRepositoryPort
)

# Import application services
from application.services.learning_monitor_service import LearningMonitorService
from application.services.alert_service import AlertService

# Import infrastructure adapters
from infrastructure.adapters.async_http_service_monitor import AsyncHttpServiceMonitorAdapter
from infrastructure.adapters.websocket_manager import InMemoryWebSocketManager
from infrastructure.adapters.history_repository import InMemoryHistoryRepository


class LearningMonitorCompositionRoot(BaseCompositionRoot):
    """
    Composition root for assembling the learning monitor service.
    
    Extends BaseCompositionRoot to inherit shared infrastructure (logging, error handling).
    Adds service-specific components (monitors, alerts, WebSocket, history).
    
    Usage:
        root = LearningMonitorCompositionRoot()
        monitor_service = root.create_monitor_service()
        status, alerts = await monitor_service.collect_status_and_alerts(services)
    """
    
    def __init__(
        self,
        enable_cache: bool = False,  # Not used for monitoring service
        enable_normalization: bool = False,  # Not used for monitoring service
        history_max_size: int = 1000,
        http_timeout: float = 2.0,
    ):
        """
        Initialize composition root.
        
        Args:
            enable_cache: Not used (inherited from BaseCompositionRoot)
            enable_normalization: Not used (inherited from BaseCompositionRoot)
            history_max_size: Maximum history entries to keep
            http_timeout: HTTP request timeout in seconds
        """
        # Initialize base composition root (for shared infrastructure)
        super().__init__(enable_cache=enable_cache, enable_normalization=enable_normalization)
        
        self.history_max_size = history_max_size
        self.http_timeout = http_timeout
        logger.info(
            f"LearningMonitorCompositionRoot initialized "
            f"(extends BaseCompositionRoot, history_max_size: {history_max_size})"
        )
    
    def create_service_monitor(self) -> ServiceMonitorPort:
        """
        Create service monitor adapter.
        
        Returns:
            ServiceMonitorPort implementation
        """
        return AsyncHttpServiceMonitorAdapter(timeout=self.http_timeout)
    
    def create_alert_analyzer(self) -> AlertAnalyzerPort:
        """
        Create alert analyzer adapter.
        
        Returns:
            AlertAnalyzerPort implementation
        """
        return AlertService()
    
    def create_websocket_manager(self) -> WebSocketManagerPort:
        """
        Create WebSocket manager adapter.
        
        Returns:
            WebSocketManagerPort implementation
        """
        return InMemoryWebSocketManager()
    
    def create_history_repository(self) -> HistoryRepositoryPort:
        """
        Create history repository adapter.
        
        Returns:
            HistoryRepositoryPort implementation
        """
        return InMemoryHistoryRepository(max_size=self.history_max_size)
    
    def create_monitor_service(self) -> LearningMonitorService:
        """
        Create learning monitor service with all dependencies.
        
        Returns:
            LearningMonitorService instance with all dependencies injected
        """
        service_monitor = self.create_service_monitor()
        alert_analyzer = self.create_alert_analyzer()
        websocket_manager = self.create_websocket_manager()
        history_repository = self.create_history_repository()
        
        service = LearningMonitorService(
            service_monitor=service_monitor,
            alert_analyzer=alert_analyzer,
            websocket_manager=websocket_manager,
            history_repository=history_repository,
        )
        
        logger.info("LearningMonitorService created with all dependencies")
        return service

