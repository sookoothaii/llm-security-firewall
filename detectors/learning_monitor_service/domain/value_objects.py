"""
Learning Monitor Service Value Objects

Domain value objects for monitoring and alerting.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any


@dataclass(frozen=True)
class ServiceStatus:
    """
    Status of a monitored service.
    
    Immutable value object representing the health and metrics of a service.
    """
    service_id: str
    service_name: str
    is_healthy: bool
    feedback_enabled: bool
    latency_ms: Optional[float] = None
    buffer_size: Optional[int] = None
    max_size: Optional[int] = None
    online_learning: Optional[Dict[str, Any]] = None
    statistics: Optional[Dict[str, Any]] = None
    last_checked: datetime = None
    error: Optional[str] = None
    
    def __post_init__(self):
        """Validate service status"""
        if self.last_checked is None:
            object.__setattr__(self, 'last_checked', datetime.now())


@dataclass(frozen=True)
class Alert:
    """
    Alert for monitoring events.
    
    Immutable value object representing an alert condition.
    """
    severity: str  # "info", "warning", "critical"
    service_id: str
    alert_type: str  # "service_unhealthy", "loss_critical", "loss_warning", "buffer_full"
    message: str
    value: Optional[float] = None  # Optional metric value (e.g., loss value)
    timestamp: datetime = None
    
    def __post_init__(self):
        """Validate alert"""
        if self.severity not in ["info", "warning", "critical"]:
            raise ValueError(f"Invalid severity: {self.severity}")
        if self.timestamp is None:
            object.__setattr__(self, 'timestamp', datetime.now())


@dataclass(frozen=True)
class LearningMetrics:
    """
    Learning metrics for a service.
    
    Immutable value object representing learning statistics.
    """
    service_id: str
    average_loss: float
    updates: int
    buffer_usage: float  # 0.0-1.0
    is_running: bool
    timestamp: datetime = None
    
    def __post_init__(self):
        """Validate metrics"""
        if not 0.0 <= self.buffer_usage <= 1.0:
            raise ValueError(f"Buffer usage must be between 0.0 and 1.0, got {self.buffer_usage}")
        if self.timestamp is None:
            object.__setattr__(self, 'timestamp', datetime.now())

