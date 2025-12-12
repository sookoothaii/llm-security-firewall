"""
Alert Service Implementation

Analyzes service metrics and generates alerts.
"""
import logging
from typing import Dict, List, Optional
from datetime import datetime

from domain.ports import AlertAnalyzerPort
from domain.value_objects import ServiceStatus, Alert

logger = logging.getLogger(__name__)


# Alert thresholds (from original main.py)
ALERT_THRESHOLDS = {
    "loss_critical": 0.25,
    "loss_warning": 0.15,
    "buffer_full": 0.95,  # 95% Buffer-Auslastung
    "no_updates_hours": 24  # Keine Updates seit X Stunden
}


class AlertService(AlertAnalyzerPort):
    """
    Alert analyzer service implementation.
    
    Evaluates service statuses and generates alerts based on thresholds.
    """
    
    def __init__(self, thresholds: Optional[Dict[str, float]] = None):
        """
        Initialize alert service.
        
        Args:
            thresholds: Optional custom thresholds (defaults to ALERT_THRESHOLDS)
        """
        self.thresholds = thresholds or ALERT_THRESHOLDS
        logger.info("AlertService initialized")
    
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
        alerts = []
        
        for service_id, status in service_statuses.items():
            # Service unhealthy alert
            if not status.is_healthy:
                alerts.append(Alert(
                    severity="critical",
                    service_id=service_id,
                    alert_type="service_unhealthy",
                    message=f"Service {status.service_name} is {status.error or 'unhealthy'}",
                    timestamp=datetime.now()
                ))
                continue
            
            # Skip if feedback not enabled
            if not status.feedback_enabled:
                continue
            
            # Check online learning metrics
            online_learning = status.online_learning or {}
            if online_learning.get("running"):
                learner_stats = online_learning.get("learner_stats", {})
                avg_loss = learner_stats.get("average_loss", 0.0)
                updates = learner_stats.get("updates", 0)
                
                # Loss alerts
                if avg_loss > self.thresholds["loss_critical"]:
                    alerts.append(Alert(
                        severity="critical",
                        service_id=service_id,
                        alert_type="loss_critical",
                        message=f"Critical loss: {avg_loss:.4f} > {self.thresholds['loss_critical']}",
                        value=avg_loss,
                        timestamp=datetime.now()
                    ))
                elif avg_loss > self.thresholds["loss_warning"]:
                    alerts.append(Alert(
                        severity="warning",
                        service_id=service_id,
                        alert_type="loss_warning",
                        message=f"High loss: {avg_loss:.4f} > {self.thresholds['loss_warning']}",
                        value=avg_loss,
                        timestamp=datetime.now()
                    ))
                
                # Buffer full alert
                buffer_size = status.buffer_size or 0
                max_size = status.max_size or 10000
                if max_size > 0:
                    buffer_usage = buffer_size / max_size
                    if buffer_usage > self.thresholds["buffer_full"]:
                        alerts.append(Alert(
                            severity="warning",
                            service_id=service_id,
                            alert_type="buffer_full",
                            message=f"Buffer nearly full: {buffer_size}/{max_size} ({buffer_usage*100:.1f}%)",
                            value=buffer_usage,
                            timestamp=datetime.now()
                        ))
        
        return alerts

