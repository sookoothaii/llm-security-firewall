"""
Alert Manager - Phase 5.4

Verwaltet Alerts und Alert-Regeln für proaktives Monitoring.
"""

from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import logging
from collections import deque
import uuid

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(Enum):
    FIRING = "firing"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"


@dataclass
class AlertRule:
    """Definition einer Alert-Regel."""
    name: str
    condition: str  # Python-Expression
    severity: AlertSeverity
    duration: timedelta  # Wie lange muss die Bedingung erfüllt sein?
    summary: str
    description: str
    labels: Dict[str, str] = None
    annotations: Dict[str, str] = None
    enabled: bool = True


@dataclass
class Alert:
    """Eine aktive oder historische Alert."""
    id: str
    rule_name: str
    severity: AlertSeverity
    status: AlertStatus
    starts_at: datetime
    ends_at: Optional[datetime]
    summary: str
    description: str
    labels: Dict[str, str]
    annotations: Dict[str, str]
    value: float
    resolved_by: Optional[str] = None


class AlertManager:
    """Verwaltet Alerts und Alert-Regeln."""

    def __init__(self, metrics_collector: 'MetricsCollector'):
        self.metrics_collector = metrics_collector
        self.rules: Dict[str, AlertRule] = {}
        self.alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=1000)

        # Callbacks für Alert-Handling
        self.handlers: List[Callable[[Alert], None]] = []

        # Standard-Regeln
        self._setup_default_rules()

        # Monitoring-Loop wird später gestartet (lazy initialization)
        self._monitoring_task = None
        self._monitoring_started = False

    def _ensure_monitoring_loop(self):
        """Stellt sicher, dass die Monitoring-Loop läuft."""
        if self._monitoring_started:
            return
        
        try:
            loop = asyncio.get_running_loop()
            self._monitoring_task = asyncio.create_task(self._monitoring_loop())
            self._monitoring_started = True
            logger.debug("Monitoring loop task created in running event loop")
        except RuntimeError:
            # No running event loop, wird beim nächsten Mal versucht
            pass

    def _setup_default_rules(self):
        """Richtet Standard-Alert-Regeln ein."""
        default_rules = [
            AlertRule(
                name="high_error_rate",
                condition="error_summary.get('avg', 0) > 0.1",
                severity=AlertSeverity.ERROR,
                duration=timedelta(minutes=5),
                summary="High error rate detected",
                description="Error rate exceeds 10% in the last 5 minutes",
                labels={"component": "router"},
                annotations={"action": "Check router logs"}
            ),
            AlertRule(
                name="high_latency",
                condition="latency_summary.get('avg', 0) > 1.0",
                severity=AlertSeverity.WARNING,
                duration=timedelta(minutes=2),
                summary="High latency detected",
                description="Average latency exceeds 1 second in the last 2 minutes",
                labels={"component": "router"},
                annotations={"action": "Check detector performance"}
            ),
            AlertRule(
                name="detector_failures",
                condition="detector_summary.get('failure_rate', 0) > 0.2",
                severity=AlertSeverity.WARNING,
                duration=timedelta(minutes=5),
                summary="High detector failure rate",
                description="Detector failure rate exceeds 20% in the last 5 minutes",
                labels={"component": "detectors"},
                annotations={"action": "Check detector services"}
            ),
            AlertRule(
                name="learning_stalled",
                condition="learning_summary.get('count', 0) == 0",
                severity=AlertSeverity.WARNING,
                duration=timedelta(hours=24),
                summary="Learning stalled",
                description="No learning optimizations in the last 24 hours",
                labels={"component": "learning"},
                annotations={"action": "Check learning engine"}
            )
        ]

        for rule in default_rules:
            self.add_rule(rule)

    def add_rule(self, rule: AlertRule):
        """Fügt eine Alert-Regel hinzu."""
        self.rules[rule.name] = rule
        logger.info(f"Added alert rule: {rule.name}")

    def add_handler(self, handler: Callable[[Alert], None]):
        """Fügt einen Alert-Handler hinzu."""
        self.handlers.append(handler)

    async def _monitoring_loop(self, interval_seconds: int = 30):
        """Überwacht kontinuierlich die Metriken auf Alerts."""
        while True:
            try:
                await self._check_rules()
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")

            await asyncio.sleep(interval_seconds)

    async def _check_rules(self):
        """Prüft alle Alert-Regeln."""
        now = datetime.utcnow()

        for rule_name, rule in self.rules.items():
            if not rule.enabled:
                continue

            try:
                # Prüfe Bedingung
                should_fire = self._evaluate_rule(rule, now)

                if should_fire is not None and should_fire > 0:
                    # Prüfe ob Alert bereits existiert
                    existing_alert = self._get_active_alert_for_rule(rule_name)

                    if existing_alert:
                        # Update existierenden Alert
                        existing_alert.value = should_fire
                        existing_alert.ends_at = None  # Keep firing

                        logger.debug(f"Alert still firing: {rule_name}")
                    else:
                        # Erstelle neuen Alert
                        alert = self._create_alert(rule, should_fire, now)
                        self.alerts[alert.id] = alert

                        # Füge zur Historie hinzu
                        self.alert_history.append(alert)

                        # Rufe Handler auf
                        await self._notify_handlers(alert)

                        logger.warning(f"Alert fired: {rule_name}, Severity: {rule.severity}")
                else:
                    # Resolve aktive Alerts für diese Regel
                    await self._resolve_alerts_for_rule(rule_name, now)

            except Exception as e:
                logger.error(f"Error evaluating rule {rule_name}: {e}")

    def _evaluate_rule(self, rule: AlertRule, now: datetime) -> Optional[float]:
        """Evaluert eine Alert-Regel."""
        try:
            # Hole relevante Metriken
            start_time = now - rule.duration
            error_summary = self.metrics_collector.get_summary("error_rate", start_time=start_time)
            latency_summary = self.metrics_collector.get_summary("router_latency_seconds", start_time=start_time)
            detector_summary = self.metrics_collector.get_summary("detector_calls_total", start_time=start_time)
            learning_summary = self.metrics_collector.get_summary("learning_optimizations_total", start_time=now - timedelta(hours=24))

            # Berechne Failure-Rate für Detektoren
            total_detector_calls = detector_summary.get("count", 0)
            # Vereinfacht: Annahme dass fehlgeschlagene Calls separat getrackt werden
            detector_failure_rate = 0.0  # Wird in echter Implementierung berechnet

            # Erstelle sicheren Namespace für eval
            namespace = {
                "error_summary": error_summary,
                "latency_summary": latency_summary,
                "detector_summary": {**detector_summary, "failure_rate": detector_failure_rate},
                "learning_summary": learning_summary,
                "now": now,
                "duration": rule.duration,
                "timedelta": timedelta,
                "datetime": datetime
            }

            result = eval(rule.condition, {"__builtins__": {}}, namespace)

            if isinstance(result, bool):
                return 1.0 if result else None
            elif isinstance(result, (int, float)):
                return float(result)
            else:
                return None

        except Exception as e:
            logger.error(f"Error evaluating condition for rule {rule.name}: {e}")
            return None

    def _get_active_alert_for_rule(self, rule_name: str) -> Optional[Alert]:
        """Findet aktiven Alert für eine Regel."""
        for alert in self.alerts.values():
            if alert.rule_name == rule_name and alert.status == AlertStatus.FIRING:
                return alert
        return None

    def _create_alert(self, rule: AlertRule, value: float, timestamp: datetime) -> Alert:
        """Erstellt einen neuen Alert."""
        alert_id = str(uuid.uuid4())

        return Alert(
            id=alert_id,
            rule_name=rule.name,
            severity=rule.severity,
            status=AlertStatus.FIRING,
            starts_at=timestamp,
            ends_at=None,
            summary=rule.summary,
            description=rule.description,
            labels=rule.labels.copy() if rule.labels else {},
            annotations=rule.annotations.copy() if rule.annotations else {},
            value=value
        )

    async def _resolve_alerts_for_rule(self, rule_name: str, timestamp: datetime):
        """Markiert Alerts für eine Regel als resolved."""
        alerts_to_resolve = []

        for alert_id, alert in list(self.alerts.items()):
            if alert.rule_name == rule_name and alert.status == AlertStatus.FIRING:
                alert.status = AlertStatus.RESOLVED
                alert.ends_at = timestamp
                alerts_to_resolve.append(alert)

                logger.info(f"Alert resolved: {rule_name}")

        # Benachrichtige Handler über Resolutions
        for alert in alerts_to_resolve:
            await self._notify_handlers(alert, resolved=True)

    async def _notify_handlers(self, alert: Alert, resolved: bool = False):
        """Benachrichtigt alle registrierten Handler."""
        for handler in self.handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(alert)
                else:
                    handler(alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}")

    def acknowledge_alert(self, alert_id: str, user: str = "system"):
        """Bestätigt einen Alert."""
        if alert_id in self.alerts:
            self.alerts[alert_id].status = AlertStatus.ACKNOWLEDGED
            self.alerts[alert_id].resolved_by = user
            logger.info(f"Alert acknowledged: {alert_id} by {user}")
            return True
        return False

    def resolve_alert(self, alert_id: str, user: str = "system"):
        """Löst einen Alert manuell auf."""
        if alert_id in self.alerts:
            alert = self.alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.ends_at = datetime.utcnow()
            alert.resolved_by = user
            logger.info(f"Alert manually resolved: {alert_id} by {user}")
            return True
        return False

    def get_active_alerts(self) -> List[Alert]:
        """Gibt alle aktiven Alerts zurück."""
        return [alert for alert in self.alerts.values()
                if alert.status == AlertStatus.FIRING]

    def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """Gibt Alert-Historie zurück."""
        return list(self.alert_history)[-limit:]

    def add_console_handler(self):
        """Fügt einen Console-Handler für Alerts hinzu."""
        def console_handler(alert: Alert):
            if alert.status == AlertStatus.FIRING:
                emoji = "🚨" if alert.severity == AlertSeverity.CRITICAL else "⚠️"
                print(f"{emoji} [{alert.severity.value.upper()}] {alert.summary}")
                print(f"   {alert.description}")
                print(f"   Rule: {alert.rule_name}, Value: {alert.value}")
                print(f"   Time: {alert.starts_at}")
                print()
            elif alert.status == AlertStatus.RESOLVED:
                print(f"✅ [RESOLVED] {alert.summary}")
                print(f"   Resolved at: {alert.ends_at}")
                print()

        self.add_handler(console_handler)

