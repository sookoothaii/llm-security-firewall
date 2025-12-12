"""
Metrics Collector - Phase 5.4

Sammelt und aggregiert System-Metriken im Prometheus-Format.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
import asyncio
import statistics
from collections import defaultdict, deque
import logging
import time
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

logger = logging.getLogger(__name__)


class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class MetricDefinition:
    """Definition einer Metrik."""
    name: str
    type: MetricType
    description: str
    labels: List[str] = None
    buckets: List[float] = None  # Für Histogramme
    quantiles: List[float] = None  # Für Summaries


@dataclass
class MetricValue:
    """Einzelner Metrik-Wert."""
    value: float
    timestamp: datetime
    labels: Dict[str, str] = None


class MetricsCollector:
    """Sammelt und aggregiert System-Metriken."""

    def __init__(self, retention_period: timedelta = timedelta(hours=24)):
        self.retention_period = retention_period
        self.metrics: Dict[str, List[MetricValue]] = defaultdict(list)
        self.definitions: Dict[str, MetricDefinition] = {}
        self.lock = Lock()
        self.executor = ThreadPoolExecutor(max_workers=4)

        # Standard-Metriken definieren
        self._define_standard_metrics()

        # Cleanup-Task wird später gestartet (lazy initialization)
        self._cleanup_task = None
        self._cleanup_started = False

    def _define_standard_metrics(self):
        """Definiert Standard-Metriken."""
        standard_metrics = [
            MetricDefinition(
                name="router_requests_total",
                type=MetricType.COUNTER,
                description="Total number of routing requests",
                labels=["source_tool", "outcome"]
            ),
            MetricDefinition(
                name="router_latency_seconds",
                type=MetricType.HISTOGRAM,
                description="Routing request latency in seconds",
                labels=["source_tool", "strategy"],
                buckets=[0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0]
            ),
            MetricDefinition(
                name="detector_calls_total",
                type=MetricType.COUNTER,
                description="Total detector calls",
                labels=["detector_name", "status", "mode"]
            ),
            MetricDefinition(
                name="detector_latency_seconds",
                type=MetricType.HISTOGRAM,
                description="Detector latency in seconds",
                labels=["detector_name"],
                buckets=[0.01, 0.05, 0.1, 0.2, 0.5, 1.0]
            ),
            MetricDefinition(
                name="policy_evaluations_total",
                type=MetricType.COUNTER,
                description="Policy evaluation count",
                labels=["policy_name", "matched"]
            ),
            MetricDefinition(
                name="feedback_submissions_total",
                type=MetricType.COUNTER,
                description="Feedback submissions",
                labels=["feedback_type", "source"]
            ),
            MetricDefinition(
                name="risk_score_distribution",
                type=MetricType.HISTOGRAM,
                description="Risk score distribution",
                buckets=[0.0, 0.25, 0.5, 0.75, 0.9, 1.0]
            ),
            MetricDefinition(
                name="system_health",
                type=MetricType.GAUGE,
                description="System health status (0=down, 1=degraded, 2=healthy)",
                labels=["component"]
            ),
            MetricDefinition(
                name="queue_size",
                type=MetricType.GAUGE,
                description="Processing queue size",
                labels=["queue_type"]
            ),
            MetricDefinition(
                name="memory_usage_bytes",
                type=MetricType.GAUGE,
                description="Memory usage in bytes",
                labels=["component"]
            ),
            MetricDefinition(
                name="error_rate",
                type=MetricType.GAUGE,
                description="Error rate (0-1)",
                labels=["component", "error_type"]
            ),
            MetricDefinition(
                name="learning_optimizations_total",
                type=MetricType.COUNTER,
                description="Learning optimization runs",
                labels=["optimization_type", "result"]
            ),
            MetricDefinition(
                name="adaptive_learning_impact",
                type=MetricType.GAUGE,
                description="Impact of adaptive learning (improvement ratio)",
                labels=["metric"]
            )
        ]

        for metric in standard_metrics:
            self.register_metric(metric)

    def register_metric(self, definition: MetricDefinition):
        """Registriert eine neue Metrik."""
        with self.lock:
            self.definitions[definition.name] = definition

    def record(self, name: str, value: float, labels: Dict[str, str] = None):
        """Zeichnet einen Metrik-Wert auf."""
        with self.lock:
            if name not in self.definitions:
                logger.warning(f"Recording undefined metric: {name}")
                return

            metric_def = self.definitions[name]

            # Validieren basierend auf Typ
            if metric_def.type == MetricType.COUNTER and value < 0:
                logger.warning(f"Counter metric {name} got negative value: {value}")
                return

            metric_value = MetricValue(
                value=value,
                timestamp=datetime.utcnow(),
                labels=labels or {}
            )

            self.metrics[name].append(metric_value)

    def inc(self, name: str, labels: Dict[str, str] = None, amount: float = 1):
        """Inkrementiert eine Counter-Metrik."""
        self.record(name, amount, labels)

    def gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Setzt eine Gauge-Metrik."""
        self.record(name, value, labels)

    def observe(self, name: str, value: float, labels: Dict[str, str] = None):
        """Beobachtet einen Wert für Histogramm/Summary."""
        self.record(name, value, labels)

    def get_metric_data(self, name: str,
                       start_time: datetime = None,
                       end_time: datetime = None) -> List[MetricValue]:
        """Holt Metrik-Daten für einen Zeitraum."""
        with self.lock:
            if name not in self.metrics:
                return []

            data = self.metrics[name]

            if start_time:
                data = [d for d in data if d.timestamp >= start_time]
            if end_time:
                data = [d for d in data if d.timestamp <= end_time]

            return data

    def get_summary(self, name: str,
                   start_time: datetime = None,
                   end_time: datetime = None) -> Dict[str, Any]:
        """Gibt eine Zusammenfassung einer Metrik zurück."""
        data = self.get_metric_data(name, start_time, end_time)

        if not data:
            return {"count": 0, "avg": 0, "min": 0, "max": 0, "sum": 0, "latest": 0}

        values = [d.value for d in data]

        summary = {
            "count": len(values),
            "avg": statistics.mean(values) if values else 0,
            "min": min(values) if values else 0,
            "max": max(values) if values else 0,
            "sum": sum(values) if values else 0,
            "latest": values[-1] if values else 0,
            "timestamp": data[-1].timestamp if data else None
        }

        # Histogramm-spezifische Berechnungen
        if name in self.definitions and self.definitions[name].type == MetricType.HISTOGRAM:
            buckets = self.definitions[name].buckets
            if buckets:
                histogram = {}
                for bucket in sorted(buckets):
                    count = sum(1 for v in values if v <= bucket)
                    histogram[f"bucket_{bucket}"] = count
                summary["histogram"] = histogram

        return summary

    def get_prometheus_format(self) -> str:
        """Gibt Metriken im Prometheus-Format zurück."""
        lines = []

        with self.lock:
            for name, definition in self.definitions.items():
                if name not in self.metrics or not self.metrics[name]:
                    continue

                # HELP und TYPE Zeilen
                lines.append(f"# HELP {name} {definition.description}")
                lines.append(f"# TYPE {name} {definition.type.value}")

                # Daten-Zeilen
                if definition.type == MetricType.COUNTER:
                    # Summiere alle Werte für Counter
                    latest_by_labels = {}
                    for value in self.metrics[name]:
                        label_str = self._labels_to_str(value.labels)
                        if label_str in latest_by_labels:
                            latest_by_labels[label_str] += value.value
                        else:
                            latest_by_labels[label_str] = value.value

                    for label_str, total_value in latest_by_labels.items():
                        lines.append(f'{name}{{{label_str}}} {total_value}')

                elif definition.type == MetricType.GAUGE:
                    # Nimm den neuesten Wert für jedes Label-Set
                    latest_by_labels = {}
                    for value in self.metrics[name]:
                        label_str = self._labels_to_str(value.labels)
                        latest_by_labels[label_str] = value.value

                    for label_str, gauge_value in latest_by_labels.items():
                        lines.append(f'{name}{{{label_str}}} {gauge_value}')

                elif definition.type == MetricType.HISTOGRAM:
                    # Histogramm in Prometheus-Format konvertieren
                    data = self.metrics[name]
                    if not data:
                        continue

                    # Gruppiere nach Labels
                    grouped_data = defaultdict(list)
                    for value in data:
                        label_str = self._labels_to_str(value.labels)
                        grouped_data[label_str].append(value.value)

                    for label_str, values in grouped_data.items():
                        # Zähle Buckets
                        if definition.buckets:
                            buckets = sorted(definition.buckets)
                            for bucket in buckets:
                                count = sum(1 for v in values if v <= bucket)
                                lines.append(f'{name}_bucket{{le="{bucket}"{label_str}}} {count}')

                            # +Inf Bucket
                            total_count = len(values)
                            lines.append(f'{name}_bucket{{le="+Inf"{label_str}}} {total_count}')

                            # Summe
                            sum_value = sum(values)
                            lines.append(f'{name}_sum{{{label_str}}} {sum_value}')
                            lines.append(f'{name}_count{{{label_str}}} {total_count}')

        return "\n".join(lines)

    def _labels_to_str(self, labels: Dict[str, str]) -> str:
        """Konvertiert Labels zu Prometheus-Format."""
        if not labels:
            return ""

        label_pairs = []
        for key, value in sorted(labels.items()):
            # Escape spezielle Zeichen
            escaped_value = str(value).replace('\\', '\\\\').replace('"', '\\"')
            escaped_key = str(key).replace('\\', '\\\\').replace('"', '\\"')
            label_pairs.append(f'{escaped_key}="{escaped_value}"')

        return "," + ",".join(label_pairs) if label_pairs else ""

    def _ensure_cleanup_task(self):
        """Stellt sicher, dass die Cleanup-Task läuft."""
        if self._cleanup_started:
            return
        
        try:
            loop = asyncio.get_running_loop()
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
            self._cleanup_started = True
            logger.debug("Cleanup task created in running event loop")
        except RuntimeError:
            # No running event loop, wird beim nächsten Mal versucht
            pass

    async def _periodic_cleanup(self):
        """Entfernt alte Metrik-Daten."""
        while True:
            try:
                cutoff = datetime.utcnow() - self.retention_period

                with self.lock:
                    for metric_name in list(self.metrics.keys()):
                        self.metrics[metric_name] = [
                            v for v in self.metrics[metric_name]
                            if v.timestamp > cutoff
                        ]

                        # Entferne leere Listen
                        if not self.metrics[metric_name]:
                            del self.metrics[metric_name]

                logger.debug(f"Cleaned up metrics older than {cutoff}")

            except Exception as e:
                logger.error(f"Error in metrics cleanup: {e}")

            await asyncio.sleep(3600)  # Stündlich

    def get_health_status(self) -> Dict[str, Any]:
        """Gibt System-Health-Status zurück."""
        health = {"status": "healthy", "components": {}}

        # Prüfe verschiedene Komponenten
        components = {
            "router": self._check_router_health(),
            "learning": self._check_learning_health(),
            "storage": self._check_storage_health(),
            "policies": self._check_policies_health()
        }

        health["components"] = components

        # Gesamtstatus
        if any(c["status"] == "down" for c in components.values()):
            health["status"] = "degraded"
        elif any(c["status"] == "degraded" for c in components.values()):
            health["status"] = "degraded"

        # Metriken für Health
        health["timestamp"] = datetime.utcnow().isoformat()
        health["metrics_summary"] = self.get_system_summary()

        return health

    def _check_router_health(self) -> Dict[str, Any]:
        """Prüft Router-Health."""
        try:
            # Prüfe Error-Rate
            router_data = self.get_metric_data("router_requests_total",
                                              start_time=datetime.utcnow() - timedelta(minutes=5))
            error_data = self.get_metric_data("error_rate",
                                             start_time=datetime.utcnow() - timedelta(minutes=5))

            if not router_data:
                return {"status": "unknown", "message": "No recent data"}

            total_requests = sum(d.value for d in router_data)
            error_rate = error_data[-1].value if error_data else 0

            if error_rate > 0.3:  # 30% Error-Rate
                return {"status": "down", "error_rate": error_rate, "requests": total_requests}
            elif error_rate > 0.1:  # 10% Error-Rate
                return {"status": "degraded", "error_rate": error_rate, "requests": total_requests}

            return {"status": "healthy", "error_rate": error_rate, "requests": total_requests}

        except Exception as e:
            return {"status": "down", "error": str(e)}

    def _check_learning_health(self) -> Dict[str, Any]:
        """Prüft Learning-Health."""
        try:
            learning_data = self.get_metric_data("learning_optimizations_total",
                                                start_time=datetime.utcnow() - timedelta(hours=1))

            if not learning_data:
                return {"status": "unknown", "message": "No recent learning data"}

            return {"status": "healthy", "optimizations": len(learning_data)}

        except Exception as e:
            return {"status": "degraded", "error": str(e)}

    def _check_storage_health(self) -> Dict[str, Any]:
        """Prüft Storage-Health."""
        # Hier könnten wir Redis/PostgreSQL Verbindungen prüfen
        return {"status": "healthy", "message": "Storage assumed healthy"}

    def _check_policies_health(self) -> Dict[str, Any]:
        """Prüft Policies-Health."""
        try:
            policy_data = self.get_metric_data("policy_evaluations_total",
                                              start_time=datetime.utcnow() - timedelta(minutes=5))

            if not policy_data:
                return {"status": "unknown", "message": "No recent policy evaluations"}

            return {"status": "healthy", "evaluations": len(policy_data)}

        except Exception as e:
            return {"status": "degraded", "error": str(e)}

    def get_system_summary(self) -> Dict[str, Any]:
        """Gibt eine Zusammenfassung der System-Metriken."""
        now = datetime.utcnow()
        five_min_ago = now - timedelta(minutes=5)
        one_hour_ago = now - timedelta(hours=1)

        return {
            "router": {
                "5min_requests": self.get_summary("router_requests_total", five_min_ago)["count"],
                "5min_avg_latency": self.get_summary("router_latency_seconds", five_min_ago)["avg"],
                "error_rate": self.get_summary("error_rate", five_min_ago)["avg"]
            },
            "detectors": {
                "total_calls": self.get_summary("detector_calls_total", one_hour_ago)["count"],
                "avg_latency": self.get_summary("detector_latency_seconds", one_hour_ago)["avg"]
            },
            "learning": {
                "optimizations": self.get_summary("learning_optimizations_total", one_hour_ago)["count"],
                "impact": self.get_summary("adaptive_learning_impact", one_hour_ago)["avg"]
            },
            "policies": {
                "evaluations": self.get_summary("policy_evaluations_total", five_min_ago)["count"]
            }
        }

