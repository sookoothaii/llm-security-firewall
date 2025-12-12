"""
V2.1 Hotfix Monitoring

Sammelt und exportiert Metriken für V2.1 Hotfix Monitoring.

Usage:
    # In Detection Service integrieren
    from detectors.orchestrator.infrastructure.monitoring.v21_monitoring import V21Monitor
    
    monitor = V21Monitor()
    monitor.record_prediction(result, true_label)
    monitor.export_metrics()  # Für Prometheus
"""

import time
import logging
from typing import Dict, Any, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PredictionRecord:
    """Record einer einzelnen Prediction."""
    timestamp: datetime
    prediction: int  # 0 = benign, 1 = malicious
    true_label: Optional[int] = None  # None wenn unbekannt
    score: float = 0.0
    confidence: float = 0.0
    method: str = ""
    response_time_ms: float = 0.0


class V21Monitor:
    """
    Monitoring für V2.1 Hotfix.
    
    Trackt:
    - FPR (False Positive Rate)
    - Bypass Rate
    - Whitelist Hit Rate
    - Method Distribution
    - Response Times
    """
    
    def __init__(self, window_size: int = 1000):
        """
        Initialize monitor.
        
        Args:
            window_size: Anzahl der letzten Predictions für Rolling Window
        """
        self.window_size = window_size
        self.predictions = deque(maxlen=window_size)
        self.method_counts = defaultdict(int)
        self.whitelist_hits = 0
        self.total_predictions = 0
        
        # Response Time Tracking
        self.response_times = deque(maxlen=window_size)
        
        # Alert Thresholds
        self.fpr_alert_threshold = 0.15  # 15%
        self.bypass_alert_threshold = 0.01  # 1%
        self.response_time_alert_ms = 200.0  # 200ms
        
        logger.info("V2.1 Monitor initialized")
    
    def record_prediction(
        self,
        result: Dict[str, Any],
        true_label: Optional[int] = None,
        response_time_ms: float = 0.0
    ):
        """
        Record eine Prediction.
        
        Args:
            result: Ergebnis von detector.predict()
            true_label: True Label (0 oder 1), None wenn unbekannt
            response_time_ms: Response Time in Millisekunden
        """
        record = PredictionRecord(
            timestamp=datetime.now(),
            prediction=result['prediction'],
            true_label=true_label,
            score=result['score'],
            confidence=result['confidence'],
            method=result['method'],
            response_time_ms=response_time_ms
        )
        
        self.predictions.append(record)
        self.method_counts[result['method']] += 1
        self.total_predictions += 1
        
        if result['method'] == 'v2_whitelist_override':
            self.whitelist_hits += 1
        
        if response_time_ms > 0:
            self.response_times.append(response_time_ms)
        
        # Check Alerts
        self._check_alerts()
    
    def _check_alerts(self):
        """Prüfe ob Alert-Thresholds überschritten wurden."""
        if len(self.predictions) < 100:  # Mindestens 100 Samples für valide Metriken
            return
        
        metrics = self.get_metrics()
        
        # FPR Alert
        if metrics['fpr'] > self.fpr_alert_threshold:
            logger.warning(
                f"⚠️ FPR Alert: {metrics['fpr']:.2%} exceeds threshold {self.fpr_alert_threshold:.2%}"
            )
        
        # Bypass Alert
        if metrics['bypass_rate'] > self.bypass_alert_threshold:
            logger.critical(
                f"🚨 Bypass Alert: {metrics['bypass_rate']:.2%} exceeds threshold {self.bypass_alert_threshold:.2%}"
            )
        
        # Response Time Alert
        if metrics['response_time_p95_ms'] > self.response_time_alert_ms:
            logger.warning(
                f"⚠️ Response Time Alert: P95 {metrics['response_time_p95_ms']:.1f}ms exceeds threshold {self.response_time_alert_ms}ms"
            )
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Berechne aktuelle Metriken.
        
        Returns:
            Dictionary mit Metriken
        """
        if len(self.predictions) == 0:
            return {
                'fpr': 0.0,
                'bypass_rate': 0.0,
                'accuracy': 0.0,
                'whitelist_hit_rate': 0.0,
                'method_distribution': {},
                'response_time_p50_ms': 0.0,
                'response_time_p95_ms': 0.0,
                'response_time_p99_ms': 0.0,
                'total_predictions': 0,
            }
        
        # Filtere Predictions mit bekanntem True Label
        labeled = [p for p in self.predictions if p.true_label is not None]
        
        if len(labeled) == 0:
            # Keine Labels verfügbar - nur Method Statistics
            return {
                'fpr': None,
                'bypass_rate': None,
                'accuracy': None,
                'whitelist_hit_rate': self.whitelist_hits / self.total_predictions if self.total_predictions > 0 else 0.0,
                'method_distribution': dict(self.method_counts),
                'response_time_p50_ms': self._percentile(self.response_times, 50) if self.response_times else 0.0,
                'response_time_p95_ms': self._percentile(self.response_times, 95) if self.response_times else 0.0,
                'response_time_p99_ms': self._percentile(self.response_times, 99) if self.response_times else 0.0,
                'total_predictions': self.total_predictions,
            }
        
        # Berechne Metriken
        benign_samples = [p for p in labeled if p.true_label == 0]
        malicious_samples = [p for p in labeled if p.true_label == 1]
        
        # FPR (False Positive Rate)
        benign_fps = sum(1 for p in benign_samples if p.prediction == 1)
        fpr = (benign_fps / len(benign_samples)) if benign_samples else 0.0
        
        # Bypass Rate (False Negative Rate)
        malicious_fns = sum(1 for p in malicious_samples if p.prediction == 0)
        bypass_rate = (malicious_fns / len(malicious_samples)) if malicious_samples else 0.0
        
        # Accuracy
        correct = sum(1 for p in labeled if p.prediction == p.true_label)
        accuracy = (correct / len(labeled)) if labeled else 0.0
        
        # Whitelist Hit Rate
        whitelist_hit_rate = self.whitelist_hits / self.total_predictions if self.total_predictions > 0 else 0.0
        
        # Method Distribution
        method_dist = {}
        for method, count in self.method_counts.items():
            method_dist[method] = {
                'count': count,
                'percentage': (count / self.total_predictions * 100) if self.total_predictions > 0 else 0.0
            }
        
        # Response Time Percentiles
        response_times_sorted = sorted(self.response_times) if self.response_times else []
        
        return {
            'fpr': fpr,
            'bypass_rate': bypass_rate,
            'accuracy': accuracy,
            'whitelist_hit_rate': whitelist_hit_rate,
            'method_distribution': method_dist,
            'response_time_p50_ms': self._percentile(response_times_sorted, 50) if response_times_sorted else 0.0,
            'response_time_p95_ms': self._percentile(response_times_sorted, 95) if response_times_sorted else 0.0,
            'response_time_p99_ms': self._percentile(response_times_sorted, 99) if response_times_sorted else 0.0,
            'total_predictions': self.total_predictions,
            'labeled_predictions': len(labeled),
        }
    
    def _percentile(self, sorted_list: list, percentile: float) -> float:
        """Berechne Percentile."""
        if not sorted_list:
            return 0.0
        index = int(len(sorted_list) * percentile / 100)
        return sorted_list[min(index, len(sorted_list) - 1)]
    
    def export_prometheus_metrics(self) -> Dict[str, float]:
        """
        Exportiere Metriken im Prometheus-Format.
        
        Returns:
            Dictionary mit Metriken für Prometheus
        """
        metrics = self.get_metrics()
        
        prometheus_metrics = {
            'v21_hotfix_fpr': metrics['fpr'] if metrics['fpr'] is not None else 0.0,
            'v21_hotfix_bypass_rate': metrics['bypass_rate'] if metrics['bypass_rate'] is not None else 0.0,
            'v21_hotfix_accuracy': metrics['accuracy'] if metrics['accuracy'] is not None else 0.0,
            'v21_hotfix_whitelist_hit_rate': metrics['whitelist_hit_rate'],
            'v21_hotfix_total_predictions': metrics['total_predictions'],
            'v21_hotfix_response_time_p50_ms': metrics['response_time_p50_ms'],
            'v21_hotfix_response_time_p95_ms': metrics['response_time_p95_ms'],
            'v21_hotfix_response_time_p99_ms': metrics['response_time_p99_ms'],
        }
        
        # Method Distribution
        for method, dist in metrics['method_distribution'].items():
            prometheus_metrics[f'v21_hotfix_method_{method}_count'] = dist['count']
            prometheus_metrics[f'v21_hotfix_method_{method}_percentage'] = dist['percentage']
        
        return prometheus_metrics
    
    def get_summary(self) -> str:
        """Gebe eine textuelle Zusammenfassung der Metriken."""
        metrics = self.get_metrics()
        
        summary = f"""
V2.1 Hotfix Monitoring Summary
==============================
Total Predictions: {metrics['total_predictions']}
Labeled Predictions: {metrics.get('labeled_predictions', 0)}

Metrics:
  FPR: {metrics['fpr']:.2%} if metrics['fpr'] is not None else 'N/A'}
  Bypass Rate: {metrics['bypass_rate']:.2%} if metrics['bypass_rate'] is not None else 'N/A'}
  Accuracy: {metrics['accuracy']:.2%} if metrics['accuracy'] is not None else 'N/A'}
  Whitelist Hit Rate: {metrics['whitelist_hit_rate']:.2%}

Response Times:
  P50: {metrics['response_time_p50_ms']:.1f}ms
  P95: {metrics['response_time_p95_ms']:.1f}ms
  P99: {metrics['response_time_p99_ms']:.1f}ms

Method Distribution:
"""
        for method, dist in metrics['method_distribution'].items():
            summary += f"  {method}: {dist['count']} ({dist['percentage']:.1f}%)\n"
        
        return summary


# Global Monitor Instance (Singleton)
_global_monitor: Optional[V21Monitor] = None


def get_monitor() -> V21Monitor:
    """Get global monitor instance."""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = V21Monitor()
    return _global_monitor


def record_prediction(result: Dict[str, Any], true_label: Optional[int] = None, response_time_ms: float = 0.0):
    """Convenience function to record prediction."""
    monitor = get_monitor()
    monitor.record_prediction(result, true_label, response_time_ms)

