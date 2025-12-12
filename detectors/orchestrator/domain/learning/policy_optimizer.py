"""
Adaptive Policy Optimizer - Phase 5.3

Optimiert Policies basierend auf Feedback und Leistungsdaten.
Nutzt FeedbackCollector für Datenanalyse.
"""

import yaml
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path

from .feedback_collector import FeedbackCollector, FeedbackType

logger = logging.getLogger(__name__)


class OptimizationGoal(Enum):
    """Ziele für Policy-Optimierung."""
    MINIMIZE_FALSE_POSITIVES = "minimize_false_positives"
    MINIMIZE_FALSE_NEGATIVES = "minimize_false_negatives"
    BALANCED_ACCURACY = "balanced_accuracy"
    MAXIMIZE_THROUGHPUT = "maximize_throughput"
    MINIMIZE_LATENCY = "minimize_latency"


@dataclass
class OptimizationResult:
    """Ergebnis einer Policy-Optimierung."""
    policy_name: str
    changes_applied: List[str]
    performance_before: Dict[str, float]
    performance_after: Dict[str, float]
    improvement: float
    timestamp: datetime


class AdaptivePolicyOptimizer:
    """Optimiert Policies basierend auf Feedback und Leistungsdaten."""

    def __init__(
        self,
        policy_engine,  # DynamicPolicyEngine
        feedback_collector: FeedbackCollector,
        config_path: str
    ):
        self.policy_engine = policy_engine
        self.feedback_collector = feedback_collector
        self.config_path = Path(config_path)

        self.optimization_history: List[OptimizationResult] = []
        self.last_optimization = None

        # Optimierungsziele mit Gewichtungen
        self.optimization_goals = {
            OptimizationGoal.MINIMIZE_FALSE_NEGATIVES: 0.4,
            OptimizationGoal.MINIMIZE_LATENCY: 0.3,
            OptimizationGoal.BALANCED_ACCURACY: 0.3
        }

        # Schwellenwerte für Optimierung
        self.optimization_thresholds = {
            'false_negative_rate': 0.1,  # 10% FN ist zu hoch
            'avg_latency_ms': 300,  # >300ms ist zu langsam
            'policy_effectiveness': 0.7  # <70% Effektivität
        }

        logger.info("AdaptivePolicyOptimizer initialized")

    def analyze_policy_performance(self) -> Dict[str, Any]:
        """Analysiert Performance aller Policies basierend auf Feedback."""
        policy_performance = {}

        # Hole Feedback-Daten aus Repository
        feedback_summary = self.feedback_collector.get_feedback_summary(hours=24)
        
        # Hole Detektor-Metriken
        detector_metrics = self.feedback_collector.get_all_metrics()

        # Für jede Policy analysieren
        for policy_name, policy in self.policy_engine.policies.items():
            if not policy.enabled:
                continue

            # Berechne Metriken aus Feedback
            false_positives = feedback_summary.get('false_positive', 0)
            false_negatives = feedback_summary.get('false_negative', 0)
            
            # Berechne durchschnittliche Latenz aus Detektor-Metriken
            avg_latency = 0.0
            total_calls = 0
            for detector_config in policy.detectors:
                detector_name = detector_config.get('name', '')
                if detector_name in detector_metrics:
                    metrics = detector_metrics[detector_name]
                    avg_latency += metrics.avg_response_time * metrics.total_calls
                    total_calls += metrics.total_calls
            
            if total_calls > 0:
                avg_latency = avg_latency / total_calls

            # Berechne Effektivität (1 - (FP + FN) / total)
            total_feedback = sum(feedback_summary.values())
            effectiveness = 1.0 - ((false_positives + false_negatives) / total_feedback) if total_feedback > 0 else 0.85

            metrics = {
                'activation_count': total_calls,
                'false_positives': false_positives,
                'false_negatives': false_negatives,
                'avg_latency': avg_latency,
                'effectiveness': effectiveness,
                'last_evaluated': datetime.utcnow()
            }

            policy_performance[policy_name] = metrics

        return policy_performance

    def optimize_policies(self) -> List[OptimizationResult]:
        """Optimiert Policies basierend auf Performance-Daten."""
        performance_data = self.analyze_policy_performance()
        optimization_results = []

        for policy_name, metrics in performance_data.items():
            # Prüfe ob Optimierung benötigt wird
            needs_optimization = self._needs_optimization(policy_name, metrics)

            if needs_optimization:
                result = self._optimize_single_policy(policy_name, metrics)
                if result:
                    optimization_results.append(result)

        if optimization_results:
            self.last_optimization = datetime.utcnow()
            logger.info(f"Optimized {len(optimization_results)} policies")

        return optimization_results

    def _needs_optimization(self, policy_name: str, metrics: Dict[str, Any]) -> bool:
        """Bestimmt ob eine Policy Optimierung benötigt."""
        # Prüfe Schwellenwerte
        total_feedback = metrics.get('false_positives', 0) + metrics.get('false_negatives', 0)
        if total_feedback > 0:
            fn_rate = metrics.get('false_negatives', 0) / total_feedback
            if fn_rate > self.optimization_thresholds['false_negative_rate']:
                logger.warning(f"Policy {policy_name} has high false negatives: {fn_rate:.2%}")
                return True

        if metrics.get('avg_latency', 0) > self.optimization_thresholds['avg_latency_ms']:
            logger.warning(f"Policy {policy_name} has high latency: {metrics['avg_latency']:.1f}ms")
            return True

        if metrics.get('effectiveness', 1.0) < self.optimization_thresholds['policy_effectiveness']:
            logger.warning(f"Policy {policy_name} has low effectiveness: {metrics['effectiveness']:.2%}")
            return True

        return False

    def _optimize_single_policy(
        self,
        policy_name: str,
        metrics: Dict[str, Any]
    ) -> Optional[OptimizationResult]:
        """Optimiert eine einzelne Policy."""
        try:
            # Lade aktuelle Policy-Konfiguration
            if not self.config_path.exists():
                logger.error(f"Policy config file not found: {self.config_path}")
                return None

            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # Finde die Policy in der Konfiguration
            policy_index = None
            for i, policy_config in enumerate(config.get('policies', [])):
                if policy_config.get('name') == policy_name:
                    policy_index = i
                    break

            if policy_index is None:
                logger.error(f"Policy {policy_name} not found in config")
                return None

            policy_config = config['policies'][policy_index].copy()
            original_config = policy_config.copy()

            changes = []

            # Optimierung 1: Anpassung der Aktivierungsschwelle
            total_feedback = metrics.get('false_positives', 0) + metrics.get('false_negatives', 0)
            if total_feedback > 0:
                fn_rate = metrics.get('false_negatives', 0) / total_feedback
                if fn_rate > 0.15:  # >15% false negatives
                    # Erhöhe Schwelle für strengere Filterung
                    current_threshold = policy_config.get('activation_threshold', 0.7)
                    new_threshold = min(current_threshold + 0.1, 0.95)
                    policy_config['activation_threshold'] = new_threshold
                    changes.append(f"Increased activation threshold to {new_threshold}")

            # Optimierung 2: Hinzufügen von zusätzlichen Detektoren bei hohen FN
            if total_feedback > 0 and (metrics.get('false_negatives', 0) / total_feedback) > 0.2:
                detectors = policy_config.get('detectors', [])
                detector_names = [d.get('name') for d in detectors]

                if 'content_safety' not in detector_names:
                    detectors.append({
                        'name': 'content_safety',
                        'mode': 'conditional',
                        'timeout_ms': 500,
                        'priority': 3
                    })
                    changes.append("Added content_safety detector")

            # Optimierung 3: Anpassung der Strategie bei hoher Latenz
            if metrics.get('avg_latency', 0) > 300:
                if policy_config.get('strategy') == 'sequential':
                    # Wechsel zu parallel für bessere Performance
                    policy_config['strategy'] = 'parallel'
                    changes.append("Changed strategy from sequential to parallel")

                # Reduziere Timeouts
                for detector in policy_config.get('detectors', []):
                    if detector.get('timeout_ms', 500) > 200:
                        old_timeout = detector.get('timeout_ms')
                        detector['timeout_ms'] = 200
                        changes.append(f"Reduced timeout for {detector.get('name')} from {old_timeout}ms to 200ms")

            # Wenn Änderungen vorgenommen wurden, speichere und lade neu
            if changes:
                # Aktualisiere Konfiguration
                config['policies'][policy_index] = policy_config

                # Backup erstellen
                backup_path = self.config_path.with_suffix('.yaml.backup')
                with open(backup_path, 'w', encoding='utf-8') as f:
                    yaml.dump(config, f, default_flow_style=False)

                # Speichere zurück in Datei
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    yaml.dump(config, f, default_flow_style=False)

                # Lade Policies neu
                self.policy_engine.reload_policies()

                # Erstelle Optimierungsergebnis
                result = OptimizationResult(
                    policy_name=policy_name,
                    changes_applied=changes,
                    performance_before=metrics,
                    performance_after=metrics,  # In Realität nach einiger Zeit neu messen
                    improvement=0.1,  # Geschätzte Verbesserung
                    timestamp=datetime.utcnow()
                )

                self.optimization_history.append(result)
                logger.info(f"Optimized policy {policy_name}: {', '.join(changes)}")

                return result

        except Exception as e:
            logger.error(f"Failed to optimize policy {policy_name}: {e}", exc_info=True)

        return None

    def auto_optimize(self, interval_hours: int = 1) -> List[OptimizationResult]:
        """Startet automatische Optimierung im angegebenen Intervall."""
        if self.last_optimization:
            time_since_last = datetime.utcnow() - self.last_optimization
            if time_since_last < timedelta(hours=interval_hours):
                return []

        logger.info("Starting automatic policy optimization")
        results = self.optimize_policies()

        return results

    def get_optimization_history(
        self,
        policy_name: str = None,
        limit: int = 10
    ) -> List[OptimizationResult]:
        """Gibt Optimierungsverlauf zurück."""
        if policy_name:
            history = [r for r in self.optimization_history if r.policy_name == policy_name]
        else:
            history = self.optimization_history

        return history[-limit:] if history else []

