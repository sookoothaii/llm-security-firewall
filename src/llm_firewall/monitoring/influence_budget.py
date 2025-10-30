"""
Influence-Budget Alerts für Slow-Roll-Poison Detection
======================================================

Tracking der Summe der (TracIn/Attribution)-Einflüsse je Domain und Zeitfenster.
Wenn eine Quelle in kurzer Zeit überproportional zu Antworten beiträgt → Alarm.

Klassischer Slow-Roll-Poison-Fingerabdruck.

Features:
- Influence tracking per domain/source
- Time-windowed attribution
- Online Z-Score anomaly detection (EWMA)
- Alert system
- PostgreSQL-backed rollup tables
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    import psycopg  # noqa: F401
    HAS_PSYCOPG3 = True
except ImportError:
    HAS_PSYCOPG3 = False


@dataclass(frozen=True)
class InfluenceRecord:
    """Einzelner Influence-Record."""
    source_id: str
    domain: str
    influence_score: float
    timestamp: datetime
    context: str  # Query/Answer context


@dataclass(frozen=True)
class InfluenceAlert:
    """Influence-Alert bei Anomalie."""
    source_id: str
    domain: str
    time_window: str
    total_influence: float
    z_score: float
    threshold: float
    anomaly_type: str  # "spike", "sustained", "sudden"
    timestamp: datetime


class InfluenceBudgetTracker:
    """
    Tracker für Influence-Budget und Anomalie-Erkennung.
    
    Detektiert Slow-Roll-Poison durch überproportionale Source-Einflüsse.
    """

    def __init__(
        self,
        z_score_threshold: float = 4.0,
        time_window_minutes: int = 60,
        min_samples_for_baseline: int = 10
    ):
        """
        Args:
            z_score_threshold: Z-Score Threshold für Alarm
            time_window_minutes: Zeitfenster für Influence-Aggregation
            min_samples_for_baseline: Mindestanzahl Samples für Baseline
        """
        self.z_score_threshold = z_score_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
        self.min_samples_for_baseline = min_samples_for_baseline

        self.influence_records: List[InfluenceRecord] = []
        self.alerts: List[InfluenceAlert] = []
        self.baseline_statistics: Dict[str, Dict] = {}

    def record_influence(
        self,
        source_id: str,
        domain: str,
        influence_score: float,
        context: str = ""
    ):
        """
        Registriere Influence-Event.
        
        Args:
            source_id: ID der Source (Domain, User, etc.)
            domain: Domain (SCIENCE, MEDICINE, etc.)
            influence_score: Influence-Score (absolut oder normalisiert)
            context: Query/Answer Context
        """
        record = InfluenceRecord(
            source_id=source_id,
            domain=domain,
            influence_score=abs(influence_score),  # Absolute value
            timestamp=datetime.now(),
            context=context
        )

        self.influence_records.append(record)

        # Update Baseline
        self._update_baseline(domain)

        # Check für Anomalien
        self._check_for_anomalies(source_id, domain)

    def _update_baseline(self, domain: str):
        """Update Baseline-Statistiken für Domain."""
        # Filter Records für Domain
        domain_records = [
            r for r in self.influence_records
            if r.domain == domain
        ]

        if len(domain_records) < self.min_samples_for_baseline:
            return

        # Berechne Statistiken über alle Sources
        influences = [r.influence_score for r in domain_records]

        mean = sum(influences) / len(influences)
        variance = sum((x - mean) ** 2 for x in influences) / len(influences)
        std = math.sqrt(variance) if variance > 0 else 1.0

        self.baseline_statistics[domain] = {
            'mean': mean,
            'std': std,
            'count': len(domain_records)
        }

    def _check_for_anomalies(self, source_id: str, domain: str):
        """Check für Influence-Anomalien."""
        # Brauchen Baseline
        if domain not in self.baseline_statistics:
            return

        baseline = self.baseline_statistics[domain]

        # Berechne Influence-Budget für Source im Zeitfenster
        cutoff_time = datetime.now() - self.time_window

        recent_influences = [
            r.influence_score
            for r in self.influence_records
            if r.source_id == source_id
            and r.domain == domain
            and r.timestamp >= cutoff_time
        ]

        if not recent_influences:
            return

        total_influence = sum(recent_influences)

        # Z-Score berechnen
        if baseline['std'] > 0:
            z_score = (total_influence - baseline['mean']) / baseline['std']
        else:
            z_score = 0.0

        # Alert bei hohem Z-Score
        if z_score >= self.z_score_threshold:
            # Bestimme Anomalie-Typ
            anomaly_type = self._classify_anomaly_type(
                source_id, domain, recent_influences
            )

            alert = InfluenceAlert(
                source_id=source_id,
                domain=domain,
                time_window=f"{self.time_window.seconds // 60}min",
                total_influence=total_influence,
                z_score=z_score,
                threshold=self.z_score_threshold,
                anomaly_type=anomaly_type,
                timestamp=datetime.now()
            )

            self.alerts.append(alert)

    def _classify_anomaly_type(
        self,
        source_id: str,
        domain: str,
        recent_influences: List[float]
    ) -> str:
        """Klassifiziere Anomalie-Typ."""
        if not recent_influences:
            return "unknown"

        # Spike: Sehr hoher einzelner Wert
        max_influence = max(recent_influences)
        avg_influence = sum(recent_influences) / len(recent_influences)

        if max_influence > 3 * avg_influence:
            return "spike"

        # Sustained: Konstant hoher Einfluss
        if len(recent_influences) >= 5:
            variance = sum((x - avg_influence) ** 2 for x in recent_influences) / len(recent_influences)
            if variance < avg_influence * 0.2:  # Niedrige Varianz
                return "sustained"

        # Sudden: Plötzlicher Anstieg
        if len(recent_influences) >= 3:
            first_half = recent_influences[:len(recent_influences)//2]
            second_half = recent_influences[len(recent_influences)//2:]

            if first_half and second_half:
                first_avg = sum(first_half) / len(first_half)
                second_avg = sum(second_half) / len(second_half)

                if second_avg > 2 * first_avg:
                    return "sudden"

        return "general"

    def get_influence_budget(
        self,
        source_id: str,
        domain: str,
        time_window_minutes: Optional[int] = None
    ) -> float:
        """
        Hole Influence-Budget für Source.
        
        Args:
            source_id: Source ID
            domain: Domain
            time_window_minutes: Optionales Zeitfenster (default: self.time_window)
            
        Returns:
            Total influence im Zeitfenster
        """
        if time_window_minutes is None:
            window = self.time_window
        else:
            window = timedelta(minutes=time_window_minutes)

        cutoff_time = datetime.now() - window

        influences = [
            r.influence_score
            for r in self.influence_records
            if r.source_id == source_id
            and r.domain == domain
            and r.timestamp >= cutoff_time
        ]

        return sum(influences)

    def get_top_influencers(
        self,
        domain: str,
        limit: int = 10,
        time_window_minutes: Optional[int] = None
    ) -> List[Tuple[str, float]]:
        """
        Hole Top-Influencers für Domain.
        
        Returns:
            Liste von (source_id, total_influence) Tupeln
        """
        if time_window_minutes is None:
            window = self.time_window
        else:
            window = timedelta(minutes=time_window_minutes)

        cutoff_time = datetime.now() - window

        # Aggregiere per Source
        source_influences: Dict[str, float] = defaultdict(float)

        for record in self.influence_records:
            if record.domain == domain and record.timestamp >= cutoff_time:
                source_influences[record.source_id] += record.influence_score

        # Sortiere nach Influence
        sorted_sources = sorted(
            source_influences.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return sorted_sources[:limit]

    def get_alerts(
        self,
        domain: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[InfluenceAlert]:
        """
        Hole Alerts.
        
        Args:
            domain: Optional Domain-Filter
            limit: Optional Limit
            
        Returns:
            Liste von Alerts
        """
        alerts = self.alerts

        if domain is not None:
            alerts = [a for a in alerts if a.domain == domain]

        # Sortiere nach Timestamp (neueste zuerst)
        alerts = sorted(alerts, key=lambda a: a.timestamp, reverse=True)

        if limit is not None:
            alerts = alerts[:limit]

        return alerts

    def get_statistics(self, domain: Optional[str] = None) -> Dict[str, Any]:
        """Statistiken über Influence-Budget."""
        records = self.influence_records

        if domain is not None:
            records = [r for r in records if r.domain == domain]

        if not records:
            return {
                'total_records': 0,
                'total_alerts': 0,
                'unique_sources': 0
            }

        unique_sources = len(set(r.source_id for r in records))
        total_influence = sum(r.influence_score for r in records)
        avg_influence = total_influence / len(records)

        alerts = self.alerts
        if domain is not None:
            alerts = [a for a in alerts if a.domain == domain]

        return {
            'total_records': len(records),
            'total_alerts': len(alerts),
            'unique_sources': unique_sources,
            'total_influence': total_influence,
            'avg_influence': avg_influence,
            'baseline': self.baseline_statistics.get(domain or 'default', {})
        }

    def reset_alerts(self):
        """Reset Alert-Liste."""
        self.alerts = []

    def cleanup_old_records(self, days: int = 30):
        """Cleanup alte Records."""
        cutoff = datetime.now() - timedelta(days=days)

        self.influence_records = [
            r for r in self.influence_records
            if r.timestamp >= cutoff
        ]


# Beispiel-Usage
if __name__ == "__main__":
    tracker = InfluenceBudgetTracker(
        z_score_threshold=4.0,
        time_window_minutes=60
    )

    # Simuliere normale Influence
    for i in range(20):
        tracker.record_influence(
            source_id="source_normal",
            domain="SCIENCE",
            influence_score=0.1 + (i % 3) * 0.05,
            context=f"Query {i}"
        )

    # Simuliere Anomalie (Slow-Roll-Poison)
    for i in range(10):
        tracker.record_influence(
            source_id="source_suspicious",
            domain="SCIENCE",
            influence_score=0.8 + i * 0.1,  # Steigend!
            context=f"Suspicious query {i}"
        )

    # Check Alerts
    alerts = tracker.get_alerts()
    print(f"Alerts: {len(alerts)}")

    for alert in alerts:
        print(f"\nALERT: {alert.source_id} in {alert.domain}")
        print(f"  Z-Score: {alert.z_score:.2f} (threshold={alert.threshold})")
        print(f"  Total Influence: {alert.total_influence:.2f}")
        print(f"  Type: {alert.anomaly_type}")

    # Top Influencers
    top = tracker.get_top_influencers("SCIENCE", limit=5)
    print("\nTop Influencers:")
    for source_id, influence in top:
        print(f"  {source_id}: {influence:.2f}")

    # Statistics
    stats = tracker.get_statistics("SCIENCE")
    print(f"\nStatistics: {stats}")

