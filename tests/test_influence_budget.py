"""
Tests für Influence-Budget Tracker
==================================

Testet Slow-Roll-Poison Detection via Influence-Tracking.
"""

import pytest

from llm_firewall.monitoring.influence_budget import (
    InfluenceAlert,
    InfluenceBudgetTracker,
)


class TestInfluenceBudgetTracker:
    """Test Influence-Budget Tracker."""

    def setup_method(self):
        """Setup Tracker."""
        self.tracker = InfluenceBudgetTracker(
            z_score_threshold=4.0, time_window_minutes=60, min_samples_for_baseline=10
        )

    def test_record_influence(self):
        """Test Influence-Recording."""
        self.tracker.record_influence(
            source_id="test_source",
            domain="SCIENCE",
            influence_score=0.5,
            context="Test context",
        )

        assert len(self.tracker.influence_records) == 1
        record = self.tracker.influence_records[0]

        assert record.source_id == "test_source"
        assert record.domain == "SCIENCE"
        assert record.influence_score == 0.5

    def test_baseline_update(self):
        """Test Baseline-Update."""
        # Genug Samples für Baseline
        for i in range(15):
            self.tracker.record_influence(
                source_id=f"source_{i}",
                domain="SCIENCE",
                influence_score=0.1 + i * 0.01,
                context=f"Context {i}",
            )

        # Baseline sollte erstellt sein
        assert "SCIENCE" in self.tracker.baseline_statistics
        baseline = self.tracker.baseline_statistics["SCIENCE"]

        assert "mean" in baseline
        assert "std" in baseline
        assert "count" in baseline
        assert baseline["count"] >= 10

    def test_anomaly_detection(self):
        """Test Anomalie-Erkennung."""
        # Normale Baseline erstellen
        for i in range(15):
            self.tracker.record_influence(
                source_id="normal",
                domain="SCIENCE",
                influence_score=0.1,
                context=f"Normal {i}",
            )

        # Anomalie triggern
        for i in range(10):
            self.tracker.record_influence(
                source_id="anomalous",
                domain="SCIENCE",
                influence_score=1.0,  # Sehr hoch!
                context=f"Anomaly {i}",
            )

        # Sollte Alerts haben
        alerts = self.tracker.get_alerts(domain="SCIENCE")
        assert len(alerts) > 0

        # Check Alert-Struktur
        alert = alerts[0]
        assert isinstance(alert, InfluenceAlert)
        assert alert.z_score >= self.tracker.z_score_threshold

    def test_get_influence_budget(self):
        """Test Influence-Budget Abruf."""
        # Füge Influences hinzu
        for i in range(5):
            self.tracker.record_influence(
                source_id="test_source",
                domain="SCIENCE",
                influence_score=0.2,
                context=f"Test {i}",
            )

        budget = self.tracker.get_influence_budget(
            source_id="test_source", domain="SCIENCE"
        )

        assert budget > 0
        assert budget == pytest.approx(1.0, abs=0.01)  # 5 * 0.2

    def test_get_top_influencers(self):
        """Test Top-Influencers Abruf."""
        # Füge verschiedene Sources hinzu
        sources = [("source_A", 0.5, 3), ("source_B", 0.3, 5), ("source_C", 0.8, 2)]

        for source_id, score, count in sources:
            for i in range(count):
                self.tracker.record_influence(
                    source_id=source_id,
                    domain="SCIENCE",
                    influence_score=score,
                    context=f"{source_id}_{i}",
                )

        top = self.tracker.get_top_influencers("SCIENCE", limit=3)

        assert len(top) <= 3
        assert isinstance(top, list)

        # Sollte nach Influence sortiert sein
        if len(top) > 1:
            assert top[0][1] >= top[1][1]

    def test_anomaly_type_classification(self):
        """Test Anomalie-Typ-Klassifikation."""
        # Baseline
        for i in range(15):
            self.tracker.record_influence(
                source_id="baseline",
                domain="SCIENCE",
                influence_score=0.1,
                context=f"Baseline {i}",
            )

        # Spike
        self.tracker.record_influence(
            source_id="spike_source",
            domain="SCIENCE",
            influence_score=5.0,  # Sehr hoher Spike!
            context="Spike",
        )

        # Sustained
        for i in range(10):
            self.tracker.record_influence(
                source_id="sustained_source",
                domain="SCIENCE",
                influence_score=1.0,  # Konstant hoch
                context=f"Sustained {i}",
            )

        alerts = self.tracker.get_alerts(domain="SCIENCE")

        # Sollte verschiedene Anomalie-Typen haben
        anomaly_types = set(alert.anomaly_type for alert in alerts)
        assert len(anomaly_types) > 0

    def test_get_statistics(self):
        """Test Statistiken."""
        # Füge Records hinzu
        for i in range(10):
            self.tracker.record_influence(
                source_id=f"source_{i % 3}",
                domain="SCIENCE",
                influence_score=0.2 + i * 0.01,
                context=f"Test {i}",
            )

        stats = self.tracker.get_statistics(domain="SCIENCE")

        assert "total_records" in stats
        assert "total_alerts" in stats
        assert "unique_sources" in stats
        assert "total_influence" in stats
        assert "avg_influence" in stats

        assert stats["total_records"] == 10
        assert stats["unique_sources"] == 3

    def test_reset_alerts(self):
        """Test Alert-Reset."""
        # Erstelle Baseline + Anomalie
        for i in range(15):
            self.tracker.record_influence(
                source_id="normal",
                domain="SCIENCE",
                influence_score=0.1,
                context=f"Normal {i}",
            )

        for i in range(5):
            self.tracker.record_influence(
                source_id="anomaly",
                domain="SCIENCE",
                influence_score=1.5,
                context=f"Anomaly {i}",
            )

        # Sollte Alerts haben
        assert len(self.tracker.get_alerts()) > 0

        # Reset
        self.tracker.reset_alerts()

        # Sollte keine Alerts mehr haben
        assert len(self.tracker.get_alerts()) == 0

    def test_cleanup_old_records(self):
        """Test Cleanup alter Records."""
        # Füge Records hinzu
        initial_count = len(self.tracker.influence_records)

        for i in range(5):
            self.tracker.record_influence(
                source_id="test",
                domain="SCIENCE",
                influence_score=0.1,
                context=f"Test {i}",
            )

        assert len(self.tracker.influence_records) == initial_count + 5

        # Cleanup (sollte nichts löschen da alle neu)
        self.tracker.cleanup_old_records(days=30)

        assert len(self.tracker.influence_records) == initial_count + 5


class TestIntegration:
    """Integration Tests."""

    def test_slow_roll_poison_detection(self):
        """Test Slow-Roll-Poison-Detection."""
        tracker = InfluenceBudgetTracker(
            z_score_threshold=3.0,  # Niedriger für Test
            time_window_minutes=60,
            min_samples_for_baseline=10,
        )

        # Simuliere normale Sources
        for i in range(20):
            tracker.record_influence(
                source_id="normal_1",
                domain="SCIENCE",
                influence_score=0.1,
                context=f"Normal query {i}",
            )

            tracker.record_influence(
                source_id="normal_2",
                domain="SCIENCE",
                influence_score=0.12,
                context=f"Normal query {i}",
            )

        # Simuliere Slow-Roll-Attack (graduell steigend)
        for i in range(15):
            tracker.record_influence(
                source_id="attacker",
                domain="SCIENCE",
                influence_score=0.2 + i * 0.1,  # Steigend!
                context=f"Attack query {i}",
            )

        # Check Alerts
        alerts = tracker.get_alerts(domain="SCIENCE")

        # Sollte Attacker-Alerts haben
        attacker_alerts = [a for a in alerts if a.source_id == "attacker"]
        assert len(attacker_alerts) > 0

        # Check Top-Influencers
        top = tracker.get_top_influencers("SCIENCE", limit=5)
        top_ids = [source_id for source_id, _ in top]

        # Attacker sollte in Top sein
        assert "attacker" in top_ids

    def test_multi_domain_tracking(self):
        """Test Multi-Domain-Tracking."""
        tracker = InfluenceBudgetTracker(
            z_score_threshold=4.0, time_window_minutes=60, min_samples_for_baseline=5
        )

        # Verschiedene Domains
        domains = ["SCIENCE", "MEDICINE", "GENERAL"]

        for domain in domains:
            for i in range(10):
                tracker.record_influence(
                    source_id=f"source_{domain}",
                    domain=domain,
                    influence_score=0.1 + i * 0.02,
                    context=f"{domain} query {i}",
                )

        # Check Stats per Domain
        for domain in domains:
            stats = tracker.get_statistics(domain=domain)
            assert stats["total_records"] == 10
            assert stats["unique_sources"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
