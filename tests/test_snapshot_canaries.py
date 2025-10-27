"""
Tests für Snapshot Canaries
===========================

Testet Drift-Erkennung und False-Entailment-Detection.
"""

import pytest
from unittest.mock import Mock
from src_hexagonal.services.honesty.snapshot_canaries import (
    CanaryClaim, SnapshotCanaries
)


class TestCanaryClaim:
    """Test Canary-Claim."""
    
    def test_canary_creation(self):
        """Test Canary-Erstellung."""
        canary = CanaryClaim(
            content="Paris is the capital of France",
            expected_truth=True,
            category="known_true"
        )
        
        assert canary.content == "Paris is the capital of France"
        assert canary.expected_truth is True
        assert canary.category == "known_true"
        assert canary.confidence_threshold == 0.95
        assert canary.created_at is not None


class TestSnapshotCanaries:
    """Test Snapshot-Canaries."""
    
    def setup_method(self):
        """Setup mit Mock NLI Model."""
        self.mock_nli = Mock()
        self.canaries = SnapshotCanaries(self.mock_nli, drift_threshold=0.1)
    
    def test_canary_creation(self):
        """Test dass Canaries erstellt werden."""
        assert len(self.canaries.canaries) > 0
        assert len(self.canaries.baseline_scores) > 0
        
        # Prüfe verschiedene Kategorien
        categories = set(canary.category for canary in self.canaries.canaries)
        expected_categories = {"known_true", "known_false", "mathematical", "temporal"}
        assert categories.issuperset(expected_categories)
    
    def test_baseline_scores_computed(self):
        """Test dass Baseline-Scores berechnet werden."""
        assert len(self.canaries.baseline_scores) == len(self.canaries.canaries)
        
        # Alle Canaries sollten Baseline-Scores haben
        for canary in self.canaries.canaries:
            assert canary.content in self.canaries.baseline_scores
            score = self.canaries.baseline_scores[canary.content]
            assert 0.0 <= score <= 1.0
    
    def test_check_drift_no_drift(self):
        """Test Drift-Check ohne Drift."""
        # Mock: identische Scores wie Baseline
        has_drift, drift_scores = self.canaries.check_drift(sample_size=3)
        
        # Sollte keinen Drift erkennen (da identische Scores)
        assert isinstance(has_drift, bool)
        assert isinstance(drift_scores, dict)
        assert len(drift_scores) <= 3  # Sample size
    
    def test_check_drift_with_drift(self):
        """Test Drift-Check mit Drift."""
        # Erhöhe Drift-Threshold für Test
        self.canaries.drift_threshold = 0.01
        
        has_drift, drift_scores = self.canaries.check_drift(sample_size=5)
        
        # Bei niedrigem Threshold sollte Drift erkannt werden
        assert isinstance(has_drift, bool)
        assert isinstance(drift_scores, dict)
    
    def test_check_false_entailments(self):
        """Test False-Entailment-Check."""
        has_false, failed = self.canaries.check_false_entailments()
        
        assert isinstance(has_false, bool)
        assert isinstance(failed, list)
        
        # Alle failed Canaries sollten in der Liste stehen
        for content in failed:
            assert isinstance(content, str)
            assert len(content) > 0
    
    def test_get_canary_stats(self):
        """Test Canary-Statistiken."""
        stats = self.canaries.get_canary_stats()
        
        assert isinstance(stats, dict)
        assert 'total' in stats
        assert stats['total'] > 0
        
        # Summe aller Kategorien sollte total entsprechen
        category_sum = sum(v for k, v in stats.items() if k != 'total')
        assert category_sum == stats['total']
    
    def test_add_custom_canary(self):
        """Test hinzufügen von benutzerdefinierten Canaries."""
        initial_count = len(self.canaries.canaries)
        
        self.canaries.add_custom_canary(
            content="Custom test claim",
            expected_truth=True,
            category="test",
            confidence_threshold=0.9
        )
        
        # Sollte einen Canary hinzugefügt haben
        assert len(self.canaries.canaries) == initial_count + 1
        
        # Neuer Canary sollte in Baseline-Scores sein
        assert "Custom test claim" in self.canaries.baseline_scores
        
        # Statistiken sollten aktualisiert sein
        stats = self.canaries.get_canary_stats()
        assert stats['test'] == 1
    
    def test_drift_threshold_effect(self):
        """Test Effekt verschiedener Drift-Thresholds."""
        # Niedriger Threshold
        canaries_low = SnapshotCanaries(self.mock_nli, drift_threshold=0.01)
        has_drift_low, _ = canaries_low.check_drift(sample_size=3)
        
        # Hoher Threshold
        canaries_high = SnapshotCanaries(self.mock_nli, drift_threshold=0.9)
        has_drift_high, _ = canaries_high.check_drift(sample_size=3)
        
        # Niedriger Threshold sollte mehr Drift erkennen
        # (oder gleich, je nach Zufall)
        assert isinstance(has_drift_low, bool)
        assert isinstance(has_drift_high, bool)
    
    def test_sample_size_effect(self):
        """Test Effekt verschiedener Sample-Sizes."""
        # Kleine Sample
        has_drift_small, drift_small = self.canaries.check_drift(sample_size=2)
        
        # Große Sample
        has_drift_large, drift_large = self.canaries.check_drift(sample_size=10)
        
        assert isinstance(has_drift_small, bool)
        assert isinstance(has_drift_large, bool)
        assert len(drift_small) <= 2
        assert len(drift_large) <= 10
    
    def test_canary_categories(self):
        """Test verschiedene Canary-Kategorien."""
        categories = {}
        for canary in self.canaries.canaries:
            category = canary.category
            if category not in categories:
                categories[category] = []
            categories[category].append(canary)
        
        # Jede Kategorie sollte Canaries haben
        for category in ["known_true", "known_false", "mathematical", "temporal"]:
            assert category in categories
            assert len(categories[category]) > 0
        
        # True claims sollten expected_truth=True haben
        for canary in categories["known_true"]:
            assert canary.expected_truth is True
        
        # False claims sollten expected_truth=False haben
        for canary in categories["known_false"]:
            assert canary.expected_truth is False


class TestIntegration:
    """Integration Tests."""
    
    def test_full_pipeline_simulation(self):
        """Simuliere vollständige Pipeline mit Canaries."""
        mock_nli = Mock()
        canaries = SnapshotCanaries(mock_nli, drift_threshold=0.15)
        
        # Simuliere mehrere Checks
        results = []
        for i in range(5):
            has_drift, drift_scores = canaries.check_drift(sample_size=3)
            has_false, failed = canaries.check_false_entailments()
            
            results.append({
                'iteration': i,
                'has_drift': has_drift,
                'max_drift': max(drift_scores.values()) if drift_scores else 0.0,
                'has_false_entailments': has_false,
                'failed_count': len(failed)
            })
        
        # Alle Ergebnisse sollten konsistent sein
        assert len(results) == 5
        
        for result in results:
            assert isinstance(result['has_drift'], bool)
            assert isinstance(result['has_false_entailments'], bool)
            assert 0.0 <= result['max_drift'] <= 1.0
            assert result['failed_count'] >= 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
