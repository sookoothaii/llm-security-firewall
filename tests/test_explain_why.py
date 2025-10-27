"""
Tests für Explain-Why Engine
============================

Testet structured reasoning chains für Promotions.
"""

import pytest
from src_hexagonal.services.honesty.explain_why import (
    EvidenceItem, PromotionReasoning, ExplainWhyEngine
)


class TestEvidenceItem:
    """Test Evidence-Item."""
    
    def test_evidence_item_creation(self):
        """Test Evidence-Item-Erstellung."""
        item = EvidenceItem(
            type="trust",
            value=0.95,
            weight=0.3,
            contribution="High trust from Nature"
        )
        
        assert item.type == "trust"
        assert item.value == 0.95
        assert item.weight == 0.3
        assert "trust" in item.contribution.lower()


class TestExplainWhyEngine:
    """Test Explain-Why Engine."""
    
    def setup_method(self):
        """Setup Engine."""
        self.engine = ExplainWhyEngine(require_minimum_evidence=2)
    
    def test_create_reasoning_promote(self):
        """Test Reasoning für PROMOTE."""
        reasoning = self.engine.create_reasoning(
            decision_id="test_001",
            decision="PROMOTE",
            confidence=0.92,
            trust_score=0.95,
            nli_score=0.88,
            corroboration_count=3,
            kb_facts=["Fact 1", "Fact 2"],
            sources=[{"name": "Nature", "verified": True}],
            domain="SCIENCE",
            threshold=0.75
        )
        
        assert reasoning.decision == "PROMOTE"
        assert reasoning.confidence == 0.92
        assert len(reasoning.evidence_chain) > 0
        assert "PROMOTED" in reasoning.reasoning_summary
    
    def test_create_reasoning_quarantine(self):
        """Test Reasoning für QUARANTINE."""
        reasoning = self.engine.create_reasoning(
            decision_id="test_002",
            decision="QUARANTINE",
            confidence=0.65,
            trust_score=0.60,
            nli_score=0.55,
            corroboration_count=1,
            kb_facts=["Single fact"],
            sources=[{"name": "Blog", "verified": False}],
            domain="MEDICINE",
            threshold=0.75
        )
        
        assert reasoning.decision == "QUARANTINE"
        assert "QUARANTINED" in reasoning.reasoning_summary
        assert reasoning.confidence < 0.75
    
    def test_reasoning_to_json(self):
        """Test JSON-Serialisierung."""
        reasoning = self.engine.create_reasoning(
            decision_id="test_003",
            decision="PROMOTE",
            confidence=0.90,
            trust_score=0.85,
            nli_score=0.80,
            corroboration_count=2,
            kb_facts=[],
            sources=[],
            domain="SCIENCE",
            threshold=0.75
        )
        
        json_str = reasoning.to_json()
        
        assert isinstance(json_str, str)
        assert "decision_id" in json_str
        assert "PROMOTE" in json_str
    
    def test_reasoning_to_audit_log(self):
        """Test Audit-Log-Format."""
        reasoning = self.engine.create_reasoning(
            decision_id="test_004",
            decision="REJECT",
            confidence=0.40,
            trust_score=0.30,
            nli_score=0.25,
            corroboration_count=0,
            kb_facts=[],
            sources=[],
            domain="GENERAL",
            threshold=0.75
        )
        
        audit_log = reasoning.to_audit_log()
        
        assert isinstance(audit_log, str)
        assert "Decision ID:" in audit_log
        assert "Evidence Chain" in audit_log
        assert "REJECT" in audit_log
    
    def test_validate_reasoning_valid(self):
        """Test Validation bei gültigem Reasoning."""
        reasoning = self.engine.create_reasoning(
            decision_id="test_005",
            decision="PROMOTE",
            confidence=0.85,
            trust_score=0.80,
            nli_score=0.75,
            corroboration_count=2,
            kb_facts=["Fact"],
            sources=[{"name": "Source"}],
            domain="SCIENCE",
            threshold=0.75
        )
        
        is_valid = self.engine.validate_reasoning(reasoning)
        
        assert is_valid is True
    
    def test_get_reasoning_by_id(self):
        """Test Abruf by ID."""
        reasoning = self.engine.create_reasoning(
            decision_id="test_006",
            decision="PROMOTE",
            confidence=0.90,
            trust_score=0.85,
            nli_score=0.80,
            corroboration_count=2,
            kb_facts=[],
            sources=[],
            domain="SCIENCE",
            threshold=0.75
        )
        
        retrieved = self.engine.get_reasoning_by_id("test_006")
        
        assert retrieved is not None
        assert retrieved.decision_id == "test_006"
    
    def test_get_recent_reasoning(self):
        """Test Abruf recent Reasoning."""
        # Erstelle mehrere Reasonings
        for i in range(5):
            self.engine.create_reasoning(
                decision_id=f"test_00{i}",
                decision="PROMOTE",
                confidence=0.85,
                trust_score=0.80,
                nli_score=0.75,
                corroboration_count=2,
                kb_facts=[],
                sources=[],
                domain="SCIENCE",
                threshold=0.75
            )
        
        recent = self.engine.get_recent_reasoning(limit=3)
        
        assert len(recent) == 3
        assert all(isinstance(r, PromotionReasoning) for r in recent)
    
    def test_export_for_regression(self):
        """Test Export für Regression-Analysis."""
        # Erstelle mehrere Reasonings
        for i in range(3):
            self.engine.create_reasoning(
                decision_id=f"test_reg_{i}",
                decision="PROMOTE",
                confidence=0.85 + i * 0.02,
                trust_score=0.80,
                nli_score=0.75,
                corroboration_count=2,
                kb_facts=[],
                sources=[],
                domain="SCIENCE",
                threshold=0.75
            )
        
        export_data = self.engine.export_reasoning_for_regression()
        
        assert isinstance(export_data, list)
        assert len(export_data) >= 3
        
        # Prüfe Struktur
        for item in export_data:
            assert 'decision' in item
            assert 'confidence' in item
            assert 'domain' in item
    
    def test_get_statistics(self):
        """Test Statistiken."""
        # Erstelle verschiedene Decisions
        self.engine.create_reasoning(
            decision_id="stat_1",
            decision="PROMOTE",
            confidence=0.90,
            trust_score=0.85,
            nli_score=0.80,
            corroboration_count=3,
            kb_facts=[],
            sources=[],
            domain="SCIENCE",
            threshold=0.75
        )
        
        self.engine.create_reasoning(
            decision_id="stat_2",
            decision="QUARANTINE",
            confidence=0.60,
            trust_score=0.55,
            nli_score=0.50,
            corroboration_count=1,
            kb_facts=[],
            sources=[],
            domain="SCIENCE",
            threshold=0.75
        )
        
        stats = self.engine.get_statistics()
        
        assert stats['total'] >= 2
        assert stats['promote'] >= 1
        assert stats['quarantine'] >= 1
        assert 'avg_confidence' in stats
        assert 'avg_evidence_count' in stats


class TestIntegration:
    """Integration Tests."""
    
    def test_full_reasoning_pipeline(self):
        """Test vollständige Reasoning-Pipeline."""
        engine = ExplainWhyEngine(require_minimum_evidence=2)
        
        # Erstelle Reasoning
        reasoning = engine.create_reasoning(
            decision_id="integration_test",
            decision="PROMOTE",
            confidence=0.92,
            trust_score=0.95,
            nli_score=0.88,
            corroboration_count=3,
            kb_facts=["Fact 1", "Fact 2", "Fact 3"],
            sources=[
                {"name": "Nature", "verified": True},
                {"name": "Science", "verified": True}
            ],
            domain="SCIENCE",
            threshold=0.75,
            metadata={"query": "Test query"}
        )
        
        # Validate
        assert engine.validate_reasoning(reasoning) is True
        
        # JSON Export
        json_str = reasoning.to_json()
        assert len(json_str) > 0
        
        # Audit Log
        audit_log = reasoning.to_audit_log()
        assert "Evidence Chain" in audit_log
        
        # Retrieve
        retrieved = engine.get_reasoning_by_id("integration_test")
        assert retrieved.decision_id == "integration_test"
        
        # Statistics
        stats = engine.get_statistics()
        assert stats['total'] >= 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
