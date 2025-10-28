"""
Unit Tests for Explanation Formatter
=====================================

Tests:
1. High directness formatting (Joerg's style)
2. Moderate directness
3. Low directness (polite)
4. Precision priority affects number display
5. Detail level affects explanation length
"""

import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from llm_firewall.engines.explanation_formatter import (
    HonestyExplanationFormatter,
    format_for_joerg
)
from llm_firewall.utils.types import (
    HonestyDecision,
    GroundTruthScore
)


class TestExplanationFormatter:
    """Test suite for HonestyExplanationFormatter"""
    
    def setup_method(self):
        """Setup before each test"""
        self.formatter = HonestyExplanationFormatter()
        
        # Create sample GT breakdown
        self.gt_breakdown = GroundTruthScore(
            overall_score=0.45,
            kb_coverage=0.30,
            source_quality=0.50,
            recency_score=0.60,
            kb_fact_count=3,
            source_count=2,
            verified_source_count=0,
            days_since_newest=100,
            domain='SCIENCE',
            domain_half_life=1825,
            query="Test query"
        )
        
        # Create sample decision
        self.abstention_decision = HonestyDecision(
            decision='ABSTAIN',
            reasoning="GT insufficient",
            gt_score=0.45,
            threshold_used=0.80,
            confidence=0.70,
            margin=-0.35,
            gt_breakdown=self.gt_breakdown,
            user_id='joerg',
            user_strictness=0.975,
            decision_id='test-id',
            sanity_override=False
        )
    
    def test_high_directness_abstention(self):
        """Test: High directness (>0.8) produces direct NEIN message"""
        result = self.formatter.format_decision(
            self.abstention_decision,
            directness=0.95,
            precision_priority=0.95,
            detail_level=0.9
        )
        
        # Should start with NEIN
        assert result.startswith("NEIN")
        
        # Should contain exact percentages
        assert "45%" in result or "45.0%" in result
        assert "80%" in result or "80.0%" in result
        
        # Should list missing evidence
        assert "KB Facts" in result
        assert "Sources" in result
    
    def test_moderate_directness_abstention(self):
        """Test: Moderate directness (0.5-0.8) is polite but clear"""
        result = self.formatter.format_decision(
            self.abstention_decision,
            directness=0.6,
            precision_priority=0.5,
            detail_level=0.5
        )
        
        # Should NOT start with NEIN (more polite)
        assert not result.startswith("NEIN")
        
        # Should still be clear
        assert "nicht" in result.lower() or "can" in result.lower()
        
        # Should mention problem
        assert "Problem" in result or "Grund" in result
    
    def test_low_directness_abstention(self):
        """Test: Low directness (<0.5) is very polite"""
        result = self.formatter.format_decision(
            self.abstention_decision,
            directness=0.3,
            precision_priority=0.3,
            detail_level=0.3
        )
        
        # Should be very polite
        assert "basierend" in result.lower() or "leider" in result.lower()
        
        # Should be less direct
        assert "NEIN" not in result
    
    def test_precision_priority_affects_numbers(self):
        """Test: High precision shows more numbers"""
        high_precision = self.formatter.format_decision(
            self.abstention_decision,
            directness=0.95,
            precision_priority=0.95,
            detail_level=0.9
        )
        
        low_precision = self.formatter.format_decision(
            self.abstention_decision,
            directness=0.95,
            precision_priority=0.3,
            detail_level=0.9
        )
        
        # High precision should have more "%" signs
        assert high_precision.count('%') > low_precision.count('%')
    
    def test_detail_level_affects_length(self):
        """Test: High detail level produces longer explanations"""
        high_detail = self.formatter.format_decision(
            self.abstention_decision,
            directness=0.95,
            precision_priority=0.95,
            detail_level=0.9
        )
        
        low_detail = self.formatter.format_decision(
            self.abstention_decision,
            directness=0.95,
            precision_priority=0.95,
            detail_level=0.3
        )
        
        # High detail should be longer
        assert len(high_detail) > len(low_detail)
    
    def test_joerg_convenience_function(self):
        """Test: format_for_joerg uses correct defaults"""
        result = format_for_joerg(self.abstention_decision)
        
        # Should be direct
        assert result.startswith("NEIN")
        
        # Should have numbers
        assert '%' in result
        
        # Should have breakdown
        assert "Komponenten" in result or "KB Facts" in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

