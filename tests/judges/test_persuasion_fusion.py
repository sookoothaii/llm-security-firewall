"""
Tests for Persuasion Fusion Judge
==================================

Creator: Joerg Bollwahn
Date: 2025-10-30
"""

from datetime import datetime
from pathlib import Path

from llm_firewall.core.types import ModelContext
from llm_firewall.judges.persuasion_fusion import PersuasionFusionJudge
from llm_firewall.persuasion import PersuasionDetector
from llm_firewall.safety.band_judge import BandJudge


class TestPersuasionFusionJudge:
    """Test fusion of persuasion detector and band-judge."""

    def test_judge_initialization(self):
        """Test judge can be created."""
        lex_dir = Path(__file__).parent.parent.parent / "src" / "llm_firewall" / "lexicons" / "persuasion"

        detector = PersuasionDetector(lex_dir)
        band_judge = BandJudge(None)  # No API key for test

        judge = PersuasionFusionJudge(detector, band_judge)

        assert judge.name == "persuasion_fusion"
        assert judge.version == "1.1.0"  # Updated to 1.1.0 (Phase 1 improvements)

    def test_score_benign_text(self):
        """Test benign text scores low risk."""
        lex_dir = Path(__file__).parent.parent.parent / "src" / "llm_firewall" / "lexicons" / "persuasion"

        detector = PersuasionDetector(lex_dir)
        band_judge = BandJudge(None)
        judge = PersuasionFusionJudge(detector, band_judge)

        ctx = ModelContext(
            session_id="test",
            request_id="req1",
            user_id="user1",
            model_id="test-model",
            prompt_hash="abc123",
            time_utc=datetime.now()
        )

        report = judge.score(ctx, "Hello, how are you?", "I'm doing well, thanks!")

        assert report.name == "persuasion_fusion"
        assert report.risks.overall.value < 0.5
        assert report.latency_ms > 0

    def test_score_persuasive_text(self):
        """Test persuasive text scores higher risk."""
        lex_dir = Path(__file__).parent.parent.parent / "src" / "llm_firewall" / "lexicons" / "persuasion"

        detector = PersuasionDetector(lex_dir)
        band_judge = BandJudge(None)
        judge = PersuasionFusionJudge(detector, band_judge)

        ctx = ModelContext("test", "req1", None, "model", "hash", datetime.now())

        # Authority + scarcity persuasion
        text = "As an expert, I must tell you this limited-time offer is urgent."

        report = judge.score(ctx, text, "")

        # Should detect persuasion patterns
        assert len(report.risks.categories) > 0
        assert report.features["persuasion_signals"] > 0

