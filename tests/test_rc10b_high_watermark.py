"""
Unit Tests for RC10b High-Watermark Logic
==========================================

Testet, dass der High-Watermark-Mechanismus Dilution verhindert.

Creator: Joerg Bollwahn
Date: 2025-11-18
License: MIT
"""

import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

# Add paths
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))
sys.path.insert(0, str(project_root))

from llm_firewall.detectors.agentic_campaign import (
    AgenticCampaignDetector,
    CampaignDetectorConfig,
)
from llm_firewall.detectors.tool_killchain import ToolEvent


def create_tool_event(
    tool: str, category: str, target: str = "", timestamp: datetime = None
) -> ToolEvent:
    """Helper to create a ToolEvent."""
    if timestamp is None:
        timestamp = datetime.now()
    timestamp_float = (
        timestamp.timestamp() if isinstance(timestamp, datetime) else float(timestamp)
    )
    return ToolEvent(
        tool=tool,
        category=category,
        target=target,
        timestamp=timestamp_float,
    )


class TestHighWatermark(unittest.TestCase):
    """Test High-Watermark-Prinzip gegen Dilution."""

    def test_watermark_persistence(self):
        """
        Testet, ob der Score oben bleibt, auch wenn Noise folgt.

        Szenario: Erst Exfil (Phase 4), dann 50x Noise (Phase 1).
        Erwartung: Score bleibt >= 0.85 (Phase-4-Floor).
        """
        # 1. Config: Exfil (Phase 4) = 0.85 Risk
        config = CampaignDetectorConfig(
            phase_floors={4: 0.85},
            category_to_phase={"exfil": 4, "read": 1, "recon": 1},
            use_high_watermark=True,
            use_phase_floor=True,
        )
        detector = AgenticCampaignDetector(config=config)

        # 2. Events: Erst Exfil, dann Noise
        events = []
        base_time = datetime.now()

        # Event A: Exfiltration (Phase 4)
        events.append(
            create_tool_event(
                "stealer",
                "exfil",
                "evil.com",
                base_time,
            )
        )

        # Check 1: Muss blocken (Phase 4 Floor)
        report1 = detector.detect_campaign(
            events,
            session_id="test_watermark",
            operator_id="test_operator",
            scope="internal",
            authorized=False,
        )
        score1 = report1.get("combined_risk_score", 0.0)

        self.assertGreaterEqual(
            score1,
            0.85,
            f"Phase 4 Event muss Score auf >= 0.85 heben, got {score1:.4f}",
        )

        # Event B: Viel Noise (Dilution Versuch)
        for i in range(50):
            events.append(
                create_tool_event(
                    "read_file",
                    "read",
                    f"doc_{i}.txt",
                    base_time + timedelta(minutes=i),
                )
            )

        # Check 2: Muss IMMER NOCH blocken (Watermark)
        report2 = detector.detect_campaign(
            events,
            session_id="test_watermark",
            operator_id="test_operator",
            scope="internal",
            authorized=False,
        )
        score2 = report2.get("combined_risk_score", 0.0)

        print(f"\n  Score after Exfil: {score1:.4f}")
        print(f"  Score with 50 Noise Events: {score2:.4f}")

        self.assertGreaterEqual(
            score2,
            0.85,
            f"High-Watermark muss Score oben halten trotz Noise, got {score2:.4f}",
        )
        self.assertGreaterEqual(
            score2,
            score1,
            f"High-Watermark darf Score nicht senken, got {score2:.4f} < {score1:.4f}",
        )

    def test_watermark_without_critical_phase(self):
        """
        Testet, dass High-Watermark nicht greift, wenn keine Critical Phase erreicht wurde.

        Szenario: Nur Phase 1 Events (Recon).
        Erwartung: Kein Floor angewendet (Score bleibt niedrig).
        """
        config = CampaignDetectorConfig(
            phase_floors={3: 0.50, 4: 0.85},
            category_to_phase={"recon": 1, "read": 1},
            use_high_watermark=True,
            use_phase_floor=True,
        )
        detector = AgenticCampaignDetector(config=config)

        # Nur Phase 1 Events
        events = []
        for i in range(20):
            events.append(
                create_tool_event(
                    "read_file",
                    "recon",
                    f"doc_{i}.txt",
                    datetime.now() + timedelta(minutes=i),
                )
            )

        report = detector.detect_campaign(
            events,
            session_id="test_no_critical",
            operator_id="test_operator",
            scope="internal",
            authorized=False,
        )
        score = report.get("combined_risk_score", 0.0)

        # Score sollte niedrig bleiben (kein Floor für Phase 1)
        self.assertLess(
            score,
            0.50,
            f"Score sollte niedrig bleiben ohne Critical Phase, got {score:.4f}",
        )

    def test_watermark_phase_3_floor(self):
        """
        Testet, dass Phase 3 Floor greift.

        Szenario: Phase 3 Event (Collection), dann Noise.
        Erwartung: Score bleibt >= 0.50 (Phase-3-Floor).
        """
        config = CampaignDetectorConfig(
            phase_floors={3: 0.50, 4: 0.85},
            category_to_phase={"collection": 3, "read": 1},
            use_high_watermark=True,
            use_phase_floor=True,
        )
        detector = AgenticCampaignDetector(config=config)

        events = []
        base_time = datetime.now()

        # Phase 3 Event
        events.append(
            create_tool_event(
                "db_query",
                "collection",
                "users",
                base_time,
            )
        )

        # Check 1: Phase 3 Floor
        report1 = detector.detect_campaign(
            events,
            session_id="test_phase3",
            operator_id="test_operator",
            scope="internal",
            authorized=False,
        )
        score1 = report1.get("combined_risk_score", 0.0)

        self.assertGreaterEqual(
            score1,
            0.50,
            f"Phase 3 Event muss Score auf >= 0.50 heben, got {score1:.4f}",
        )

        # Noise hinzufügen
        for i in range(30):
            events.append(
                create_tool_event(
                    "read_file",
                    "read",
                    f"doc_{i}.txt",
                    base_time + timedelta(minutes=i),
                )
            )

        # Check 2: Watermark hält
        report2 = detector.detect_campaign(
            events,
            session_id="test_phase3",
            operator_id="test_operator",
            scope="internal",
            authorized=False,
        )
        score2 = report2.get("combined_risk_score", 0.0)

        self.assertGreaterEqual(
            score2, 0.50, f"High-Watermark muss Phase-3-Floor halten, got {score2:.4f}"
        )

    def test_watermark_disabled(self):
        """
        Testet, dass High-Watermark deaktiviert werden kann.

        Szenario: Phase 4 Event, dann Noise, aber use_high_watermark=False.
        Erwartung: Score kann durch Noise sinken (kein Watermark).
        """
        config = CampaignDetectorConfig(
            phase_floors={4: 0.85},
            category_to_phase={"exfil": 4, "read": 1},
            use_high_watermark=False,  # Deaktiviert
            use_phase_floor=True,
        )
        detector = AgenticCampaignDetector(config=config)

        events = []
        base_time = datetime.now()

        # Phase 4 Event
        events.append(
            create_tool_event(
                "stealer",
                "exfil",
                "evil.com",
                base_time,
            )
        )

        # Viel Noise
        for i in range(50):
            events.append(
                create_tool_event(
                    "read_file",
                    "read",
                    f"doc_{i}.txt",
                    base_time + timedelta(minutes=i),
                )
            )

        report = detector.detect_campaign(
            events,
            session_id="test_no_watermark",
            operator_id="test_operator",
            scope="internal",
            authorized=False,
        )
        score = report.get("combined_risk_score", 0.0)

        # Ohne High-Watermark kann der Score durch Noise sinken
        # (Dies ist das erwartete Verhalten, wenn Watermark deaktiviert ist)
        print(f"\n  Score without High-Watermark: {score:.4f}")
        # Wir testen nur, dass es nicht abstürzt und einen Score zurückgibt
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


if __name__ == "__main__":
    unittest.main()
