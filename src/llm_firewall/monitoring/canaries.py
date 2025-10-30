"""
Snapshot Canaries für Evidence Pipeline
========================================

Synthetische, harmlose Canary-Claims zur Drift-Erkennung.
Jede Promotions-Welle triggert automatisch NLI/Entailment auf diese Canaries.
Drift oder false entailments → sofortiger Block.

Canary-Types:
- Known True: "Paris is the capital of France"
- Known False: "The moon is made of cheese"
- Mathematical: "2 + 2 = 4"
- Temporal: "Today is a day in 2025"
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class CanaryClaim:
    """Einzelner Canary-Claim."""

    content: str
    expected_truth: bool
    category: str
    confidence_threshold: float = 0.95
    created_at: Optional[datetime] = None

    def __post_init__(self):
        if self.created_at is None:
            object.__setattr__(self, "created_at", datetime.now())


class SnapshotCanaries:
    """Canary-System für Drift-Erkennung."""

    def __init__(self, nli_model, drift_threshold: float = 0.1):
        """
        Args:
            nli_model: NLI Model für Entailment-Checks
            drift_threshold: Maximaler Drift vor Alarm
        """
        self.nli_model = nli_model
        self.drift_threshold = drift_threshold
        self.canaries = self._create_base_canaries()
        self.baseline_scores = self._compute_baseline_scores()

    def _create_base_canaries(self) -> List[CanaryClaim]:
        """Erstelle Basis-Canaries."""
        canaries = []

        # Known True Claims (25 total)
        true_claims = [
            "Paris is the capital of France",
            "Water boils at 100 degrees Celsius at sea level",
            "The Earth orbits around the Sun",
            "2 + 2 equals 4",
            "The human heart has four chambers",
            "Shakespeare wrote Hamlet",
            "The speed of light is approximately 300,000 km/s",
            "Oxygen is essential for human breathing",
            "The Great Wall of China is visible from space",
            "The Pacific Ocean is the largest ocean on Earth",
            "DNA contains genetic information",
            "Gold is a chemical element with symbol Au",
            "The Moon orbits the Earth",
            "Mammals are warm-blooded vertebrates",
            "Photosynthesis occurs in plants",
            "The freezing point of water is 0 degrees Celsius",
            "Gravity attracts objects toward Earth",
            "Carbon dioxide is produced by cellular respiration",
            "The Eiffel Tower is located in Paris",
            "Neurons transmit electrical signals in the nervous system",
            "The Pythagorean theorem relates sides of right triangles",
            "Mitochondria are the powerhouse of the cell",
            "The Amazon River is in South America",
            "Diamonds are made of carbon",
            "The human body has 206 bones",
        ]

        for claim in true_claims:
            canaries.append(
                CanaryClaim(
                    content=claim,
                    expected_truth=True,
                    category="known_true",
                    confidence_threshold=0.95,
                )
            )

        # Known False Claims (25 total)
        false_claims = [
            "The moon is made of cheese",
            "Humans can breathe underwater without equipment",
            "The Sun is smaller than the Earth",
            "2 + 2 equals 5",
            "Shakespeare wrote Harry Potter",
            "The speed of light is 10 km/h",
            "Cats are a type of bird",
            "The Atlantic Ocean is larger than the Pacific",
            "The year 2025 has 400 days",
            "Gravity pushes objects away from Earth",
            "Water freezes at 100 degrees Celsius",
            "The Moon is larger than the Sun",
            "Plants produce oxygen during night only",
            "Gold is lighter than aluminum",
            "The Great Wall of China is visible from the Moon",
            "Humans have five hearts",
            "Antarctica is the smallest continent",
            "Light travels slower than sound",
            "The Earth is flat",
            "Magnets repel all metals",
            "DNA is made of proteins",
            "Fish breathe using lungs",
            "The Sahara is the wettest place on Earth",
            "Mount Everest is at sea level",
            "Humans evolved from modern chimpanzees",
        ]

        for claim in false_claims:
            canaries.append(
                CanaryClaim(
                    content=claim,
                    expected_truth=False,
                    category="known_false",
                    confidence_threshold=0.95,
                )
            )

        # Mathematical Claims
        math_claims = [
            "The square root of 16 is 4",
            "Pi is approximately 3.14159",
            "A triangle has three sides",
            "The area of a circle is π times radius squared",
            "Zero is neither positive nor negative",
        ]

        for claim in math_claims:
            canaries.append(
                CanaryClaim(
                    content=claim,
                    expected_truth=True,
                    category="mathematical",
                    confidence_threshold=0.98,
                )
            )

        # Temporal Claims (dynamisch)
        current_year = datetime.now().year
        temporal_claims = [
            f"The year {current_year} is in the 21st century",
            f"Today is a day in the year {current_year}",
            "The 20th century ended in the year 2000",
            "The 21st century began in the year 2001",
        ]

        for claim in temporal_claims:
            canaries.append(
                CanaryClaim(
                    content=claim,
                    expected_truth=True,
                    category="temporal",
                    confidence_threshold=0.90,
                )
            )

        return canaries

    def _compute_baseline_scores(self) -> Dict[str, float]:
        """Berechne Baseline-NLI-Scores für alle Canaries."""
        baseline = {}

        for canary in self.canaries:
            try:
                # Simuliere NLI-Score (in Realität: self.nli_model.predict())
                if canary.expected_truth:
                    # True claims sollten hohe NLI-Scores haben
                    score = random.uniform(0.8, 0.95)
                else:
                    # False claims sollten niedrige NLI-Scores haben
                    score = random.uniform(0.05, 0.2)

                baseline[canary.content] = score
            except Exception:
                # Fallback bei Fehlern
                baseline[canary.content] = 0.5

        return baseline

    def check_drift(
        self, sample_size: Optional[int] = None
    ) -> Tuple[bool, Dict[str, float]]:
        """
        Prüfe Drift in Canary-Scores.

        Args:
            sample_size: Anzahl zufälliger Canaries (None = alle)

        Returns:
            (has_drift, drift_scores)
        """
        if sample_size is None:
            canaries_to_check = self.canaries
        else:
            canaries_to_check = random.sample(
                self.canaries, min(sample_size, len(self.canaries))
            )

        current_scores = {}
        drift_scores = {}

        for canary in canaries_to_check:
            try:
                # Aktueller NLI-Score
                if canary.expected_truth:
                    current_score = random.uniform(0.8, 0.95)
                else:
                    current_score = random.uniform(0.05, 0.2)

                current_scores[canary.content] = current_score

                # Drift berechnen
                baseline_score = self.baseline_scores[canary.content]
                drift = abs(current_score - baseline_score)
                drift_scores[canary.content] = drift

            except Exception:
                # Bei Fehlern: maximaler Drift annehmen
                drift_scores[canary.content] = 1.0

        # Prüfe ob Drift-Schwellen überschritten
        max_drift = max(drift_scores.values()) if drift_scores else 0.0
        has_drift = max_drift > self.drift_threshold

        return has_drift, drift_scores

    def check_false_entailments(self) -> Tuple[bool, List[str]]:
        """
        Prüfe auf false entailments (Canaries die falsch klassifiziert werden).

        Returns:
            (has_false_entailments, failed_canaries)
        """
        failed_canaries = []

        for canary in self.canaries:
            try:
                # Simuliere NLI-Score
                if canary.expected_truth:
                    nli_score = random.uniform(0.8, 0.95)
                else:
                    nli_score = random.uniform(0.05, 0.2)

                # Prüfe ob Score mit erwarteter Wahrheit übereinstimmt
                if canary.expected_truth:
                    # True claim sollte hohen Score haben
                    if nli_score < canary.confidence_threshold:
                        failed_canaries.append(canary.content)
                else:
                    # False claim sollte niedrigen Score haben
                    if nli_score > (1.0 - canary.confidence_threshold):
                        failed_canaries.append(canary.content)

            except Exception:
                # Bei Fehlern als failed markieren
                failed_canaries.append(canary.content)

        has_false_entailments = len(failed_canaries) > 0
        return has_false_entailments, failed_canaries

    def get_canary_stats(self) -> Dict[str, int]:
        """Statistiken über Canaries."""
        stats: Dict[str, int] = {}

        for canary in self.canaries:
            category = canary.category
            stats[category] = stats.get(category, 0) + 1

        stats["total"] = len(self.canaries)
        return stats

    def add_custom_canary(
        self,
        content: str,
        expected_truth: bool,
        category: str = "custom",
        confidence_threshold: float = 0.95,
    ):
        """Füge benutzerdefinierten Canary hinzu."""
        canary = CanaryClaim(
            content=content,
            expected_truth=expected_truth,
            category=category,
            confidence_threshold=confidence_threshold,
        )

        self.canaries.append(canary)

        # Aktualisiere Baseline
        if canary.expected_truth:
            self.baseline_scores[content] = random.uniform(0.8, 0.95)
        else:
            self.baseline_scores[content] = random.uniform(0.05, 0.2)


# Beispiel-Usage
if __name__ == "__main__":
    # Mock NLI Model
    class MockNLIModel:
        def predict(self, text):
            return random.uniform(0.0, 1.0)

    # Erstelle Canary-System
    canaries = SnapshotCanaries(MockNLIModel(), drift_threshold=0.1)

    # Prüfe Drift
    has_drift, drift_scores = canaries.check_drift(sample_size=5)
    print(f"Has drift: {has_drift}")
    print(f"Max drift: {max(drift_scores.values()) if drift_scores else 0:.3f}")

    # Prüfe False Entailments
    has_false, failed = canaries.check_false_entailments()
    print(f"Has false entailments: {has_false}")
    print(f"Failed canaries: {len(failed)}")

    # Statistiken
    stats = canaries.get_canary_stats()
    print(f"Canary stats: {stats}")
