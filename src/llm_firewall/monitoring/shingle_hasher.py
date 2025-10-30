"""
Shingle-Hashing für Near-Duplicate Poison Detection
===================================================

5-gram-Shingle-Hashes zur Erkennung von n-gram-Profil-Abweichungen.
Ungewöhnliche n-gram-Profile (Frequenzspitzen, KL-Divergenz) sind oft 
früher sichtbar als Semantik-Abweichungen.

Features:
- 5-gram Shingle-Hashing
- KL-Divergenz zu Basis-KB
- Frequenzspitzen-Detection
- Near-Duplicate Detection
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple


@dataclass(frozen=True)
class ShingleProfile:
    """Shingle-Profil eines Dokuments."""
    shingles: Set[str]
    frequencies: Dict[str, int]
    total_shingles: int
    content_hash: str  # BLAKE3 des Volltexts


class ShingleHasher:
    """Shingle-Hashing für Poison-Detection."""

    def __init__(self, n_gram_size: int = 5, min_frequency: int = 2):
        """
        Args:
            n_gram_size: Größe der n-grams (Standard: 5)
            min_frequency: Minimale Frequenz für Shingle-Berücksichtigung
        """
        self.n_gram_size = n_gram_size
        self.min_frequency = min_frequency
        self.baseline_profiles: Dict[str, ShingleProfile] = {}
        self.baseline_frequencies: Dict[str, float] = {}

    def _normalize_text(self, text: str) -> str:
        """Normalisiere Text für Shingle-Extraktion."""
        # Kleinschreibung, Whitespace normalisieren
        text = text.lower()
        text = re.sub(r'\s+', ' ', text)

        # Entferne Sonderzeichen, behalte Buchstaben und Zahlen
        text = re.sub(r'[^a-z0-9\s]', '', text)

        return text.strip()

    def _extract_shingles(self, text: str) -> List[str]:
        """Extrahiere n-gram Shingles aus Text."""
        normalized = self._normalize_text(text)
        words = normalized.split()

        if len(words) < self.n_gram_size:
            return []

        shingles = []
        for i in range(len(words) - self.n_gram_size + 1):
            shingle = ' '.join(words[i:i + self.n_gram_size])
            shingles.append(shingle)

        return shingles

    def _compute_content_hash(self, text: str) -> str:
        """Berechne BLAKE2b-Hash des Volltexts (Python 3.12 compatible)."""
        return hashlib.blake2b(text.encode('utf-8')).hexdigest()

    def create_profile(self, content: str) -> ShingleProfile:
        """
        Erstelle Shingle-Profil für Content.
        
        Args:
            content: Text-Content
            
        Returns:
            Shingle-Profil
        """
        shingles = self._extract_shingles(content)

        if not shingles:
            return ShingleProfile(
                shingles=set(),
                frequencies={},
                total_shingles=0,
                content_hash=self._compute_content_hash(content)
            )

        # Zähle Frequenzen
        shingle_counts = Counter(shingles)

        # Filtere nach min_frequency
        filtered_counts = {
            shingle: count
            for shingle, count in shingle_counts.items()
            if count >= self.min_frequency
        }

        return ShingleProfile(
            shingles=set(filtered_counts.keys()),
            frequencies=filtered_counts,
            total_shingles=sum(filtered_counts.values()),
            content_hash=self._compute_content_hash(content)
        )

    def add_baseline_profile(self, profile_id: str, content: str):
        """Füge Baseline-Profil hinzu."""
        profile = self.create_profile(content)
        self.baseline_profiles[profile_id] = profile

        # Aktualisiere globale Baseline-Frequenzen
        self._update_baseline_frequencies()

    def _update_baseline_frequencies(self):
        """Aktualisiere globale Baseline-Frequenzen."""
        all_shingles = set()
        for profile in self.baseline_profiles.values():
            all_shingles.update(profile.shingles)

        # Berechne relative Frequenzen
        total_frequency = sum(
            sum(profile.frequencies.values())
            for profile in self.baseline_profiles.values()
        )

        self.baseline_frequencies = {}
        for shingle in all_shingles:
            frequency = sum(
                profile.frequencies.get(shingle, 0)
                for profile in self.baseline_profiles.values()
            )
            self.baseline_frequencies[shingle] = frequency / total_frequency if total_frequency > 0 else 0.0

    def compute_kl_divergence(self, profile: ShingleProfile) -> float:
        """
        Berechne KL-Divergenz zwischen Profil und Baseline.
        
        KL(P||Q) = Σ P(x) * log(P(x) / Q(x))
        """
        if not profile.shingles or not self.baseline_frequencies:
            return 0.0

        kl_divergence = 0.0

        for shingle in profile.shingles:
            # P(x) = Frequenz im aktuellen Profil
            p_freq = profile.frequencies.get(shingle, 0) / profile.total_shingles

            # Q(x) = Frequenz in Baseline
            q_freq = self.baseline_frequencies.get(shingle, 1e-10)  # Smoothing

            if p_freq > 0:
                kl_divergence += p_freq * math.log(p_freq / q_freq)

        return kl_divergence

    def detect_frequency_spikes(self, profile: ShingleProfile,
                               spike_threshold: float = 3.0) -> List[Tuple[str, float]]:
        """
        Erkenne Frequenzspitzen (ungewöhnlich häufige Shingles).
        
        Args:
            profile: Zu prüfendes Profil
            spike_threshold: Z-Score Threshold für Spike-Erkennung
            
        Returns:
            Liste von (shingle, z_score) Tupeln
        """
        spikes: List[Tuple[str, float]] = []

        if not profile.shingles or not self.baseline_frequencies:
            return spikes

        # Berechne Baseline-Statistiken
        baseline_freqs = list(self.baseline_frequencies.values())
        if not baseline_freqs:
            return spikes

        baseline_mean = sum(baseline_freqs) / len(baseline_freqs)
        baseline_variance = sum((f - baseline_mean) ** 2 for f in baseline_freqs) / len(baseline_freqs)
        baseline_std = math.sqrt(baseline_variance) if baseline_variance > 0 else 1.0

        for shingle in profile.shingles:
            # Aktuelle Frequenz
            current_freq = profile.frequencies.get(shingle, 0) / profile.total_shingles

            # Baseline-Frequenz
            baseline_freq = self.baseline_frequencies.get(shingle, baseline_mean)

            # Z-Score berechnen
            if baseline_std > 0:
                z_score = (current_freq - baseline_freq) / baseline_std
            else:
                z_score = 0.0

            if z_score > spike_threshold:
                spikes.append((shingle, z_score))

        # Sortiere nach Z-Score (höchste zuerst)
        spikes.sort(key=lambda x: x[1], reverse=True)
        return spikes

    def find_near_duplicates(self, profile: ShingleProfile,
                           similarity_threshold: float = 0.8) -> List[Tuple[str, float]]:
        """
        Finde Near-Duplicates basierend auf Jaccard-Ähnlichkeit.
        
        Args:
            profile: Zu prüfendes Profil
            similarity_threshold: Mindest-Ähnlichkeit für Duplicate
            
        Returns:
            Liste von (profile_id, similarity) Tupeln
        """
        near_duplicates = []

        for profile_id, baseline_profile in self.baseline_profiles.items():
            # Jaccard-Ähnlichkeit
            intersection = len(profile.shingles & baseline_profile.shingles)
            union = len(profile.shingles | baseline_profile.shingles)

            if union > 0:
                similarity = intersection / union
                if similarity >= similarity_threshold:
                    near_duplicates.append((profile_id, similarity))

        # Sortiere nach Ähnlichkeit (höchste zuerst)
        near_duplicates.sort(key=lambda x: x[1], reverse=True)
        return near_duplicates

    def detect_anomalies(self, content: str,
                        kl_threshold: float = 0.4,
                        spike_threshold: float = 3.0,
                        duplicate_threshold: float = 0.85) -> Dict[str, Any]:
        """
        Umfassende Anomalie-Erkennung.
        
        Args:
            content: Zu prüfender Content
            kl_threshold: KL-Divergenz Threshold
            spike_threshold: Spike Z-Score Threshold
            duplicate_threshold: Duplicate Similarity Threshold
            
        Returns:
            Anomalie-Report
        """
        profile = self.create_profile(content)

        # KL-Divergenz
        kl_div = self.compute_kl_divergence(profile)

        # Frequenzspitzen
        spikes = self.detect_frequency_spikes(profile, spike_threshold)

        # Near-Duplicates
        near_duplicates = self.find_near_duplicates(profile, duplicate_threshold)

        # Anomalie-Flags
        has_kl_anomaly = kl_div > kl_threshold
        has_spike_anomaly = len(spikes) > 0
        has_duplicate_anomaly = len(near_duplicates) > 0

        return {
            'content_hash': profile.content_hash,
            'total_shingles': profile.total_shingles,
            'unique_shingles': len(profile.shingles),
            'kl_divergence': kl_div,
            'has_kl_anomaly': has_kl_anomaly,
            'frequency_spikes': spikes,
            'has_spike_anomaly': has_spike_anomaly,
            'near_duplicates': near_duplicates,
            'has_duplicate_anomaly': has_duplicate_anomaly,
            'overall_anomaly': has_kl_anomaly or has_spike_anomaly or has_duplicate_anomaly
        }

    def get_baseline_stats(self) -> Dict[str, Any]:
        """Statistiken über Baseline-Profile."""
        if not self.baseline_profiles:
            return {'total_profiles': 0, 'total_shingles': 0, 'unique_shingles': 0}

        all_shingles = set()
        total_shingles = 0

        for profile in self.baseline_profiles.values():
            all_shingles.update(profile.shingles)
            total_shingles += profile.total_shingles

        return {
            'total_profiles': len(self.baseline_profiles),
            'total_shingles': total_shingles,
            'unique_shingles': len(all_shingles),
            'avg_shingles_per_profile': total_shingles / len(self.baseline_profiles) if self.baseline_profiles else 0
        }


# Beispiel-Usage
if __name__ == "__main__":
    # Erstelle Shingle-Hasher
    hasher = ShingleHasher(n_gram_size=5, min_frequency=2)

    # Füge Baseline-Content hinzu
    baseline_texts = [
        "This is a normal scientific paper about machine learning",
        "Another research paper on artificial intelligence and neural networks",
        "A study about natural language processing and text analysis"
    ]

    for i, text in enumerate(baseline_texts):
        hasher.add_baseline_profile(f"baseline_{i}", text)

    # Teste Anomalie-Erkennung
    test_content = "This is a suspicious text with unusual patterns and strange word combinations that might indicate poisoning"

    anomalies = hasher.detect_anomalies(test_content)
    print(f"Anomalies detected: {anomalies['overall_anomaly']}")
    print(f"KL Divergence: {anomalies['kl_divergence']:.3f}")
    print(f"Frequency spikes: {len(anomalies['frequency_spikes'])}")
    print(f"Near duplicates: {len(anomalies['near_duplicates'])}")

    # Baseline-Statistiken
    stats = hasher.get_baseline_stats()
    print(f"Baseline stats: {stats}")
