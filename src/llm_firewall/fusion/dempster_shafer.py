"""
Dempster-Shafer Fusion für Evidence Pipeline
============================================

Kombiniert trust, NLI, corroboration als Evidenzmassen statt simplen Schwellen.
Minimiert Fehlpromotions bei widersprüchlichen Signalen ohne FPR zu treiben.

Formel: m = ⊕(m_trust, m_nli, m_corr)
Entscheidung: promote wenn Belief(promote) - Belief(quarantine) ≥ τ

GPT-5 corrected version with proper normalization.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable, Tuple, List


@dataclass(frozen=True)
class EvidenceMass:
    """
    Mass assignment over frame Θ={PROMOTE, QUARANTINE}.
    
    Supports ignorance mass (unknown/theta).
    """
    promote: float
    quarantine: float
    unknown: float  # ignorance (theta)
    
    def __post_init__(self):
        """Validate mass."""
        self.validate()
    
    def validate(self) -> None:
        """Validate mass values."""
        p, q, u = self.promote, self.quarantine, self.unknown
        s = p + q + u
        
        if not (0.0 <= p <= 1.0 and 0.0 <= q <= 1.0 and 0.0 <= u <= 1.0):
            raise ValueError(
                f"Evidence mass values must be within [0,1] "
                f"(got promote={p}, quarantine={q}, unknown={u})"
            )
        
        if s > 1.0 + 1e-9:
            raise ValueError(
                f"Evidence mass values must sum to ≤ 1.0 "
                f"(got promote={p}, quarantine={q}, unknown={u}, sum={s})"
            )


def make_mass(score: float, allow_ignorance: float = 0.0) -> EvidenceMass:
    """
    Deterministic mapping score∈[0,1] -> mass over {PROMOTE, QUARANTINE, Θ}.
    
    Args:
        score: Confidence score [0,1]
        allow_ignorance: Amount of ignorance to preserve [0,1]
        
    Returns:
        Evidence mass
    """
    s = float(score)
    t = float(allow_ignorance)
    
    if not (0.0 <= s <= 1.0) or not (0.0 <= t <= 1.0):
        raise ValueError("score and allow_ignorance must be in [0,1]")
    
    # Allocate ignorance first, then split residual by s
    residual = 1.0 - t
    p = s * residual              # exact product
    q = (1.0 - s) * residual
    
    return EvidenceMass(promote=p, quarantine=q, unknown=t)


def conflict(m1: EvidenceMass, m2: EvidenceMass) -> float:
    """
    Compute conflict mass K.
    
    K = m1(PROMOTE)*m2(QUARANTINE) + m1(QUARANTINE)*m2(PROMOTE)
    """
    m1.validate()
    m2.validate()
    
    return m1.promote * m2.quarantine + m1.quarantine * m2.promote


def combine_pair(m1: EvidenceMass, m2: EvidenceMass) -> Tuple[EvidenceMass, float]:
    """
    Dempster's rule with proper normalization by (1-K).
    
    Supports ignorance mass Θ.
    
    Args:
        m1, m2: Evidence masses to combine
        
    Returns:
        (combined_mass, conflict_K)
    """
    m1.validate()
    m2.validate()
    
    K = conflict(m1, m2)
    denom = 1.0 - K
    
    if denom <= 1e-15:
        # Total conflict → neutral fallback (uninformative)
        return EvidenceMass(promote=0.5, quarantine=0.5, unknown=0.0), 1.0
    
    # Combine masses
    P = (m1.promote * m2.promote + 
         m1.promote * m2.unknown + 
         m1.unknown * m2.promote) / denom
    
    Q = (m1.quarantine * m2.quarantine + 
         m1.quarantine * m2.unknown + 
         m1.unknown * m2.quarantine) / denom
    
    T = (m1.unknown * m2.unknown) / denom
    
    out = EvidenceMass(promote=P, quarantine=Q, unknown=T)
    
    # Clamp minor FP drift
    s = out.promote + out.quarantine + out.unknown
    if s > 1.0 + 1e-9:
        excess = s - 1.0
        out = EvidenceMass(
            promote=max(0.0, out.promote - excess/3),
            quarantine=max(0.0, out.quarantine - excess/3),
            unknown=max(0.0, out.unknown - excess/3)
        )
    
    out.validate()
    return out, K


def combine_all(masses: Iterable[EvidenceMass]) -> Tuple[EvidenceMass, float]:
    """
    Combine multiple evidence masses.
    
    Args:
        masses: Iterable of evidence masses
        
    Returns:
        (combined_mass, total_conflict_K)
    """
    it = iter(masses)
    
    try:
        cur = next(it)
    except StopIteration:
        # Empty list → neutral
        return EvidenceMass(promote=0.5, quarantine=0.5, unknown=0.0), 0.0
    
    total_K = 0.0
    
    for m in it:
        cur, K = combine_pair(cur, m)
        # Cumulative conflict (no double count)
        total_K = 1.0 - (1.0 - total_K) * (1.0 - K)
    
    return cur, total_K


def detect_conflict(K: float, tau: float = 0.50) -> bool:
    """
    Return True if conflict mass is high.
    
    Args:
        K: Conflict mass
        tau: Threshold (default: 0.50)
        
    Returns:
        True if conflict exceeds threshold
    """
    return K >= tau


class DempsterShaferFusion:
    """Dempster-Shafer Evidenzkombination (backward compatible wrapper)."""
    
    def __init__(self, conflict_threshold: float = 0.5):
        """
        Args:
            conflict_threshold: Hoher Konflikt → menschliche Prüfung
        """
        self.conflict_threshold = conflict_threshold
    
    def combine_masses(self, masses: List[EvidenceMass]) -> EvidenceMass:
        """
        Kombiniere Evidenzmassen per Dempster-Rule.
        
        Args:
            masses: Liste von Evidenzmassen
            
        Returns:
            Kombinierte Masse
        """
        if not masses:
            return EvidenceMass(promote=0.0, quarantine=0.0, unknown=1.0)
        
        combined, K = combine_all(masses)
        return combined
    
    def compute_belief(self, mass: EvidenceMass) -> Tuple[float, float]:
        """
        Berechne Belief-Funktionen.
        
        Returns:
            (belief_promote, belief_quarantine)
        """
        return mass.promote, mass.quarantine
    
    def should_promote(self, mass: EvidenceMass, threshold: float = 0.1) -> Tuple[bool, float, float]:
        """
        Entscheide Promotion basierend auf Belief-Differenz.
        
        Args:
            mass: Kombinierte Evidenzmasse
            threshold: Mindest-Belief-Differenz für Promotion
            
        Returns:
            (should_promote, belief_promote, belief_quarantine)
        """
        belief_promote, belief_quarantine = self.compute_belief(mass)
        
        belief_diff = belief_promote - belief_quarantine
        should_promote = belief_diff >= threshold
        
        return should_promote, belief_promote, belief_quarantine
    
    def detect_conflict(self, masses: List[EvidenceMass]) -> bool:
        """
        Erkenne hohen Konflikt zwischen Evidenzen.
        
        Returns:
            True wenn Konflikt > threshold
        """
        if len(masses) < 2:
            return False
        
        _, total_K = combine_all(masses)
        return detect_conflict(total_K, self.conflict_threshold)


def create_evidence_masses(
    trust: float,
    nli: float, 
    corroboration: float,
    trust_weight: float = 0.4,
    nli_weight: float = 0.4,
    corr_weight: float = 0.2
) -> List[EvidenceMass]:
    """
    Erstelle Evidenzmassen aus Pipeline-Metriken.
    
    Uses make_mass for deterministic float arithmetic.
    """
    masses = []
    
    # Trust-Masse
    if trust_weight > 0:
        trust_mass = make_mass(trust, allow_ignorance=1.0 - trust_weight)
        masses.append(trust_mass)
    
    # NLI-Masse
    if nli_weight > 0:
        nli_mass = make_mass(nli, allow_ignorance=1.0 - nli_weight)
        masses.append(nli_mass)
    
    # Corroboration-Masse
    if corr_weight > 0:
        corr_mass = make_mass(corroboration, allow_ignorance=1.0 - corr_weight)
        masses.append(corr_mass)
    
    return masses


# Beispiel-Usage
if __name__ == "__main__":
    # Test mit widersprüchlichen Signalen
    fusion = DempsterShaferFusion(conflict_threshold=0.5)
    
    # Hoher Trust, niedrige NLI, mittlere Corroboration
    masses = create_evidence_masses(
        trust=0.9,
        nli=0.3,
        corroboration=0.6
    )
    
    combined = fusion.combine_masses(masses)
    should_promote, belief_p, belief_q = fusion.should_promote(combined, threshold=0.1)
    has_conflict = fusion.detect_conflict(masses)
    
    print(f"Combined mass: {combined}")
    print(f"Should promote: {should_promote}")
    print(f"Belief (promote, quarantine): ({belief_p:.3f}, {belief_q:.3f})")
    print(f"Has conflict: {has_conflict}")
