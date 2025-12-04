"""
Proof of Concept: Evidence-Based AnswerPolicy Decision
======================================================

Isolierter Test der Dempster-Shafer Fusion mit simulierten Engine-Evidenzen.
Demonstriert, wie p_correct aus fusionierten Evidenzen berechnet wird,
ohne die Haupt-Engine zu verändern.

Author: Joerg Bollwahn / AI Assistant
Date: 2025-12-03
License: MIT
"""

import sys
from pathlib import Path

# Add src to path
base_dir = Path(__file__).parent
src_dir = base_dir / "src"
sys.path.insert(0, str(src_dir))

from llm_firewall.fusion.dempster_shafer import (
    DempsterShaferFusion,
    make_mass,
)
from llm_firewall.core.decision_policy import get_policy


def test_evidence_fusion_decision():
    """Isolierter Test: Entscheidung auf Basis fusionierter Evidenzen."""

    # 1. Dempster-Shafer Fuser initialisieren
    fuser = DempsterShaferFusion(conflict_threshold=0.5)

    # 2. Evidenzen für zwei beispielhafte Szenarien simulieren
    test_evidence_sets = [
        {  # Szenario A: Hohes Risiko, hoher CUSUM-Drift
            "risk_scorer": 0.85,  # base_risk_score aus der Engine
            "cusum_drift": 0.70,  # normalisierter Score aus VectorGuard
            "encoding_anomaly": 0.50,  # encoding_anomaly_score
            "expected_mode": "silence",  # Erwartetes Ergebnis
        },
        {  # Szenario B: Geringes Risiko, kein Drift
            "risk_scorer": 0.10,
            "cusum_drift": 0.05,
            "encoding_anomaly": 0.10,
            "expected_mode": "answer",
        },
        {  # Szenario C: Mittleres Risiko, mittlerer Drift (Grenzfall)
            "risk_scorer": 0.50,
            "cusum_drift": 0.40,
            "encoding_anomaly": 0.30,
            "expected_mode": "silence",  # Sollte bei Kids-Policy blockieren
        },
    ]

    # 3. AnswerPolicy-Konfiguration (Kids-Policy)
    policy = get_policy("kids")
    POLICY_THRESHOLD = policy.threshold()

    print("=" * 70)
    print("Test Evidence-Based AnswerPolicy")
    print("=" * 70)
    print(f"Policy: {policy.policy_name}")
    print(f"Threshold: {POLICY_THRESHOLD:.6f}")
    print(f"Cost wrong: {policy.cost_wrong}, Cost silence: {policy.cost_silence}")
    print()

    for i, evidences in enumerate(test_evidence_sets):
        scenario_name = chr(65 + i)  # A, B, C
        print(f"Szenario {scenario_name}:")
        print(f"  Risk Score: {evidences['risk_scorer']:.2f}")
        print(f"  CUSUM Drift: {evidences['cusum_drift']:.2f}")
        print(f"  Encoding Anomaly: {evidences['encoding_anomaly']:.2f}")

        # A) Evidenzen in EvidenceMass-Objekte konvertieren
        # WICHTIG: make_mass(score) interpretiert score als "promote"-Confidence
        # Für Risk/CUSUM/Encoding: Hoher Score = hohes Risiko = hohe Quarantine-Mass
        # Daher: score invertieren (1.0 - risk_score) für promote, risk_score für quarantine
        # ODER: Direkt Quarantine-Mass setzen via EvidenceMass-Konstruktor

        # Methode 1: Invertierte Scores (1.0 - risk = promote-confidence)
        risk_promote_confidence = 1.0 - evidences["risk_scorer"]
        cusum_promote_confidence = 1.0 - evidences["cusum_drift"]
        encoding_promote_confidence = 1.0 - evidences["encoding_anomaly"]

        risk_mass = make_mass(score=risk_promote_confidence, allow_ignorance=0.1)
        cusum_mass = make_mass(score=cusum_promote_confidence, allow_ignorance=0.15)
        encoding_mass = make_mass(
            score=encoding_promote_confidence, allow_ignorance=0.2
        )

        # B) Evidenzen fusionieren (Kern des Tests)
        masses = [risk_mass, cusum_mass, encoding_mass]
        combined_mass = fuser.combine_masses(masses)

        # C) Belief-Funktionen berechnen
        belief_promote, belief_quarantine = fuser.compute_belief(combined_mass)

        # D) p_correct aus Belief ableiten
        # p_correct = 1 - belief_quarantine (je höher Quarantine-Belief, desto niedriger p_correct)
        p_correct = max(0.0, min(1.0, 1.0 - belief_quarantine))

        # E) AnswerPolicy-Entscheidung
        mode = policy.decide(p_correct)
        blocked_by_ap = mode == "silence"

        # F) Erweiterte Metadaten-Struktur (wie in der echten Engine)
        metadata = {
            "enabled": True,
            "policy_name": policy.policy_name,
            "p_correct": round(p_correct, 4),
            "threshold": round(POLICY_THRESHOLD, 6),
            "mode": mode,
            "blocked_by_answer_policy": blocked_by_ap,
            # NEUE FELDER (für erweiterte Analyse):
            "belief_promote": round(belief_promote, 4),
            "belief_quarantine": round(belief_quarantine, 4),
            "plausibility_quarantine": round(
                belief_quarantine + combined_mass.unknown, 4
            ),  # Belief + Unknown
            "evidence_masses": {
                "risk": {
                    "promote": round(risk_mass.promote, 4),
                    "quarantine": round(risk_mass.quarantine, 4),
                    "unknown": round(risk_mass.unknown, 4),
                },
                "cusum": {
                    "promote": round(cusum_mass.promote, 4),
                    "quarantine": round(cusum_mass.quarantine, 4),
                    "unknown": round(cusum_mass.unknown, 4),
                },
                "encoding": {
                    "promote": round(encoding_mass.promote, 4),
                    "quarantine": round(encoding_mass.quarantine, 4),
                    "unknown": round(encoding_mass.unknown, 4),
                },
            },
            "combined_mass": {
                "promote": round(combined_mass.promote, 4),
                "quarantine": round(combined_mass.quarantine, 4),
                "unknown": round(combined_mass.unknown, 4),
            },
        }

        # G) Ausgabe
        print(
            f"  Combined Mass: promote={combined_mass.promote:.4f}, "
            f"quarantine={combined_mass.quarantine:.4f}, "
            f"unknown={combined_mass.unknown:.4f}"
        )
        print(
            f"  Belief: promote={belief_promote:.4f}, "
            f"quarantine={belief_quarantine:.4f}"
        )
        print(f"  p_correct: {p_correct:.4f}")
        print(
            f"  Entscheidung: mode='{mode}' (erwartet: '{evidences['expected_mode']}')"
        )
        print(f"  Blocked by AnswerPolicy: {blocked_by_ap}")
        print()

        # H) Einfache Validierung
        if mode != evidences["expected_mode"]:
            print(
                f"  [WARNUNG] Entscheidung weicht ab! "
                f"Erwartet '{evidences['expected_mode']}', "
                f"erhalten '{mode}'"
            )
            print(f"     (p_correct={p_correct:.4f}, threshold={POLICY_THRESHOLD:.6f})")
        else:
            print("  [OK] Entscheidung korrekt")

        print()

    print("=" * 70)
    print(
        "[SUCCESS] Test abgeschlossen: Entscheidung auf fusionierten Evidenzen moeglich."
    )
    print("=" * 70)
    print()
    print("Nächste Schritte:")
    print("  1. Integration in FirewallEngineV2._should_answer()")
    print("  2. CUSUM-Score-Getter aus VectorGuard implementieren")
    print("  3. Erweiterte Metadaten in _create_decision_with_metadata() aufnehmen")


if __name__ == "__main__":
    test_evidence_fusion_decision()
