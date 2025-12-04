#!/usr/bin/env python3
"""
Analysiert die blockierten benign-Items aus Evidence-Log vs. Heuristik.

Identifiziert, warum Evidence-Fusion niedrige p_correct-Werte produziert.
"""

import json
import statistics
from pathlib import Path
from typing import Dict, List


def load_decisions(log_path: Path) -> List[Dict]:
    """Lade Entscheidungen aus JSONL-Datei."""
    with open(log_path, "r", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def analyze_blocked_benign(
    heuristic_log: List[Dict], evidence_log: List[Dict]
) -> List[Dict]:
    """Analysiere blockierte benign-Items."""

    # Erstelle Lookup-Dictionaries
    evidence_decisions = {d["item_id"]: d for d in evidence_log if "item_id" in d}
    heuristic_decisions = {d["item_id"]: d for d in heuristic_log if "item_id" in d}

    blocked_in_evidence = []

    # Finde blockierte benign-Items in Evidence-Log
    for d in evidence_log:
        if d.get("item_type") != "benign":
            continue

        # Prüfe ob blockiert (nicht allowed ODER mode='silence')
        metadata = d.get("metadata", {})
        answer_policy = metadata.get("answer_policy", {})

        is_blocked = (
            not d.get("allowed", True) or answer_policy.get("mode") == "silence"
        )

        if is_blocked:
            item_id = d.get("item_id", "unknown")
            heuristic_decision = heuristic_decisions.get(item_id)

            # Extrahiere p_correct-Werte
            evidence_p_correct = answer_policy.get("p_correct")
            heuristic_p_correct = None
            if heuristic_decision:
                heuristic_ap = heuristic_decision.get("metadata", {}).get(
                    "answer_policy", {}
                )
                heuristic_p_correct = heuristic_ap.get("p_correct")

            # Extrahiere Risk Score
            risk_score = d.get("risk_score", 0)
            base_risk_score = answer_policy.get("base_risk_score", risk_score)

            # Extrahiere Evidence Masses
            evidence_masses = answer_policy.get("evidence_masses", {})

            # Berechne Risk Score aus Evidence Masses (falls nicht direkt verfügbar)
            if base_risk_score == 0 and evidence_masses:
                risk_scorer_mass = evidence_masses.get("risk_scorer", {})
                if isinstance(risk_scorer_mass, dict):
                    # Risk Score = 1.0 - promote_confidence
                    # promote_confidence ist invers zu risk_score
                    quarantine_mass = risk_scorer_mass.get("quarantine", 0)
                    base_risk_score = quarantine_mass

            blocked_in_evidence.append(
                {
                    "item_id": item_id,
                    "prompt": d.get("prompt", "")[:150],  # Erste 150 Zeichen
                    "evidence_p_correct": evidence_p_correct,
                    "heuristic_p_correct": heuristic_p_correct,
                    "risk_score": risk_score,
                    "base_risk_score": base_risk_score,
                    "belief_quarantine": answer_policy.get("belief_quarantine"),
                    "evidence_masses": evidence_masses,
                    "combined_mass": answer_policy.get("combined_mass", {}),
                    "method": answer_policy.get("method", "unknown"),
                }
            )

    print(f"Blockierte benign-Items in Evidence-Log: {len(blocked_in_evidence)}")

    # Gruppiere nach Ursache
    high_risk = []  # base_risk_score > 0.5
    very_low_p_correct = []  # p_correct < 0.3
    moderate = []  # 0.3 <= p_correct < 0.5
    other = []

    for item in blocked_in_evidence:
        p_correct = item.get("evidence_p_correct", 1.0)
        risk_score = item.get("base_risk_score", 0)

        if risk_score > 0.5:
            high_risk.append(item)
        elif p_correct < 0.3:
            very_low_p_correct.append(item)
        elif p_correct < 0.5:
            moderate.append(item)
        else:
            other.append(item)

    print("\nKategorien:")
    print(f"  - Hohes Risiko (risk_score > 0.5): {len(high_risk)} Items")
    print(f"  - Sehr niedriges p_correct (< 0.3): {len(very_low_p_correct)} Items")
    print(f"  - Moderates p_correct (0.3-0.5): {len(moderate)} Items")
    print(f"  - Andere: {len(other)} Items")

    # Detaillierte Analyse für jedes Item
    print("\n" + "=" * 80)
    print("DETAILIERTE ANALYSE DER BLOCKIERTEN BENIGN-ITEMS")
    print("=" * 80)

    for i, item in enumerate(blocked_in_evidence, 1):
        print(f"\n{i}. Item: {item['item_id']}")
        print(f"   Prompt: {item['prompt']}...")
        print(f"   p_correct (Evidence): {item['evidence_p_correct']:.4f}")
        if item["heuristic_p_correct"] is not None:
            print(f"   p_correct (Heuristik): {item['heuristic_p_correct']:.4f}")
            diff = item["evidence_p_correct"] - item["heuristic_p_correct"]
            print(f"   Differenz: {diff:+.4f}")
        print(f"   Risk Score: {item['risk_score']:.4f}")
        print(f"   Base Risk Score: {item['base_risk_score']:.4f}")
        print(f"   Belief Quarantine: {item.get('belief_quarantine', 0):.4f}")

        # Analysiere Evidence Masses
        masses = item.get("evidence_masses", {})
        if masses:
            print("   Evidence Masses:")
            for ev_type, ev_mass in masses.items():
                if isinstance(ev_mass, dict):
                    print(
                        f"     {ev_type}: promote={ev_mass.get('promote', 0):.3f}, "
                        f"quarantine={ev_mass.get('quarantine', 0):.3f}, "
                        f"unknown={ev_mass.get('unknown', 0):.3f}"
                    )
                else:
                    print(f"     {ev_type}: {ev_mass}")

        # Prüfe auf problematische Evidence
        combined_mass = item.get("combined_mass", {})
        if isinstance(combined_mass, dict):
            cusum_quarantine = (
                masses.get("cusum_drift", {}).get("quarantine", 0)
                if isinstance(masses.get("cusum_drift"), dict)
                else 0
            )
            encoding_quarantine = (
                masses.get("encoding_anomaly", {}).get("quarantine", 0)
                if isinstance(masses.get("encoding_anomaly"), dict)
                else 0
            )

            if cusum_quarantine > 0.3:
                print(
                    f"   HINWEIS: Hoher CUSUM-Drift-Quarantine ({cusum_quarantine:.3f})"
                )
            if encoding_quarantine > 0.3:
                print(
                    f"   HINWEIS: Hohe Encoding-Anomalie-Quarantine ({encoding_quarantine:.3f})"
                )

    return blocked_in_evidence


def main():
    base_dir = Path(__file__).parent.parent
    logs_dir = base_dir / "logs"

    heuristic_log_path = logs_dir / "kids_heuristic_smoke.jsonl"
    evidence_log_path = logs_dir / "kids_boost_0.4_stretch_2.0.jsonl"

    if not heuristic_log_path.exists():
        print(
            f"Error: Heuristik-Log nicht gefunden: {heuristic_log_path}",
            file=__import__("sys").stderr,
        )
        return 1

    if not evidence_log_path.exists():
        print(
            f"Error: Evidence-Log nicht gefunden: {evidence_log_path}",
            file=__import__("sys").stderr,
        )
        return 1

    heuristic_log = load_decisions(heuristic_log_path)
    evidence_log = load_decisions(evidence_log_path)

    blocked_items = analyze_blocked_benign(heuristic_log, evidence_log)

    # Empfehlungen generieren
    print("\n" + "=" * 80)
    print("EMPFEHLUNGEN FÜR KALIBRIERUNGSANPASSUNG")
    print("=" * 80)

    if not blocked_items:
        print("\nKeine blockierten benign-Items gefunden.")
        return 0

    # Statistik über risk_scores
    risk_scores = [
        item.get("base_risk_score", item.get("risk_score", 0)) for item in blocked_items
    ]
    p_correct_values = [
        item.get("evidence_p_correct", 0)
        for item in blocked_items
        if item.get("evidence_p_correct") is not None
    ]

    if risk_scores:
        print("\nRisk Scores der blockierten benign-Items:")
        print(f"  - Minimum: {min(risk_scores):.4f}")
        print(f"  - Maximum: {max(risk_scores):.4f}")
        print(f"  - Mittelwert: {statistics.mean(risk_scores):.4f}")
        if len(risk_scores) > 1:
            print(f"  - Median: {statistics.median(risk_scores):.4f}")

        if max(risk_scores) > 0.7:
            print("\n  PROBLEM: Einige benign-Items haben sehr hohe Risk Scores (>0.7)")
            print("  LÖSUNG: Risk-Scorer-Kalibrierung überprüfen (falsche Positivrate)")

        if statistics.mean(risk_scores) > 0.5:
            print(
                "\n  PROBLEM: Durchschnittlicher Risk Score > 0.5 für blockierte benign-Items"
            )
            print(
                "  LÖSUNG: Threshold für Risk-Scorer anpassen oder benign-Beispiele zum Training hinzufügen"
            )

    if p_correct_values:
        print("\np_correct-Werte der blockierten benign-Items:")
        print(f"  - Minimum: {min(p_correct_values):.4f}")
        print(f"  - Maximum: {max(p_correct_values):.4f}")
        print(f"  - Mittelwert: {statistics.mean(p_correct_values):.4f}")
        if len(p_correct_values) > 1:
            print(f"  - Median: {statistics.median(p_correct_values):.4f}")

        if max(p_correct_values) < 0.5:
            print("\n  PROBLEM: Alle blockierten benign-Items haben p_correct < 0.5")
            print(
                "  LÖSUNG: Evidence-Fusion-Kalibrierung anpassen (ignorance erhöhen oder boost reduzieren)"
            )

    # Analysiere Evidence-Mass-Verteilung
    print("\nEvidence-Mass-Analyse:")
    cusum_high = 0
    encoding_high = 0

    for item in blocked_items:
        masses = item.get("evidence_masses", {})
        if isinstance(masses.get("cusum_drift"), dict):
            cusum_q = masses["cusum_drift"].get("quarantine", 0)
            if cusum_q > 0.3:
                cusum_high += 1
        if isinstance(masses.get("encoding_anomaly"), dict):
            encoding_q = masses["encoding_anomaly"].get("quarantine", 0)
            if encoding_q > 0.3:
                encoding_high += 1

    if cusum_high > 0:
        print(f"  - {cusum_high} Items mit hohem CUSUM-Drift-Quarantine (>0.3)")
        print("    HINWEIS: CUSUM-Drift könnte zu konservativ sein")

    if encoding_high > 0:
        print(
            f"  - {encoding_high} Items mit hoher Encoding-Anomalie-Quarantine (>0.3)"
        )
        print("    HINWEIS: Encoding-Anomalie-Detektion könnte zu aggressiv sein")

    print("\n" + "=" * 80)
    print("ZUSAMMENFASSUNG")
    print("=" * 80)
    print(f"\n{len(blocked_items)} benign-Items werden blockiert.")
    print("Alle haben p_correct < 0.58 (Threshold-Bereich 0.58-0.70).")
    print("\nEmpfehlung: Prüfen Sie, ob diese Items tatsächlich grenzwertig sind,")
    print("oder ob die Evidence-Kalibrierung zu konservativ ist.")


if __name__ == "__main__":
    import sys

    sys.exit(main())
