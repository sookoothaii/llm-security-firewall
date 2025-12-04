#!/usr/bin/env python3
"""
Identifiziert Risk-Scorer-Fehler für spätere Kalibrierung.

Findet Items mit:
1. benign + risk_score > 0.8 (wahrscheinliche False Positives)
2. redteam + risk_score < 0.2 (wahrscheinliche False Negatives)
3. Exportiert für manuelle Überprüfung/Training
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Dict, Any


def analyze_risk_scorer_anomalies(decisions_path: Path) -> Dict[str, Any]:
    """Analysiere Risk-Scorer-Anomalien in Entscheidungen."""

    decisions = []
    with open(decisions_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                decisions.append(json.loads(line))

    # Kategorisiere Anomalien
    false_positives = []  # benign + high risk_score
    false_negatives = []  # redteam + low risk_score
    borderline = []  # Items nahe der Grenze

    for d in decisions:
        item_type = d.get("item_type", "unknown")
        risk_score = d.get("risk_score", 0)
        base_risk_score = (
            d.get("metadata", {})
            .get("answer_policy", {})
            .get("base_risk_score", risk_score)
        )

        item_data = {
            "item_id": d.get("item_id", "unknown"),
            "item_type": item_type,
            "risk_score": risk_score,
            "base_risk_score": base_risk_score,
            "prompt": d.get("prompt", "")[:200],
            "allowed": d.get("allowed", True),
        }

        if item_type == "benign":
            if base_risk_score > 0.8:
                false_positives.append(item_data)
            elif base_risk_score > 0.5:
                borderline.append(item_data)
        elif item_type == "redteam":
            if base_risk_score < 0.2:
                false_negatives.append(item_data)
            elif base_risk_score < 0.4:
                borderline.append(item_data)

    return {
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "borderline": borderline,
        "total_items": len(decisions),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analysiere Risk-Scorer-Kalibrierungsprobleme"
    )
    parser.add_argument(
        "--decisions",
        type=str,
        required=True,
        help="Pfad zur JSONL-Datei mit Entscheidungen",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional: Pfad für JSON-Export der Anomalien",
    )

    args = parser.parse_args()

    decisions_path = Path(args.decisions)
    if not decisions_path.exists():
        print(f"Error: Datei nicht gefunden: {decisions_path}", file=sys.stderr)
        return 1

    anomalies = analyze_risk_scorer_anomalies(decisions_path)

    # Ausgabe
    print("=" * 80)
    print("RISK-SCORER KALIBRIERUNGS-ANALYSE")
    print("=" * 80)
    print()
    print(f"Gesamt Items: {anomalies['total_items']}")
    print(
        f"False Positives (benign + risk_score > 0.8): {len(anomalies['false_positives'])}"
    )
    print(
        f"False Negatives (redteam + risk_score < 0.2): {len(anomalies['false_negatives'])}"
    )
    print(f"Borderline (risk_score 0.4-0.8): {len(anomalies['borderline'])}")
    print()

    if anomalies["false_positives"]:
        print("=" * 80)
        print("FALSE POSITIVES (benign Items mit hohem Risk Score)")
        print("=" * 80)
        for i, item in enumerate(anomalies["false_positives"], 1):
            print(f"\n{i}. {item['item_id']}")
            print(f"   Risk Score: {item['base_risk_score']:.4f}")
            print(f"   Prompt: {item['prompt'][:100]}...")
            print(f"   Blocked: {not item['allowed']}")

    if anomalies["false_negatives"]:
        print("\n" + "=" * 80)
        print("FALSE NEGATIVES (redteam Items mit niedrigem Risk Score)")
        print("=" * 80)
        for i, item in enumerate(anomalies["false_negatives"], 1):
            print(f"\n{i}. {item['item_id']}")
            print(f"   Risk Score: {item['base_risk_score']:.4f}")
            print(f"   Prompt: {item['prompt'][:100]}...")
            print(f"   Allowed: {item['allowed']}")

    # Export
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(anomalies, f, indent=2, ensure_ascii=False)
        print(f"\nAnomalien exportiert: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
