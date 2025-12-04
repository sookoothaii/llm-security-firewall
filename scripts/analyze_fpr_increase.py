#!/usr/bin/env python3
"""
Analysiere FPR-Erhöhung: Welche benign-Items werden zusätzlich blockiert?

Vergleicht Heuristik vs. Evidence-Fusion und identifiziert die zusätzlich
blockierten benign-Items mit ihren p_correct-Werten und Evidence-Massen.
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Any


def load_decisions(filepath: Path) -> List[Dict]:
    """Lade Entscheidungen aus JSONL-Datei."""
    decisions = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                decisions.append(json.loads(line))
    return decisions


def get_blocked_benign(decisions: List[Dict]) -> Dict[str, Dict]:
    """Extrahiere blockierte benign-Items mit Metadaten."""
    blocked = {}
    for d in decisions:
        if d.get("item_type") == "benign" and not d.get("allowed", True):
            item_id = d.get("item_id", "unknown")
            metadata = d.get("metadata", {})
            answer_policy = metadata.get("answer_policy", {})

            blocked[item_id] = {
                "item_id": item_id,
                "prompt": d.get("prompt", "")[:100],  # Erste 100 Zeichen
                "p_correct": answer_policy.get("p_correct"),
                "risk_score": d.get("risk_score", 0),
                "base_risk_score": answer_policy.get("base_risk_score"),
                "belief_quarantine": answer_policy.get("belief_quarantine"),
                "evidence_masses": answer_policy.get("evidence_masses", {}),
                "combined_mass": answer_policy.get("combined_mass", {}),
                "method": answer_policy.get("method", "unknown"),
            }
    return blocked


def compare_blocked_benign(heuristic_log: Path, evidence_log: Path) -> Dict[str, Any]:
    """Vergleiche blockierte benign-Items zwischen Heuristik und Evidence-Fusion."""

    heuristic_decisions = load_decisions(heuristic_log)
    evidence_decisions = load_decisions(evidence_log)

    heuristic_blocked = get_blocked_benign(heuristic_decisions)
    evidence_blocked = get_blocked_benign(evidence_decisions)

    # Finde zusätzlich blockierte Items
    additional_blocked = {}
    for item_id, data in evidence_blocked.items():
        if item_id not in heuristic_blocked:
            additional_blocked[item_id] = data

    # Finde Items, die in Heuristik blockiert, aber in Evidence durchgelassen wurden
    unblocked = {}
    for item_id, data in heuristic_blocked.items():
        if item_id not in evidence_blocked:
            # Finde das Item in evidence_decisions
            for d in evidence_decisions:
                if d.get("item_id") == item_id:
                    metadata = d.get("metadata", {})
                    answer_policy = metadata.get("answer_policy", {})
                    unblocked[item_id] = {
                        "item_id": item_id,
                        "p_correct": answer_policy.get("p_correct"),
                        "method": answer_policy.get("method", "unknown"),
                    }
                    break

    return {
        "heuristic_blocked_count": len(heuristic_blocked),
        "evidence_blocked_count": len(evidence_blocked),
        "additional_blocked_count": len(additional_blocked),
        "additional_blocked": additional_blocked,
        "unblocked_count": len(unblocked),
        "unblocked": unblocked,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analysiere FPR-Erhöhung zwischen Heuristik und Evidence-Fusion"
    )
    parser.add_argument(
        "--heuristic-log", type=str, required=True, help="Pfad zur Heuristik-Log-Datei"
    )
    parser.add_argument(
        "--evidence-log",
        type=str,
        required=True,
        help="Pfad zur Evidence-Fusion-Log-Datei",
    )
    parser.add_argument(
        "--output", type=str, default=None, help="Optional: Pfad für Markdown-Report"
    )

    args = parser.parse_args()

    heuristic_log = Path(args.heuristic_log)
    evidence_log = Path(args.evidence_log)

    if not heuristic_log.exists():
        print(f"Error: Heuristik-Log nicht gefunden: {heuristic_log}", file=sys.stderr)
        return 1

    if not evidence_log.exists():
        print(f"Error: Evidence-Log nicht gefunden: {evidence_log}", file=sys.stderr)
        return 1

    # Vergleiche
    comparison = compare_blocked_benign(heuristic_log, evidence_log)

    # Generiere Report
    lines = []
    lines.append("# FPR-Erhöhung Analyse")
    lines.append("")
    lines.append(f"**Heuristik-Log:** {heuristic_log.name}")
    lines.append(f"**Evidence-Log:** {evidence_log.name}")
    lines.append("")
    lines.append("## Zusammenfassung")
    lines.append("")
    lines.append(
        f"- **Heuristik blockiert:** {comparison['heuristic_blocked_count']} benign Items"
    )
    lines.append(
        f"- **Evidence blockiert:** {comparison['evidence_blocked_count']} benign Items"
    )
    lines.append(
        f"- **Zusätzlich blockiert:** {comparison['additional_blocked_count']} Items"
    )
    lines.append(f"- **Weniger blockiert:** {comparison['unblocked_count']} Items")
    lines.append("")

    if comparison["additional_blocked_count"] > 0:
        lines.append("## Zusätzlich blockierte benign-Items")
        lines.append("")
        lines.append(
            "Diese Items wurden in Evidence-Fusion blockiert, aber in Heuristik durchgelassen:"
        )
        lines.append("")

        # Sortiere nach p_correct (niedrigste zuerst)
        sorted_items = sorted(
            comparison["additional_blocked"].items(),
            key=lambda x: x[1].get("p_correct", 1.0),
        )

        lines.append(
            "| Item ID | Prompt (Auszug) | p_correct | risk_score | belief_quarantine |"
        )
        lines.append(
            "|---------|-----------------|-----------|------------|-------------------|"
        )

        for item_id, data in sorted_items[:10]:  # Erste 10
            prompt = data.get("prompt", "")[:50].replace("|", " ")
            p_correct = data.get("p_correct", 0)
            risk_score = data.get("risk_score", 0)
            belief_q = data.get("belief_quarantine", 0)
            lines.append(
                f"| {item_id} | {prompt}... | {p_correct:.4f} | {risk_score:.3f} | {belief_q:.4f} |"
            )

        if len(sorted_items) > 10:
            lines.append(f"\n*... und {len(sorted_items) - 10} weitere Items*")

        lines.append("")
        lines.append("### Statistik der zusätzlich blockierten Items")
        lines.append("")

        p_correct_values = [
            d.get("p_correct", 0)
            for d in comparison["additional_blocked"].values()
            if d.get("p_correct") is not None
        ]
        risk_scores = [
            d.get("risk_score", 0)
            for d in comparison["additional_blocked"].values()
            if d.get("risk_score") is not None
        ]

        if p_correct_values:
            lines.append(
                f"- **p_correct Mittelwert:** {sum(p_correct_values) / len(p_correct_values):.4f}"
            )
            lines.append(f"- **p_correct Minimum:** {min(p_correct_values):.4f}")
            lines.append(f"- **p_correct Maximum:** {max(p_correct_values):.4f}")

        if risk_scores:
            lines.append(
                f"- **risk_score Mittelwert:** {sum(risk_scores) / len(risk_scores):.4f}"
            )
            lines.append(f"- **risk_score Minimum:** {min(risk_scores):.4f}")
            lines.append(f"- **risk_score Maximum:** {max(risk_scores):.4f}")

        lines.append("")

    if comparison["unblocked_count"] > 0:
        lines.append("## Weniger blockierte benign-Items")
        lines.append("")
        lines.append(
            f"Diese {comparison['unblocked_count']} Items wurden in Heuristik blockiert, aber in Evidence-Fusion durchgelassen."
        )
        lines.append("")

    # Ausgabe
    report_text = "\n".join(lines)

    try:
        print(report_text)
    except UnicodeEncodeError:
        pass

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\nReport gespeichert: {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
