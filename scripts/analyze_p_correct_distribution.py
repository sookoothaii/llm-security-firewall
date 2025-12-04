#!/usr/bin/env python3
"""
Analyse-Skript für p_correct-Verteilung aus Experiment-Ergebnissen.

Analysiert die p_correct-Verteilung in JSONL-Ergebnissen und erstellt
eine Zusammenfassung für Kalibrierungszwecke.

Author: Joerg Bollwahn
Date: 2025-12-03
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any


def extract_p_correct_values(input_path: Path) -> Dict[str, List[float]]:
    """
    Extrahiert p_correct-Werte aus JSONL-Ergebnissen.

    Args:
        input_path: Pfad zur JSONL-Datei mit Experiment-Ergebnissen

    Returns:
        Dictionary mit 'redteam' und 'benign' Listen von p_correct-Werten
    """
    redteam_values = []
    benign_values = []
    all_values = []

    with open(input_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
                item_type = item.get("item_type", "unknown")

                # p_correct aus Metadata extrahieren
                metadata = item.get("metadata", {})
                answer_policy = metadata.get("answer_policy", {})
                p_correct = answer_policy.get("p_correct")

                if p_correct is not None:
                    all_values.append(p_correct)

                    if item_type == "redteam":
                        redteam_values.append(p_correct)
                    elif item_type == "benign":
                        benign_values.append(p_correct)

            except json.JSONDecodeError as e:
                print(f"Warning: Invalid JSON on line {line_num}: {e}", file=sys.stderr)
                continue
            except Exception as e:
                print(
                    f"Warning: Error processing line {line_num}: {e}", file=sys.stderr
                )
                continue

    return {
        "redteam": redteam_values,
        "benign": benign_values,
        "all": all_values,
    }


def compute_statistics(values: List[float], name: str) -> Dict[str, float]:
    """
    Berechnet Statistik für eine Liste von Werten.

    Args:
        values: Liste von p_correct-Werten
        name: Name der Gruppe (für Fehlermeldungen)

    Returns:
        Dictionary mit min, max, mean, median, std
    """
    if not values:
        return {
            "count": 0,
            "min": None,
            "max": None,
            "mean": None,
            "median": None,
            "std": None,
        }

    sorted_values = sorted(values)
    n = len(values)

    mean = sum(values) / n
    median = (
        sorted_values[n // 2]
        if n % 2 == 1
        else (sorted_values[n // 2 - 1] + sorted_values[n // 2]) / 2
    )

    # Standardabweichung
    variance = sum((x - mean) ** 2 for x in values) / n
    std = variance**0.5

    return {
        "count": n,
        "min": min(values),
        "max": max(values),
        "mean": mean,
        "median": median,
        "std": std,
    }


def analyze_threshold_sensitivity(
    values: List[float], thresholds: List[float]
) -> Dict[float, int]:
    """
    Analysiert, wie viele Werte unter verschiedenen Thresholds liegen.

    Args:
        values: Liste von p_correct-Werten
        thresholds: Liste von Threshold-Werten

    Returns:
        Dictionary: threshold -> Anzahl Werte < threshold
    """
    result = {}
    for threshold in thresholds:
        count = sum(1 for v in values if v < threshold)
        result[threshold] = count
    return result


def print_analysis_report(
    redteam_stats: Dict[str, Any],
    benign_stats: Dict[str, Any],
    threshold_sensitivity_redteam: Dict[float, int],
    threshold_sensitivity_benign: Dict[float, int],
    output_path: Path = None,
):
    """
    Druckt Analyse-Report.

    Args:
        redteam_stats: Statistik für redteam-Werte
        benign_stats: Statistik für benign-Werte
        threshold_sensitivity_redteam: Threshold-Sensitivität für redteam
        threshold_sensitivity_benign: Threshold-Sensitivität für benign
        output_path: Optional: Pfad für Markdown-Output
    """

    lines = []
    lines.append("# p_correct Verteilungsanalyse")
    lines.append("")
    lines.append("## Redteam Statistik")
    lines.append("")
    lines.append(f"- **Anzahl:** {redteam_stats['count']}")
    lines.append(
        f"- **Minimum:** {redteam_stats['min']:.4f}"
        if redteam_stats["min"] is not None
        else "- **Minimum:** N/A"
    )
    lines.append(
        f"- **Maximum:** {redteam_stats['max']:.4f}"
        if redteam_stats["max"] is not None
        else "- **Maximum:** N/A"
    )
    lines.append(
        f"- **Mittelwert:** {redteam_stats['mean']:.4f}"
        if redteam_stats["mean"] is not None
        else "- **Mittelwert:** N/A"
    )
    lines.append(
        f"- **Median:** {redteam_stats['median']:.4f}"
        if redteam_stats["median"] is not None
        else "- **Median:** N/A"
    )
    lines.append(
        f"- **Std. Abw.:** {redteam_stats['std']:.4f}"
        if redteam_stats["std"] is not None
        else "- **Std. Abw.:** N/A"
    )
    lines.append("")

    lines.append("## Benign Statistik")
    lines.append("")
    lines.append(f"- **Anzahl:** {benign_stats['count']}")
    lines.append(
        f"- **Minimum:** {benign_stats['min']:.4f}"
        if benign_stats["min"] is not None
        else "- **Minimum:** N/A"
    )
    lines.append(
        f"- **Maximum:** {benign_stats['max']:.4f}"
        if benign_stats["max"] is not None
        else "- **Maximum:** N/A"
    )
    lines.append(
        f"- **Mittelwert:** {benign_stats['mean']:.4f}"
        if benign_stats["mean"] is not None
        else "- **Mittelwert:** N/A"
    )
    lines.append(
        f"- **Median:** {benign_stats['median']:.4f}"
        if benign_stats["median"] is not None
        else "- **Median:** N/A"
    )
    lines.append(
        f"- **Std. Abw.:** {benign_stats['std']:.4f}"
        if benign_stats["std"] is not None
        else "- **Std. Abw.:** N/A"
    )
    lines.append("")

    lines.append("## Threshold-Sensitivität")
    lines.append("")
    lines.append("### Redteam (Werte < Threshold)")
    lines.append("")
    lines.append("| Threshold | Anzahl | Prozent |")
    lines.append("|-----------|--------|---------|")
    for threshold in sorted(threshold_sensitivity_redteam.keys()):
        count = threshold_sensitivity_redteam[threshold]
        total = redteam_stats["count"]
        percent = (count / total * 100) if total > 0 else 0.0
        lines.append(f"| {threshold:.2f} | {count} | {percent:.1f}% |")
    lines.append("")

    lines.append("### Benign (Werte < Threshold)")
    lines.append("")
    lines.append("| Threshold | Anzahl | Prozent |")
    lines.append("|-----------|--------|---------|")
    for threshold in sorted(threshold_sensitivity_benign.keys()):
        count = threshold_sensitivity_benign[threshold]
        total = benign_stats["count"]
        percent = (count / total * 100) if total > 0 else 0.0
        lines.append(f"| {threshold:.2f} | {count} | {percent:.1f}% |")
    lines.append("")

    # Kritische Analyse
    lines.append("## Kritische Analyse")
    lines.append("")

    redteam_min = redteam_stats["min"]
    if redteam_min is not None:
        if redteam_min > 0.50:
            lines.append(
                f"⚠️ **WARNUNG:** Redteam Minimum ({redteam_min:.4f}) liegt über 0.50. Threshold-Sensitivität ist eingeschränkt."
            )
        elif redteam_min > 0.30:
            lines.append(
                f"⚠️ **HINWEIS:** Redteam Minimum ({redteam_min:.4f}) liegt über 0.30. Threshold-Sensitivität im mittleren Bereich."
            )
        else:
            lines.append(
                f"✅ **OK:** Redteam Minimum ({redteam_min:.4f}) liegt unter 0.30. Gute Threshold-Sensitivität möglich."
            )
    lines.append("")

    # Ausgabe
    report_text = "\n".join(lines)

    # Try to print, but handle Unicode errors gracefully
    try:
        print(report_text)
    except UnicodeEncodeError:
        # If printing fails due to encoding, just write to file
        pass

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\nReport gespeichert: {output_path}")
    else:
        # If no output path, try to write to stdout with UTF-8
        try:
            import sys

            sys.stdout.reconfigure(encoding="utf-8")
            print(report_text)
        except (AttributeError, UnicodeEncodeError):
            # Fallback: write to temporary file
            temp_path = Path("temp_analysis_report.md")
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(report_text)
            print(f"\nReport gespeichert (Unicode-Fallback): {temp_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Analysiere p_correct-Verteilung aus Experiment-Ergebnissen"
    )
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Pfad zur JSONL-Datei mit Experiment-Ergebnissen",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional: Pfad für Markdown-Report (default: stdout)",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        return 1

    output_path = Path(args.output) if args.output else None

    # Extrahiere p_correct-Werte
    print(f"Lese Experiment-Ergebnisse aus: {input_path}")
    values = extract_p_correct_values(input_path)

    if not values["all"]:
        print(
            "Error: Keine p_correct-Werte gefunden in den Ergebnissen.", file=sys.stderr
        )
        return 1

    print(f"Gefunden: {len(values['redteam'])} redteam, {len(values['benign'])} benign")
    print()

    # Berechne Statistik
    redteam_stats = compute_statistics(values["redteam"], "redteam")
    benign_stats = compute_statistics(values["benign"], "benign")

    # Threshold-Sensitivität
    thresholds = [0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.85, 0.90, 0.93, 0.95, 0.98]
    threshold_sensitivity_redteam = analyze_threshold_sensitivity(
        values["redteam"], thresholds
    )
    threshold_sensitivity_benign = analyze_threshold_sensitivity(
        values["benign"], thresholds
    )

    # Report generieren
    print_analysis_report(
        redteam_stats,
        benign_stats,
        threshold_sensitivity_redteam,
        threshold_sensitivity_benign,
        output_path,
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
