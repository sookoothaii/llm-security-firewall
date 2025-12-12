#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyze PolygloToxicityPrompts Failures
========================================

Analysiert die durchgelassenen Prompts des PolygloToxicityPrompts-Tests
nach Sprache und identifiziert Schwachstellen.

Usage:
    python scripts/analyze_polyglot_failures.py --results results/polyglotoxicity_20251205_223453.json
    python scripts/analyze_polyglot_failures.py --results results/polyglotoxicity_*.json --top 5
"""

import json
import argparse
from pathlib import Path
from collections import Counter
from typing import Dict, List, Any
import re

try:
    from langdetect import detect, LangDetectException

    HAS_LANGDETECT = True
except ImportError:
    HAS_LANGDETECT = False


def detect_language(text: str) -> str:
    """
    Detect language of text.

    Returns:
        Language code (ISO 639-1) or "unknown"
    """
    if not HAS_LANGDETECT:
        # Fallback: Simple heuristic based on Unicode ranges
        if re.search(r"[\u4e00-\u9fff]", text):  # Chinese
            return "zh"
        elif re.search(r"[\u3040-\u309f\u30a0-\u30ff]", text):  # Japanese
            return "ja"
        elif re.search(r"[\u0400-\u04ff]", text):  # Russian
            return "ru"
        elif re.search(r"[\u0600-\u06ff]", text):  # Arabic
            return "ar"
        elif re.search(r"[\u0900-\u097f]", text):  # Hindi
            return "hi"
        elif re.search(r"[\uac00-\ud7af]", text):  # Korean
            return "ko"
        elif re.search(r"[\u0590-\u05ff]", text):  # Hebrew
            return "he"
        elif re.search(r"[\u0370-\u03ff]", text):  # Greek
            return "el"
        elif re.search(r"[\u0e00-\u0e7f]", text):  # Thai
            return "th"
        else:
            return "en"  # Default to English

    try:
        return detect(text)
    except LangDetectException:
        return "unknown"


def analyze_failures(results_json_path: str, top_n: int = 10):
    """
    Analysiert die fehlgeschlagenen Prompts des PolygloToxicityPrompts-Tests.

    Args:
        results_json_path: Pfad zur JSON-Datei mit den Testergebnissen
        top_n: Anzahl der Top-Sprachen zu zeigen
    """
    try:
        with open(results_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Datei nicht gefunden: {results_json_path}")
        return
    except json.JSONDecodeError as e:
        print(f"[ERROR] Ungueltiges JSON: {e}")
        return

    results = data.get("results", [])
    summary = data.get("summary", {})

    if not results:
        print("[ERROR] Keine Ergebnisse in der JSON-Datei gefunden")
        return

    # Filter: Durchgelassene Prompts (blocked=False)
    failed_results = [r for r in results if not r.get("blocked", False)]
    total_results = len(results)
    total_failed = len(failed_results)

    print("=" * 80)
    print("ANALYSE: PolygloToxicityPrompts - Fehlgeschlagene Prompts")
    print("=" * 80)
    print(
        f"\nGesamt-ASR: {summary.get('attack_success_rate', 0.0):.1%} ({total_failed}/{total_results})"
    )
    print(
        f"Blockiert: {summary.get('blocked_tests', 0)} ({100 * (1 - summary.get('attack_success_rate', 0.0)):.1f}%)"
    )
    print(
        f"Durchgelassen: {total_failed} ({100 * summary.get('attack_success_rate', 0.0):.1f}%)"
    )

    # Spracherkennung für durchgelassene Prompts
    print("\n[INFO] Analysiere Sprachen der durchgelassenen Prompts...")
    language_distribution = Counter()
    language_examples: Dict[str, List[Dict[str, Any]]] = {}

    for result in failed_results:
        prompt = result.get("prompt", "")
        category = result.get("category", "unknown")

        # Versuche Sprache zu erkennen
        lang = detect_language(prompt)
        language_distribution[lang] += 1

        # Sammle Beispiele (max 3 pro Sprache)
        if lang not in language_examples:
            language_examples[lang] = []
        if len(language_examples[lang]) < 3:
            language_examples[lang].append(
                {
                    "prompt": prompt[:200] + "..." if len(prompt) > 200 else prompt,
                    "risk_score": result.get("risk_score", 0.0),
                    "category": category,
                }
            )

    # Berechne Failure-Rate pro Sprache
    print(f"\n[OK] {len(language_distribution)} verschiedene Sprachen erkannt")

    print(f"\n{'=' * 80}")
    print(f"Top {top_n} Sprachen mit den meisten Durchlass-Fehlern:")
    print(f"{'=' * 80}")

    for lang, count in language_distribution.most_common(top_n):
        # Berechne Failure-Rate für diese Sprache
        lang_total = sum(
            1 for r in results if detect_language(r.get("prompt", "")) == lang
        )
        lang_fail_rate = (count / lang_total * 100) if lang_total > 0 else 0.0

        print(f"\n{lang.upper()}:")
        print(
            f"  Durchgelassen: {count} von {lang_total} ({lang_fail_rate:.1f}% Failure-Rate)"
        )
        print("  Beispiele:")
        for i, example in enumerate(language_examples.get(lang, [])[:2], 1):
            print(
                f"    [{i}] Risk: {example['risk_score']:.2f}, Category: {example['category']}"
            )
            # Safe encoding: replace problematic characters
            safe_prompt = (
                example["prompt"][:150].encode("ascii", "replace").decode("ascii")
            )
            print(f"        Prompt: {safe_prompt}...")

    # Empfehlungen
    print(f"\n{'=' * 80}")
    print("EMPFOHLUNGEN FÜR DIE OPTIMIERUNG")
    print(f"{'=' * 80}")

    top_lang = (
        language_distribution.most_common(1)[0][0] if language_distribution else None
    )
    if top_lang and top_lang != "en":
        top_count = language_distribution.most_common(1)[0][1]
        print(
            f"\n1. PRIORITAET: {top_lang.upper()}-spezifische Toxicity-Filter erweitern"
        )
        print(
            f"   -> {top_count} Fehler in dieser Sprache ({top_count / total_failed * 100:.1f}% aller Fehler)"
        )
        print(
            f"   -> Aktuell unterstuetzte Sprachen: 17+ (inkl. {top_lang if top_lang in ['es', 'fr', 'de', 'it', 'pt', 'tr', 'pl', 'nl', 'el', 'he', 'th', 'vi', 'id', 'ms', 'mt', 'eu'] else 'teilweise'})"
        )
    else:
        print("\n1. PRIORITAET: Multilinguale Toxicity-Detection verbessern")
        print("   -> Fehler sind breit ueber mehrere Sprachen verteilt")
        print(
            "   -> Toxicity-Detector wurde bereits implementiert, sollte bei naechstem Test aktiv sein"
        )

    print("\n2. TECHNISCHE OPTIONEN:")
    print("   a) Toxicity-Keywords fuer Top-Sprachen erweitern (bereits implementiert)")
    print(
        "   b) Multilinguale Embeddings/Modelle evaluieren (z.B. XLM-Roberta fuer Toxicity)"
    )
    print("   c) Externe multilinguale API als Fallback (z.B. Google Perspective API)")

    print("\n3. WEITERER SCHRITT:")
    print("   Fuehren Sie einen gezielten Test mit den Top-3 Problemsprachen durch,")
    print("   um die genauen Failure-Muster zu verstehen.")
    print("   -> Neuer Test: python scripts/run_polyglotoxicity_eval.py --limit 1000")

    # Speichere detaillierte Analyse
    analysis_output = {
        "total_tests": total_results,
        "total_failed": total_failed,
        "asr": summary.get("attack_success_rate", 0.0),
        "language_distribution": dict(language_distribution),
        "top_languages": [
            {"lang": lang, "count": count, "percentage": count / total_failed * 100}
            for lang, count in language_distribution.most_common(top_n)
        ],
        "examples": language_examples,
    }

    output_file = (
        Path(results_json_path).parent
        / f"polyglot_analysis_{Path(results_json_path).stem.split('_')[-1]}.json"
    )
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(analysis_output, f, indent=2, ensure_ascii=False)

    print(f"\n[OK] Detaillierte Analyse gespeichert: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze PolygloToxicityPrompts test failures by language"
    )
    parser.add_argument(
        "--results",
        type=str,
        required=True,
        help="Path to JSON results file from polyglotoxicity evaluation",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top languages to show (default: 10)",
    )

    args = parser.parse_args()

    analyze_failures(args.results, top_n=args.top)


if __name__ == "__main__":
    main()
